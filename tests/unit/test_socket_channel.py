"""SocketChannel: the one layer that touches a real socket.

Tested by injecting a fake socket through `socket.create_connection`, so no real
socket is ever created and the suite stays hermetic (constitution III). What is
being tested is SocketChannel's own behaviour — timeout application, the mapping
of OSError onto the FR-007 categories, and that failures never name the host —
not the operating system's networking.
"""

import socket

import pytest

from ssas_xmla.errors import ConnectionError as SsasConnectionError
from ssas_xmla.transport import SocketChannel

HOST = "ssas.example.internal"
PORT = 2383


class FakeSocket:
    def __init__(self, recv_data=b"", raise_on=None, exc=None):
        self.sent = bytearray()
        self.timeout_set = None
        self.closed = False
        self._recv_data = recv_data
        self._raise_on = raise_on
        self._exc = exc or OSError("boom")

    def settimeout(self, value):
        self.timeout_set = value

    def sendall(self, data):
        if self._raise_on == "send":
            raise self._exc
        self.sent.extend(data)

    def recv(self, size):
        if self._raise_on == "recv":
            raise self._exc
        chunk, self._recv_data = self._recv_data[:size], self._recv_data[size:]
        return chunk

    def close(self):
        if self._raise_on == "close":
            raise self._exc
        self.closed = True


@pytest.fixture
def fake_connect(monkeypatch):
    def _install(sock=None, error=None):
        def _create_connection(address, timeout=None):
            if error is not None:
                raise error
            _create_connection.address = address
            _create_connection.timeout = timeout
            return sock

        monkeypatch.setattr(socket, "create_connection", _create_connection)
        return _create_connection

    return _install


def test_connects_to_the_given_address_and_applies_the_timeout(fake_connect):
    sock = FakeSocket()
    created = fake_connect(sock=sock)
    SocketChannel(HOST, PORT, 12.5)
    assert created.address == (HOST, PORT)
    assert created.timeout == 12.5
    # FR-009: applied to the socket too, not only to connect
    assert sock.timeout_set == 12.5


def test_connect_failure_maps_to_connection_error_without_naming_the_host(fake_connect):
    fake_connect(error=OSError("Connection refused"))
    with pytest.raises(SsasConnectionError) as excinfo:
        SocketChannel(HOST, PORT, 5.0)
    message = str(excinfo.value)
    assert str(PORT) in message
    # constitution I: the host must not reach an error message
    assert HOST not in message


def test_send_writes_through(fake_connect):
    sock = FakeSocket()
    fake_connect(sock=sock)
    SocketChannel(HOST, PORT, 5.0).send(b"payload")
    assert bytes(sock.sent) == b"payload"


def test_send_failure_maps_to_connection_error(fake_connect):
    fake_connect(sock=FakeSocket(raise_on="send"))
    with pytest.raises(SsasConnectionError, match="send failed"):
        SocketChannel(HOST, PORT, 5.0).send(b"x")


def test_recv_returns_bytes(fake_connect):
    fake_connect(sock=FakeSocket(recv_data=b"abcdef"))
    channel = SocketChannel(HOST, PORT, 5.0)
    assert channel.recv(3) == b"abc"
    assert channel.recv(3) == b"def"
    assert channel.recv(3) == b""


def test_recv_timeout_is_reported_as_a_timeout(fake_connect):
    """A timeout is the FR-009 failure and must be distinguishable in the message
    from a connection that dropped."""
    fake_connect(sock=FakeSocket(raise_on="recv", exc=TimeoutError()))
    with pytest.raises(SsasConnectionError, match="timed out"):
        SocketChannel(HOST, PORT, 5.0).recv(10)


def test_recv_other_oserror_maps_to_connection_error(fake_connect):
    fake_connect(sock=FakeSocket(raise_on="recv", exc=OSError("reset by peer")))
    with pytest.raises(SsasConnectionError, match="receive failed"):
        SocketChannel(HOST, PORT, 5.0).recv(10)


def test_close_closes_the_socket(fake_connect):
    sock = FakeSocket()
    fake_connect(sock=sock)
    SocketChannel(HOST, PORT, 5.0).close()
    assert sock.closed


def test_close_never_raises(fake_connect):
    """Close runs on the error path, so it must not mask the original failure."""
    fake_connect(sock=FakeSocket(raise_on="close"))
    SocketChannel(HOST, PORT, 5.0).close()  # no exception


def test_the_injection_is_what_prevents_a_real_connection(fake_connect):
    """Guard on THIS module's mechanism, not on pytest-socket.

    The previous version duplicated test_offline_gate and asserted a third-party
    invariant, so it would have passed unchanged even if `fake_connect` stopped
    patching anything. This follows the injected socket through: the fake records
    the address it was asked for and the bytes written to it, which can only
    happen if SocketChannel is talking to the fake and not to a real socket.
    (Asserting the unpatched case here is impossible -- monkeypatch is still
    active inside the test; test_offline_gate covers that.)
    """
    sock = FakeSocket()
    created = fake_connect(sock=sock)
    channel = SocketChannel(HOST, PORT, 1.0)

    # the fake was reached, so the patch is genuinely in the path
    assert created.address == (HOST, PORT)
    assert created.timeout == 1.0
    # and the object under test is wired to it, not to a real socket
    channel.send(b"probe")
    assert bytes(sock.sent) == b"probe"
