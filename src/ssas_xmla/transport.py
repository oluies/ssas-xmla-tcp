"""Socket lifecycle and message framing over it.

The byte seam is the point of this module. `Channel` is a protocol with two
methods; the real one wraps a socket, and tests supply recorded bytes. Every layer
above therefore runs with sockets disabled (constitution III), with no stub server
to keep in sync.
"""
from __future__ import annotations

import socket
from typing import Protocol

from . import dime
from .errors import ConnectionError as SsasConnectionError
from .errors import ProtocolError


class Channel(Protocol):
    """A bidirectional byte stream. The seam that makes everything above testable."""

    def send(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class SocketChannel:
    """A real TCP socket, with a deadline on every wait (FR-009)."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self._host = host
        try:
            self._sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            # Deliberately does not include the host: constitution I.
            raise SsasConnectionError(f"could not connect on port {port}") from exc
        self._sock.settimeout(timeout)

    def send(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise SsasConnectionError("send failed") from exc

    def recv(self, size: int) -> bytes:
        try:
            return self._sock.recv(size)
        except TimeoutError as exc:
            raise SsasConnectionError("timed out waiting for a response") from exc
        except OSError as exc:
            raise SsasConnectionError("receive failed") from exc

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class BytesChannel:
    """A channel backed by a recorded response. For tests and fixture replay."""

    def __init__(self, response: bytes = b"") -> None:
        self.sent = bytearray()
        self._response = response
        self._pos = 0
        self.closed = False

    def send(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        chunk = self._response[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True

    def queue(self, response: bytes) -> None:
        """Append another response, for a multi-round-trip exchange."""
        self._response += response


class MessageStream:
    """Sends and receives whole DIME messages over a Channel.

    Holds a read buffer between calls. A peer may pack several messages into one
    TCP segment, so consuming the whole buffer per message would silently drop
    whatever followed — which is exactly what an early version of this class did.
    """

    def __init__(self, channel: Channel) -> None:
        self._channel = channel
        self._buf = bytearray()

    def send_message(self, payload: bytes) -> None:
        self._channel.send(dime.encode_message(payload))

    def receive_message(self) -> bytes:
        """Read one complete DIME message, honouring the record lengths.

        Reads are driven by the header's declared lengths rather than by waiting for
        the peer to go quiet, so a slow or fragmented response is assembled rather
        than truncated.
        """
        while True:
            parsed = self._try_parse()
            if parsed is not None:
                payload, content_type, options, consumed = parsed
                del self._buf[:consumed]
                dime.check_negotiated(options, content_type)
                return payload
            chunk = self._channel.recv(65536)
            if not chunk:
                raise SsasConnectionError(
                    "connection closed before a complete message arrived"
                )
            self._buf.extend(chunk)

    def _try_parse(self):
        """Return (payload, content_type, options, consumed) or None if incomplete."""
        if len(self._buf) < dime.HEADER_LEN:
            return None
        try:
            payload, content_type, options, next_offset = dime.decode_message_at(
                bytes(self._buf), 0
            )
        except ProtocolError as exc:
            # A truncated record just means "not yet"; a bad version is fatal.
            if "truncated" in str(exc):
                return None
            raise
        return payload, content_type, options, next_offset

    def close(self) -> None:
        self._channel.close()
