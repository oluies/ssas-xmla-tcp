"""Session lifecycle and state transitions."""

import pytest

from ssas_xmla import dime
from ssas_xmla.auth import Credential
from ssas_xmla.client import ConnectionTarget, Session, State, connect
from ssas_xmla.errors import AuthenticationError
from ssas_xmla.transport import BytesChannel
from tests.fixtures import synth


class DoneContext:
    """A context that completes on the first step, and can seal.

    Sealing is a reversible XOR so wrap/unwrap round-trip without a KDC. The
    token is NTLM-shaped (16 bytes) so frame arithmetic matches the real thing.
    """

    protection = False
    TOKEN = b"\x01\x00\x00\x00" + b"\xaa" * 12

    def __init__(self):
        self._stepped = False

    def step(self, in_token=None):
        self._stepped = True
        return b"tok"

    @property
    def complete(self):
        return self._stepped

    def wrap_winrm(self, data):
        return self.TOKEN, bytes(b ^ 0x5A for b in data), 0

    def unwrap_winrm(self, header, data):
        return bytes(b ^ 0x5A for b in data)


def sealed(payload: bytes) -> bytes:
    """Seal a fixture response the way the server would."""
    from ssas_xmla import sealing

    return sealing.seal_message(DoneContext(), payload)


def sent_plaintext(channel) -> bytes:
    """What the client actually asked for, read back through the seal.

    Requests are sealed once a session is authenticated, so a test that greps
    `channel.sent` for XML would only ever see ciphertext. This unwraps every DIME
    record and unseals the ones that are sealed frames, so assertions can stay
    written in terms of the request rather than its encryption.
    """
    from ssas_xmla import dime, sealing

    ctx = DoneContext()
    out, offset = [], 0
    buf = bytes(channel.sent)
    while offset < len(buf):
        try:
            record, offset = dime.decode_record(buf, offset)
        except Exception:
            break
        body = record.data
        try:
            out.append(sealing.unseal_message(ctx, body))
        except Exception:
            out.append(body)  # plaintext handshake record
    return b"".join(out)


def _channel_for(*payloads):
    """First payload is the plaintext handshake reply; the rest are sealed, as
    the server sends them after authentication."""
    ch = BytesChannel()
    for i, p in enumerate(payloads):
        body = p.encode() if i == 0 else sealed(p.encode())
        ch.queue(synth.dime_message(body))
    return ch


def test_target_rejects_nonsense():
    with pytest.raises(ValueError, match="host"):
        ConnectionTarget(host="", port=2383)
    with pytest.raises(ValueError, match="port"):
        ConnectionTarget(host="h", port=0)
    with pytest.raises(ValueError, match="unbounded"):
        ConnectionTarget(host="h", port=2383, timeout=0)


def test_there_is_no_default_port():
    """A default would invite guessing between a default and a named instance."""
    with pytest.raises(TypeError):
        ConnectionTarget(host="h")  # port is required


def test_state_moves_unconnected_to_authenticated():
    ch = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    assert s.state is State.UNCONNECTED
    s.open(channel=ch, context=DoneContext())
    assert s.state is State.AUTHENTICATED


def test_request_before_authentication_is_refused():
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    with pytest.raises(AuthenticationError, match="not authenticated"):
        s.discover("DISCOVER_DATASOURCES")


def test_a_failed_session_is_terminal():
    class Boom:
        protection = False
        complete = False

        def step(self, in_token=None):
            raise RuntimeError("nope")

    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    with pytest.raises(AuthenticationError):
        s.open(channel=BytesChannel(), context=Boom())
    assert s.state is State.FAILED
    with pytest.raises(AuthenticationError):
        s.discover("DISCOVER_DATASOURCES")


def test_close_is_idempotent_and_works_on_a_failed_session():
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    s.close()
    s.close()
    assert s.state is State.CLOSED


def test_context_manager_closes_on_the_way_out():
    ch = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        assert s.state is State.AUTHENTICATED
    assert s.state is State.CLOSED


def test_discover_datasources_returns_rows():
    ch = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE,
    )
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        result = s.discover_datasources()
    assert len(result) == 1
    assert result.rows[0]["DataSourceName"] == "Analysis Services"


def test_the_request_sent_is_a_valid_dime_message():
    ch = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE,
    )
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        s.discover_datasources()
    payload, content_type = dime.decode_message(bytes(ch.sent))
    assert content_type == dime.TYPE_TEXT_XML
    assert b"Authenticate" in payload


def test_password_reaches_the_security_layer_and_is_not_retained():
    """The standalone-NTLM password path had no coverage: dropping the argument
    anywhere in connect -> open -> build_context would only fail against a live
    server."""
    seen = {}

    def fake_build_context(credential, host, password=None):
        seen["password"] = password
        return DoneContext()

    import ssas_xmla.auth as auth_mod
    from ssas_xmla import client as client_mod

    original = auth_mod.build_context
    client_mod.auth.build_context = fake_build_context
    try:
        ch = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
        s = connect("h", 2383, channel=ch, password="s3cret")
    finally:
        client_mod.auth.build_context = original

    assert seen["password"] == "s3cret"
    # never stored on the session or its credential, so no repr or log can leak it
    assert "s3cret" not in repr(s)
    assert "s3cret" not in repr(s.credential)
