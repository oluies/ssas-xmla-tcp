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


def test_password_reaches_the_security_layer_and_is_not_retained(monkeypatch):
    """The standalone-NTLM password path had no coverage: dropping the argument
    anywhere in connect -> open -> build_context would only fail against a live
    server."""
    seen = {}

    def fake_build_context(credential, host, password=None, port=None):
        seen["password"] = password
        seen["host"], seen["port"] = host, port
        return DoneContext()

    # monkeypatch, not manual save/restore: an interrupt between the assignment and
    # the finally would have leaked the patch into the rest of the session.
    import ssas_xmla.auth as auth_mod

    monkeypatch.setattr(auth_mod, "build_context", fake_build_context)
    ch = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
    s = connect("h", 2383, channel=ch, password="s3cret")

    assert seen["password"] == "s3cret"
    # the port reaches build_context, which is what lets it compose the SPN the
    # reference client uses (MSOLAPSvc.3/host:port -- see Credential.target)
    assert (seen["host"], seen["port"]) == ("h", 2383)
    # never stored on the session or its credential, so no repr or log can leak it
    assert "s3cret" not in repr(s)
    assert "s3cret" not in repr(s.credential)


# --- connection-scoped state and the NEGO sequencing ---------------------------
# The negotiation bits are silently fatal when wrong: the server closes the
# connection with no error and logs nothing. Nothing decoded the OPTIONS byte of
# the records a session actually emits, so neither the reset bug below nor a
# regression in the clear-then-set rule would have been caught.


def _record_options(sent: bytes) -> list[bytes]:
    """The OPTIONS field of every DIME record the client put on the wire."""
    out, offset = [], 0
    while offset < len(sent):
        record, offset = dime.decode_record(sent, offset)
        out.append(record.options)
    return out


def test_nego_is_clear_on_the_first_record_and_set_on_every_later_one():
    ch = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE,
    )
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        s.discover_datasources()
    options = _record_options(bytes(ch.sent))
    assert len(options) >= 2
    assert options[0] == dime.OPTIONS_CLEAR_TEXT
    assert all(o == dime.OPTIONS_NEGOTIATED for o in options[1:])


def test_reopening_a_session_starts_the_nego_sequence_over():
    """`Session` is a public dataclass with a public `open()`, so a reconnect on
    the same instance used to send its FIRST record with OPT_NEGO already set --
    and carry a SessionId belonging to the connection that just died."""
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    first = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE_WITH_SESSION,
    )
    s.open(channel=first, context=DoneContext())
    s.discover_datasources()
    assert s._session_id == "A1B2C3"  # captured from the first connection
    s.close()

    second = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
    s.open(channel=second, context=DoneContext())
    assert _record_options(bytes(second.sent))[0] == dime.OPTIONS_CLEAR_TEXT
    assert s._session_id is None  # not carried over from the dead connection


def test_a_context_that_cannot_seal_is_refused_at_open():
    """auth.SecurityContext needs only step/complete, so an injected context can
    pass the handshake and then die on the first request with a bare
    AttributeError -- outside the FR-007 taxonomy the probe's outcome table needs."""

    class HandshakeOnly:
        protection = False

        def __init__(self):
            self._stepped = False

        def step(self, in_token=None):
            self._stepped = True
            return b"tok"

        @property
        def complete(self):
            return self._stepped

    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    with pytest.raises(AuthenticationError, match="cannot seal"):
        s.open(channel=BytesChannel(), context=HandshakeOnly())
    assert s.state is State.FAILED


def test_a_response_that_does_not_decrypt_is_an_error_not_an_empty_rowset():
    """An empty rowset is a MEANINGFUL answer -- catalogs() documents that none
    visible is distinct from refused -- so garbage must not arrive looking like
    one. rowset.parse degrades a parse error to Rowset(), which was harmless while
    the payload was clear text and is not now that every response passes through a
    cipher: the likeliest failure of a new crypto layer produces exactly this."""
    from ssas_xmla.errors import ProtocolError

    class WrongKey(DoneContext):
        def unwrap_winrm(self, header, data):
            return b"\x93\x1f\xa2 not xml at all"

    ch = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE,
    )
    with connect("h", 2383, channel=ch, context=WrongKey()) as s:
        with pytest.raises(ProtocolError, match="not an XMLA envelope"):
            s.discover_datasources()


def test_a_large_chunked_sealed_rowset_arrives_whole_through_the_session():
    """Where the three splits actually compose in the shipped code.

    `test_all_three_split_layers_compose` drives sealing, DIME and the trickling
    channel directly; the place they meet in the library is
    `Session._roundtrip_rowset`, which additionally sends OPTIONS_NEGOTIATED,
    unseals, captures the SessionId, fault-checks and parses. Every other session
    test uses a single-record fixture, so that path was only ever exercised on
    responses small enough to avoid all three splits.
    """
    from ssas_xmla import sealing

    rows = "".join(
        f"<row><CATALOG_NAME>C{i:04d}</CATALOG_NAME><DESCRIPTION>{'d' * 120}</DESCRIPTION></row>"
        for i in range(400)
    )
    body = (
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
        '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis"><return>'
        '<root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">'
        f"{rows}</root></return></DiscoverResponse></Body></Envelope>"
    ).encode()
    assert len(body) > sealing.MAX_CHUNK  # (1) sealing must chunk it

    sealed_bytes = sealed(body)
    parts = [sealed_bytes[i : i + 2000] for i in range(0, len(sealed_bytes), 2000)]
    assert len(parts) > 1  # (2) DIME must chunk it

    ch = BytesChannel()
    ch.queue(synth.dime_message(synth.AUTHENTICATE_RESPONSE.format(token="").encode()))
    ch.queue(synth.chunked_dime_message(parts))

    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        catalogs = s.catalogs()

    assert len(catalogs) == 400
    assert catalogs[0].name == "C0000"
    assert catalogs[-1].name == "C0399"
