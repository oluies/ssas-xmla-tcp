"""Handshake tests driven by SYNTHETIC tokens (research.md D6)."""

import base64
import logging

import pytest

from ssas_xmla import auth
from ssas_xmla.errors import AuthenticationError, ProtocolError
from tests.fixtures import synth


class FakeContext:
    """A scripted GSS context: yields each token in turn, then completes."""

    def __init__(self, tokens, complete_after=None):
        self._tokens = list(tokens)
        self._i = 0
        self._complete_after = complete_after if complete_after is not None else len(tokens)
        self.protection = False

    def step(self, in_token=None):
        self.last_in = in_token
        if self._i >= len(self._tokens):
            return None
        token = self._tokens[self._i]
        self._i += 1
        return token

    @property
    def complete(self):
        return self._i >= self._complete_after


def _responder(server_tokens):
    """Returns a send_authenticate that replies with each server token in turn."""
    sent = []
    it = iter(server_tokens)

    def send(token_b64):
        sent.append(token_b64)
        try:
            tok = next(it)
        except StopIteration:
            tok = b""
        return synth.AUTHENTICATE_RESPONSE.format(token=base64.b64encode(tok).decode())

    return send, sent


def test_single_round_trip_completes():
    ctx = FakeContext([synth.FAKE_CLIENT_TOKEN], complete_after=1)
    send, sent = _responder([synth.FAKE_SERVER_TOKEN])
    auth.handshake(ctx, send)
    assert len(sent) == 1


def test_multi_round_trip_completes():
    ctx = FakeContext(
        [synth.FAKE_CLIENT_TOKEN, synth.FAKE_CLIENT_TOKEN, synth.FAKE_CLIENT_TOKEN],
        complete_after=3,
    )
    send, sent = _responder([synth.FAKE_SERVER_TOKEN, synth.FAKE_SERVER_TOKEN, b""])
    auth.handshake(ctx, send)
    assert len(sent) == 3


def test_server_token_is_fed_back_into_the_context():
    ctx = FakeContext([synth.FAKE_CLIENT_TOKEN, synth.FAKE_CLIENT_TOKEN], complete_after=2)
    send, _ = _responder([synth.FAKE_SERVER_TOKEN, b""])
    auth.handshake(ctx, send)
    assert ctx.last_in == synth.FAKE_SERVER_TOKEN


def test_a_context_that_never_completes_is_stopped():
    ctx = FakeContext([synth.FAKE_CLIENT_TOKEN] * 50, complete_after=99)
    send, _ = _responder([synth.FAKE_SERVER_TOKEN] * 50)
    with pytest.raises(AuthenticationError, match="did not complete"):
        auth.handshake(ctx, send, max_rounds=4)


def test_context_failure_does_not_leak_the_underlying_message():
    class Boom:
        protection = False
        complete = False

        def step(self, in_token=None):
            raise RuntimeError("principal reader@CORP.EXAMPLE.COM has no key")

    with pytest.raises(AuthenticationError) as excinfo:
        auth.handshake(Boom(), lambda t: "")
    assert "CORP.EXAMPLE.COM" not in str(excinfo.value)
    assert "reader@" not in str(excinfo.value)


def test_missing_token_in_response_is_a_protocol_error():
    with pytest.raises(ProtocolError, match="no security token"):
        auth.extract_token("<Envelope><Body/></Envelope>")


def test_no_token_is_ever_logged(caplog):
    caplog.set_level(logging.DEBUG)
    ctx = FakeContext([synth.FAKE_CLIENT_TOKEN], complete_after=1)
    send, _ = _responder([synth.FAKE_SERVER_TOKEN])
    auth.handshake(ctx, send)
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "SYNTHETIC" not in logged
    assert base64.b64encode(synth.FAKE_CLIENT_TOKEN).decode() not in logged


def test_credential_has_no_password_field():
    """So no code path can leak a credential by logging a Credential."""
    cred = auth.Credential(mechanism="ntlm", principal="svc")
    assert not any("pass" in f.lower() for f in cred.__dataclass_fields__)
    assert "pass" not in repr(cred).lower()


def test_fault_on_the_terminal_authenticate_round_is_not_dropped():
    """For NTLM the client context completes as it emits its last token, so the
    handshake returns without inspecting the reply. A "Logon failure" there was
    silently dropped and the session reached AUTHENTICATED regardless."""
    import pytest

    from ssas_xmla import dime
    from ssas_xmla.client import connect
    from ssas_xmla.errors import AuthenticationError
    from ssas_xmla.transport import BytesChannel
    from tests.unit.test_client_session import DoneContext

    fault = (
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><Fault>'
        "<faultcode>XMLAnalysisError.0xC1000001</faultcode>"
        "<faultstring>Logon failure: unknown user name or bad password.</faultstring>"
        "</Fault></Body></Envelope>"
    )
    ch = BytesChannel(synth.dime_message(fault.encode()))
    with pytest.raises(AuthenticationError, match="refused"):
        connect("h", 2383, channel=ch, context=DoneContext())
    del dime


# --- build_context: the bridge to pyspnego ------------------------------------


def test_build_context_passes_the_right_arguments(monkeypatch):
    """Kerberos and NTLM differ only by protocol; everything else is shared, which
    is why one handshake loop serves both."""
    import spnego

    from ssas_xmla.auth import Credential, build_context

    seen = {}

    def fake_client(**kwargs):
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(spnego, "client", fake_client)
    cred = Credential(mechanism="ntlm", principal="svc", service="MSOLAPSvc.3")
    build_context(cred, "host.example", password="pw")
    assert seen["protocol"] == "ntlm"
    assert seen["username"] == "svc"
    assert seen["password"] == "pw"
    assert seen["hostname"] == "host.example"
    assert seen["service"] == "MSOLAPSvc.3"


def test_build_context_selects_kerberos_for_ticket_mechanisms(monkeypatch):
    import spnego

    from ssas_xmla.auth import Credential, build_context

    seen = {}
    monkeypatch.setattr(spnego, "client", lambda **kw: seen.update(kw) or object())
    build_context(Credential(mechanism="KERBEROS"), "h")
    assert seen["protocol"] == "kerberos"
    assert seen["password"] is None  # ambient identity; nothing to pass


def test_build_context_failure_does_not_leak_the_underlying_message(monkeypatch):
    """A spnego failure can name the principal and realm."""
    import spnego

    from ssas_xmla.auth import Credential, build_context
    from ssas_xmla.errors import AuthenticationError

    def boom(**kwargs):
        raise ValueError("no credentials for reader@CORP.EXAMPLE.COM")

    monkeypatch.setattr(spnego, "client", boom)
    with pytest.raises(AuthenticationError) as excinfo:
        build_context(Credential(mechanism="kerberos", principal="reader"), "h")
    message = str(excinfo.value)
    assert "CORP.EXAMPLE.COM" not in message
    assert "kerberos" in message
