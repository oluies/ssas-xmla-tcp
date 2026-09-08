"""Handshake tests driven by SYNTHETIC tokens (research.md D6)."""

import base64
import logging

import pytest

from ssas_xmla import auth
from ssas_xmla.auth import Credential
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
    from ssas_xmla.client import connect
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


# --- build_context: the bridge to pyspnego ------------------------------------


def test_build_context_passes_the_right_arguments(monkeypatch):
    """Kerberos and NTLM differ only by protocol; everything else is shared, which
    is why one handshake loop serves both."""
    import spnego

    from ssas_xmla.auth import Credential, build_context

    seen: dict = {}

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


def test_an_unknown_mechanism_is_rejected_not_coerced_to_ntlm():
    """Credential is public API and integration config feeds it straight from
    $SSAS_MECHANISM, so a typo used to authenticate as NTLM without a word."""
    from ssas_xmla.auth import Credential, build_context
    from ssas_xmla.errors import AuthenticationError

    with pytest.raises(AuthenticationError, match="unknown authMechanism"):
        build_context(Credential(mechanism="kerbros"), "host")


def test_negotiate_is_accepted_and_is_not_ntlm(monkeypatch):
    import spnego

    from ssas_xmla.auth import Credential, build_context

    seen = {}
    monkeypatch.setattr(spnego, "client", lambda **kw: seen.update(kw) or object())
    build_context(Credential(mechanism="negotiate"), "h")
    assert seen["protocol"] == "negotiate"


# --- the SPN ------------------------------------------------------------------
# NTLM ignores the target, which is why a portless SPN worked all along; Kerberos
# matches the SPN as registered and will not. Mirrors ADOMD's
# CalculateNTAuthenticationSPN (XmlaClient.cs:2750).


def test_the_default_spn_is_portless():
    """ADOMD calls DsMakeSpn WITH the port, but that justifies the string only on
    SSPI. On the GSSAPI path this library actually takes, the host half is imported
    as hostbased_service and goes through realm determination, where a trailing
    `example:2383` maps to no realm. Neither form is KDC-tested, so the default is
    the shape that shipped and that GSSAPI expects."""
    assert Credential().target("box.example", 2383) == "MSOLAPSvc.3/box.example"


def test_the_port_form_is_available_explicitly():
    assert Credential(use_port=True).target("box.example", 2383) == ("MSOLAPSvc.3/box.example:2383")


def test_a_named_instance_registers_under_the_instance_name():
    cred = Credential(instance="TAB")
    assert cred.target("box.example", 2383) == "MSOLAPSvc.3/box.example:TAB"


def test_an_explicit_spn_overrides_everything():
    cred = Credential(instance="TAB", spn="MSOLAPSvc.3/other.example")
    assert cred.target("box.example", 2383) == "MSOLAPSvc.3/other.example"


def test_the_service_class_is_configurable():
    """SQL Browser uses MSOLAPDisco.3; a site may register another class."""
    assert Credential(service="MSOLAPDisco.3", use_port=True).target("box.example", 0) == (
        "MSOLAPDisco.3/box.example:0"
    )


def test_no_port_falls_back_to_the_portless_form():
    assert Credential().target("box.example") == "MSOLAPSvc.3/box.example"


# --- build_context passes BOTH halves of the SPN -------------------------------
# spnego recomposes the SPN as f"{service}/{hostname}", so overriding only the host
# silently discarded the service class of a full `spn=` override -- the main reason
# a site sets one. These go through build_context, not just Credential.target():
# the earlier tests asserted the string and so could not catch this.


class _Spy:
    """Captures what build_context hands to spnego.client."""

    def __init__(self):
        self.seen = {}

    def client(self, **kwargs):
        self.seen = kwargs
        return object()


def _spy_build(monkeypatch, credential, host="box.example", port=2383):
    import sys
    import types

    spy = _Spy()
    module = types.ModuleType("spnego")
    module.client = spy.client
    monkeypatch.setitem(sys.modules, "spnego", module)
    auth.build_context(credential, host, None, port)
    return spy.seen


def test_a_full_spn_override_changes_the_service_class_too(monkeypatch):
    seen = _spy_build(monkeypatch, Credential(spn="HOST/other.example"))
    assert (seen["service"], seen["hostname"]) == ("HOST", "other.example")


def test_the_default_reaches_spnego_as_service_and_bare_host(monkeypatch):
    seen = _spy_build(monkeypatch, Credential())
    assert (seen["service"], seen["hostname"]) == ("MSOLAPSvc.3", "box.example")


def test_the_instance_form_keeps_the_instance_in_the_host_half(monkeypatch):
    seen = _spy_build(monkeypatch, Credential(instance="TAB"))
    assert (seen["service"], seen["hostname"]) == ("MSOLAPSvc.3", "box.example:TAB")


def test_an_spn_without_a_slash_is_refused_not_an_IndexError(monkeypatch):
    """`.split("/", 1)[1]` raised IndexError -- an uncaught exception outside the
    FR-007 taxonomy, which open() turned into State.FAILED plus a bare IndexError."""
    with pytest.raises(AuthenticationError, match="<service>/<host>"):
        _spy_build(monkeypatch, Credential(spn="olap.corp.example"))
