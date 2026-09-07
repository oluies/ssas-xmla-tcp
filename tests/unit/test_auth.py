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
