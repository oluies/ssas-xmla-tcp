"""The integration fixtures are themselves somewhere a credential can go missing.

A password dropped there costs nothing in the offline suite -- it fails only on
the machine that HAS a live instance, and it fails as "could not initialise a
ntlm security context", which reads as a broken mechanism rather than as a
fixture that never passed what the README told the operator to export. So the
handover is asserted here, where it runs on every commit.
"""

from __future__ import annotations

import inspect

import pytest

from ssas_xmla import Credential
from tests.integration import conftest


def _raw(fixture):
    """The undecorated function behind a pytest fixture."""
    return getattr(fixture, "__wrapped__", fixture)


class _FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_live_session_hands_the_password_to_connect(monkeypatch):
    seen: dict[str, object] = {}

    def fake_connect(host, port, credential=None, password=None, **kwargs):
        seen.update(host=host, port=port, credential=credential, password=password)
        return _FakeSession()

    monkeypatch.setattr("ssas_xmla.connect", fake_connect)
    credential = Credential(mechanism="ntlm", principal="EXAMPLE\\reader")

    generator = _raw(conftest.live_session)(("host.example", 2383), credential, "s3cret")
    next(generator)
    generator.close()

    assert seen["password"] == "s3cret", "the password never reached connect()"
    assert seen["host"] == "host.example"
    assert seen["port"] == 2383


def test_ntlm_without_a_password_skips_with_the_cause(monkeypatch):
    """Not a bare skip: NTLM has no ambient identity, and saying so is the point."""
    monkeypatch.delenv("SSAS_PASSWORD", raising=False)
    credential = Credential(mechanism="NTLM", principal="EXAMPLE\\reader")

    with pytest.raises(BaseException) as caught:
        _raw(conftest.live_password)(credential)

    assert isinstance(caught.value, pytest.skip.Exception)
    assert "SSAS_PASSWORD" in str(caught.value)


def test_kerberos_without_a_password_is_not_an_error(monkeypatch):
    """The ambient ticket cache is the normal Kerberos case; demanding a password
    there would refuse the configuration the library is actually aimed at."""
    monkeypatch.delenv("SSAS_PASSWORD", raising=False)
    credential = Credential(mechanism="kerberos")

    assert _raw(conftest.live_password)(credential) is None


def test_the_fixture_signature_stays_honest():
    """live_session must REQUEST the password fixture; a default would hide its loss."""
    parameters = inspect.signature(_raw(conftest.live_session)).parameters
    assert "live_password" in parameters
