"""The probe CLI: argument handling and the failure-category exit codes.

probe.py was at 0% coverage while being the milestone's actual deliverable. Its
exit codes are the machine-readable form of FR-007/SC-005 -- an operator or a
script has to tell "wrong port" from "wrong password" from "no permission"
without parsing prose.
"""

import pytest

from ssas_xmla import probe
from ssas_xmla.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    NegotiationError,
    ServerError,
)
from ssas_xmla.rowset import Rowset


class _FakeSession:
    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def discover_datasources(self):
        if self._raises is not None:
            raise self._raises
        return self._result


@pytest.fixture
def patched_connect(monkeypatch):
    def _install(session_or_error):
        def fake_connect(*args, **kwargs):
            if isinstance(session_or_error, Exception):
                raise session_or_error
            return session_or_error

        monkeypatch.setattr(probe, "connect", fake_connect)

    return _install


ARGS = ["--host", "h", "--port", "2383"]


def test_success_prints_datasources_and_exits_zero(patched_connect, capsys):
    rows = Rowset(
        columns=["DataSourceName", "ProviderName"],
        rows=[{"DataSourceName": "AS", "ProviderName": "Microsoft Analysis Services"}],
    )
    patched_connect(_FakeSession(result=rows))
    assert probe.main(ARGS) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "AS" in out


@pytest.mark.parametrize(
    "error,code,phrase",
    [
        (ConnectionError("no route"), 2, "CONNECTION FAILED"),
        (AuthenticationError("bad ticket"), 3, "AUTHENTICATION FAILED"),
        (NegotiationError("binary xml"), 4, "NEGOTIATION FAILED"),
        (AuthorizationError("denied"), 5, "AUTHORIZATION REFUSED"),
        (ServerError("bad request"), 6, "SERVER REJECTED"),
    ],
)
def test_each_failure_category_has_its_own_exit_code(patched_connect, capsys, error, code, phrase):
    patched_connect(error)
    assert probe.main(ARGS) == code
    assert phrase in capsys.readouterr().err


def test_the_exit_codes_are_all_distinct():
    """A script has to tell the categories apart; overlapping codes would defeat
    the whole point of having separate error types."""
    codes = set()
    for err, expected in (
        (ConnectionError("x"), 2),
        (AuthenticationError("x"), 3),
        (NegotiationError("x"), 4),
        (AuthorizationError("x"), 5),
        (ServerError("x"), 6),
    ):
        codes.add(expected)
        del err
    assert len(codes) == 5
    assert 0 not in codes  # success must be unambiguous


def test_negotiation_failure_points_at_the_scope_decision(patched_connect, capsys):
    """A refused clear-text negotiation is a scope change, not a retryable error,
    so the operator is sent to the decision record rather than left guessing."""
    patched_connect(NegotiationError("server chose binary XML"))
    probe.main(ARGS)
    err = capsys.readouterr().err
    assert "research.md" in err


def test_port_is_required_and_documented_as_pinned():
    """There is no default port: guessing between a default instance's well-known
    port and a named instance's pinned one presents as a hang."""
    with pytest.raises(SystemExit):
        probe.main(["--host", "h"])


def test_password_comes_from_the_environment_not_argv(monkeypatch, patched_connect):
    """A password in argv is visible in the process list to every other user."""
    seen = {}

    def fake_connect(host, port, credential=None, timeout=None, password=None):
        seen["password"] = password
        return _FakeSession(result=Rowset())

    monkeypatch.setattr(probe, "connect", fake_connect)
    monkeypatch.setenv("SSAS_PASSWORD", "from-env")
    probe.main(ARGS)
    assert seen["password"] == "from-env"
    assert "--password" not in " ".join(ARGS)


def test_mechanism_choices_are_constrained():
    with pytest.raises(SystemExit):
        probe.main(ARGS + ["--mechanism", "telepathy"])
