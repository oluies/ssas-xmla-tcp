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


def test_the_exit_codes_are_all_distinct(patched_connect, monkeypatch):
    """A script has to tell the categories apart, so no two may share a code.

    Earlier this asserted len({2,3,4,5,6}) == 5 -- true by construction, and it
    would have passed even if probe.main returned 3 for two different errors. It
    now runs probe for each category and collects what it actually returns.
    """
    observed = {}
    for error in (
        ConnectionError("x"),
        AuthenticationError("x"),
        NegotiationError("x"),
        AuthorizationError("x"),
        ServerError("x"),
    ):
        patched_connect(error)
        observed[type(error).__name__] = probe.main(ARGS)
    assert len(set(observed.values())) == len(observed), observed
    assert 0 not in observed.values()  # success must stay unambiguous


def test_a_failure_raised_by_the_request_is_also_categorised(patched_connect, capsys):
    """Every other failure test raises from `connect`. This one connects fine and
    fails on the request, which is a different code path through probe.main."""
    patched_connect(_FakeSession(raises=AuthorizationError("no read permission")))
    assert probe.main(ARGS) == 5
    assert "AUTHORIZATION REFUSED" in capsys.readouterr().err


def test_an_unexpected_ssas_error_still_exits_nonzero(patched_connect, capsys):
    """The `except SsasError` catch-all was untested; without it an unmapped
    error would traceback instead of reporting. Uses the base class deliberately:
    ProtocolError now has its own handler, so it no longer exercises the fallback."""
    from ssas_xmla.errors import SsasError

    patched_connect(_FakeSession(raises=SsasError("something unmapped")))
    assert probe.main(ARGS) == 1
    assert "FAILED" in capsys.readouterr().err


def test_a_protocol_error_is_its_own_outcome(patched_connect, capsys):
    from ssas_xmla.errors import ProtocolError

    patched_connect(_FakeSession(raises=ProtocolError("malformed record")))
    assert probe.main(ARGS) == 7
    assert "PROTOCOL ERROR" in capsys.readouterr().err


def test_a_padding_mechanism_is_reported_with_the_fix(patched_connect, capsys):
    """Kerberos is the default, and a padding mechanism cannot be framed at all --
    so the out-of-the-box run used to die with a generic FAILED after a SUCCESSFUL
    handshake, for a configuration the library already knew it could not support."""
    from ssas_xmla.errors import ProtocolError

    patched_connect(
        _FakeSession(
            raises=ProtocolError("the negotiated mechanism padded the plaintext by 4 bytes")
        )
    )
    assert probe.main(ARGS) == 7
    err = capsys.readouterr().err
    assert "--mechanism ntlm" in err


def test_the_authentication_hint_names_the_spn_that_was_requested(patched_connect, capsys):
    """ "Check ticket or keytab" pointed at the wrong cause when the real problem
    was an SPN that did not match how the instance is registered."""
    from ssas_xmla.errors import AuthenticationError

    patched_connect(_FakeSession(raises=AuthenticationError("refused")))
    assert probe.main(ARGS) == 3
    err = capsys.readouterr().err
    assert "MSOLAPSvc.3/" in err
    assert "--instance" in err and "--spn" in err


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


def test_there_is_no_password_flag_to_reintroduce():
    """The invariant worth pinning is the parser's shape, not that one local
    constant happens to omit a flag."""
    with pytest.raises(SystemExit):
        probe.main(ARGS + ["--password", "s3cret"])


def test_mechanism_choices_are_constrained():
    with pytest.raises(SystemExit):
        probe.main(ARGS + ["--mechanism", "telepathy"])


def test_ntlm_is_not_told_to_check_an_spn_it_ignores(patched_connect, capsys):
    """NTLM ignores the target entirely, so SPN advice on an NTLM failure points at
    three flags that cannot change anything — the same misdirection the hint was
    written to remove, aimed at the one mechanism verified end to end."""
    from ssas_xmla.errors import AuthenticationError

    patched_connect(_FakeSession(raises=AuthenticationError("refused")))
    assert probe.main(["--host", "h", "--port", "2383", "--mechanism", "ntlm"]) == 3
    err = capsys.readouterr().err
    assert "SPN" in err  # it says NTLM ignores it...
    assert "--instance" not in err and "--use-port" not in err  # ...and offers no flag
    assert "SSAS_PASSWORD" in err
