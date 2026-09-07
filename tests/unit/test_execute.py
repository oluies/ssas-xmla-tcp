"""US3: read-only query execution."""
import pytest

from ssas_xmla.client import ConnectionTarget, connect
from ssas_xmla.errors import ServerError
from ssas_xmla.transport import BytesChannel
from tests.fixtures import synth
from tests.unit.test_client_session import DoneContext


def _session(*payloads):
    ch = BytesChannel()
    ch.queue(synth.dime_message(synth.AUTHENTICATE_RESPONSE.format(token="").encode()))
    for p in payloads:
        ch.queue(synth.dime_message(p.encode()))
    return connect("h", 2383, channel=ch, context=DoneContext()), ch


def test_returns_rows():
    s, _ = _session(synth.EXECUTE_RESPONSE)
    result = s.execute("EVALUATE TOPN(2, Sales)")
    assert len(result) == 2
    assert result.rows[0]["SalesAmount"] == "1234.56"
    assert result.columns == ["ProductKey", "SalesAmount"]


def test_statement_is_carried_and_escaped():
    s, ch = _session(synth.EXECUTE_RESPONSE)
    s.execute("EVALUATE FILTER(T, T[x] < 5)")
    sent = bytes(ch.sent)
    assert b"<Statement>" in sent
    assert b"&lt; 5" in sent  # escaped, not raw


def test_catalog_is_sent_when_given():
    s, ch = _session(synth.EXECUTE_RESPONSE)
    s.execute("EVALUATE Sales", catalog="AWTabular")
    assert b"<Catalog>AWTabular</Catalog>" in bytes(ch.sent)


def test_malformed_query_surfaces_the_servers_own_text():
    """FR-008: the server's explanation reaches the caller, not a generic message."""
    s, _ = _session(synth.SYNTAX_FAULT)
    with pytest.raises(ServerError) as excinfo:
        s.execute("SELECT nonsense")
    assert "syntax for the query is incorrect" in str(excinfo.value)


def test_empty_result_is_not_an_error():
    s, _ = _session(synth.EMPTY_ROWSET_RESPONSE)
    assert len(s.execute("EVALUATE FILTER(Sales, FALSE())")) == 0


def test_timeout_is_bounded_and_cannot_be_disabled():
    """FR-009: there is no unbounded option, at any layer."""
    with pytest.raises(ValueError, match="unbounded"):
        ConnectionTarget(host="h", port=2383, timeout=0)
    with pytest.raises(ValueError):
        ConnectionTarget(host="h", port=2383, timeout=-1)
