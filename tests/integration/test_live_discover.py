"""T030: the exchange milestone 1 exists to prove, against a real instance.

Also settles T031 — whether the server accepts the clear-text negotiation. A
NegotiationError here is not a bug in this test: it means D2's assumption is wrong
and the feature must be re-estimated before US2 work continues.
"""
import pytest

pytestmark = pytest.mark.integration


def test_discover_datasources_returns_rows(live_session):
    result = live_session.discover_datasources()
    assert len(result) >= 1
    assert "DataSourceName" in result.columns


def test_clear_text_negotiation_was_accepted(live_session):
    """T031, the decision gate. If this fails, stop and read D2 in research.md."""
    assert live_session.terms.content_type == "text/xml"
    assert not live_session.terms.request_binary
    assert not live_session.terms.response_binary
    assert not live_session.terms.request_compressed
    assert not live_session.terms.response_compressed


def test_catalogs_are_listed(live_session):
    catalogs = live_session.catalogs()
    # An empty list is legitimate (the account may see nothing), so assert the
    # call succeeds and is well-formed rather than that data exists.
    assert all(c.name for c in catalogs)
