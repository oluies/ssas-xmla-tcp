"""US2: catalog listing and per-catalog structure."""

import pytest

from ssas_xmla.client import Catalog, connect
from ssas_xmla.errors import AuthorizationError
from ssas_xmla.transport import BytesChannel
from tests.fixtures import synth
from tests.unit.test_client_session import DoneContext


def _session(*payloads):
    ch = BytesChannel()
    ch.queue(synth.dime_message(synth.AUTHENTICATE_RESPONSE.format(token="").encode()))
    for p in payloads:
        ch.queue(synth.dime_message(p.encode()))
    return connect("h", 2383, channel=ch, context=DoneContext()), ch


def test_lists_catalogs():
    s, _ = _session(synth.DBSCHEMA_CATALOGS_RESPONSE)
    cats = s.catalogs()
    assert [c.name for c in cats] == ["AWTabular", "AWMultidim"]
    assert isinstance(cats[0], Catalog)


def test_infers_model_kind_from_compatibility_level():
    s, _ = _session(synth.DBSCHEMA_CATALOGS_RESPONSE)
    by_name = {c.name: c for c in s.catalogs()}
    assert by_name["AWTabular"].kind == "tabular"
    # No level reported, and nothing else to go on: say unknown rather than guess.
    assert by_name["AWMultidim"].kind == "unknown"


def test_empty_catalog_list_is_valid_and_not_an_error():
    """FR-007: nothing visible is a different answer from being refused."""
    s, _ = _session(synth.EMPTY_ROWSET_RESPONSE)
    assert s.catalogs() == []


def test_refusal_raises_rather_than_returning_empty():
    s, _ = _session(synth.SOAP_FAULT)
    with pytest.raises(AuthorizationError):
        s.catalogs()


def test_catalog_restricts_the_request():
    s, ch = _session(synth.EMPTY_ROWSET_RESPONSE)
    s.tables("AWTabular")
    assert b"<Catalog>AWTabular</Catalog>" in bytes(ch.sent)
    assert b"DBSCHEMA_TABLES" in bytes(ch.sent)


def test_columns_requests_the_column_rowset():
    s, ch = _session(synth.EMPTY_ROWSET_RESPONSE)
    s.columns("AWTabular")
    assert b"DBSCHEMA_COLUMNS" in bytes(ch.sent)


def test_restrictions_are_passed_through():
    s, ch = _session(synth.EMPTY_ROWSET_RESPONSE)
    s.discover("MDSCHEMA_CUBES", restrictions="<CUBE_NAME>Sales</CUBE_NAME>")
    assert b"<CUBE_NAME>Sales</CUBE_NAME>" in bytes(ch.sent)


def test_rows_without_a_name_are_skipped():
    odd = synth.DBSCHEMA_CATALOGS_RESPONSE.replace(
        "<CATALOG_NAME>AWMultidim</CATALOG_NAME>", "<CATALOG_NAME></CATALOG_NAME>"
    )
    s, _ = _session(odd)
    assert [c.name for c in s.catalogs()] == ["AWTabular"]
