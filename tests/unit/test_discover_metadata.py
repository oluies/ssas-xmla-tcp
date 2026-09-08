"""US2: catalog listing and per-catalog structure."""

import pytest

from ssas_xmla.client import Catalog, connect
from ssas_xmla.errors import AuthorizationError
from ssas_xmla.transport import BytesChannel
from tests.fixtures import synth
from tests.unit.test_client_session import DoneContext, sealed, sent_plaintext


def _session(*payloads):
    ch = BytesChannel()
    ch.queue(synth.dime_message(synth.AUTHENTICATE_RESPONSE.format(token="").encode()))
    for p in payloads:
        ch.queue(synth.dime_message(sealed(p.encode())))
    return connect("h", 2383, channel=ch, context=DoneContext()), ch


def test_lists_catalogs():
    s, _ = _session(synth.DBSCHEMA_CATALOGS_RESPONSE)
    cats = s.catalogs()
    assert [c.name for c in cats] == ["AWTabular", "AWMultidim"]
    assert isinstance(cats[0], Catalog)


def test_compatibility_level_alone_does_not_decide_the_kind():
    """COMPATIBILITY_LEVEL does not distinguish the two: multidimensional uses
    1050/1100/1103, so a ">= 1100 means tabular" rule mislabels every MD database
    made on SQL Server 2012 or later. Both rows here report unknown -- one has only
    a level, the other has nothing."""
    s, _ = _session(synth.DBSCHEMA_CATALOGS_RESPONSE)
    by_name = {c.name: c for c in s.catalogs()}
    assert by_name["AWTabular"].kind == "unknown"
    assert by_name["AWMultidim"].kind == "unknown"


def test_kind_is_reported_when_the_server_states_it():
    """CATALOG_TYPE is authoritative; both documented values are exercised."""
    body = (
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
        '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis"><return>'
        '<root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">'
        "<row><CATALOG_NAME>T</CATALOG_NAME><CATALOG_TYPE>Tabular</CATALOG_TYPE></row>"
        "<row><CATALOG_NAME>M</CATALOG_NAME>"
        "<CATALOG_TYPE>Multidimensional</CATALOG_TYPE></row>"
        "</root></return></DiscoverResponse></Body></Envelope>"
    )
    s, _ = _session(body)
    by_name = {c.name: c.kind for c in s.catalogs()}
    assert by_name == {"T": "tabular", "M": "multidimensional"}


def test_session_id_is_captured_and_reused():
    """[MS-SSAS] requires every request after the first to carry the SessionId.
    Without capture the client re-sent BeginSession forever, opening a new
    server-side session per request."""
    with_session = synth.EMPTY_ROWSET_RESPONSE.replace(
        "<Body>",
        '<Header><Session xmlns="urn:schemas-microsoft-com:xml-analysis" '
        'SessionId="ABC-123"/></Header><Body>',
    )
    s, ch = _session(with_session, synth.EMPTY_ROWSET_RESPONSE)
    s.discover("DBSCHEMA_CATALOGS")
    first = sent_plaintext(ch)
    assert b"BeginSession" in first
    s.discover("DBSCHEMA_TABLES")
    second = sent_plaintext(ch)[len(first) :]
    assert b'SessionId="ABC-123"' in second
    assert b"BeginSession" not in second


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
    assert b"<Catalog>AWTabular</Catalog>" in sent_plaintext(ch)
    assert b"DBSCHEMA_TABLES" in sent_plaintext(ch)


def test_columns_requests_the_column_rowset():
    s, ch = _session(synth.EMPTY_ROWSET_RESPONSE)
    s.columns("AWTabular")
    assert b"DBSCHEMA_COLUMNS" in sent_plaintext(ch)


def test_restrictions_are_passed_through():
    s, ch = _session(synth.EMPTY_ROWSET_RESPONSE)
    s.discover("MDSCHEMA_CUBES", restrictions={"CUBE_NAME": "Sales"})
    assert b"<CUBE_NAME>Sales</CUBE_NAME>" in sent_plaintext(ch)


def test_restriction_values_are_escaped():
    """This parameter was the one route by which caller text reached the wire
    unfiltered."""
    s, ch = _session(synth.EMPTY_ROWSET_RESPONSE)
    s.discover("MDSCHEMA_CUBES", restrictions={"CUBE_NAME": "A & B <x>"})
    sent = sent_plaintext(ch)
    assert b"A &amp; B &lt;x&gt;" in sent
    assert b"<x>" not in sent.split(b"<RestrictionList>")[1].split(b"</RestrictionList>")[0]


def test_restriction_names_are_validated_not_escaped():
    """An element NAME cannot be made safe by escaping; it has to be rejected."""
    import pytest

    s, _ = _session(synth.EMPTY_ROWSET_RESPONSE)
    with pytest.raises(ValueError, match="invalid restriction name"):
        s.discover("MDSCHEMA_CUBES", restrictions={"</RestrictionList><Injected/><N": "v"})


def test_rows_without_a_name_are_skipped():
    odd = synth.DBSCHEMA_CATALOGS_RESPONSE.replace(
        "<CATALOG_NAME>AWMultidim</CATALOG_NAME>", "<CATALOG_NAME></CATALOG_NAME>"
    )
    s, _ = _session(odd)
    assert [c.name for c in s.catalogs()] == ["AWTabular"]
