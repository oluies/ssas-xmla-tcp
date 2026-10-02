from ssas_xmla import rowset
from tests.fixtures import synth


def test_parses_a_namespaced_rowset():
    r = rowset.parse(synth.DISCOVER_DATASOURCES_RESPONSE)
    assert len(r) == 1
    assert "DataSourceName" in r.columns
    assert r.rows[0]["ProviderType"] == "MDP"


def test_empty_result_is_not_an_error():
    empty = (
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
        '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
        '<return><root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset"/></return>'
        "</DiscoverResponse></Body></Envelope>"
    )
    r = rowset.parse(empty)
    assert len(r) == 0
    assert r.columns == []


def test_unparseable_xml_yields_an_empty_rowset_not_a_crash():
    assert len(rowset.parse("<not xml")) == 0


def test_finds_a_soap_fault():
    code, message = rowset.find_fault(synth.SOAP_FAULT)
    assert code and "XMLAnalysisError" in code
    assert message and "does not have access" in message


def test_no_fault_in_a_good_response():
    assert rowset.find_fault(synth.DISCOVER_DATASOURCES_RESPONSE) == (None, None)


def test_rows_iterate():
    r = rowset.parse(synth.DISCOVER_DATASOURCES_RESPONSE)
    assert [row["DataSourceName"] for row in r] == ["Analysis Services"]


def test_a_cell_carrying_a_document_keeps_it():
    """A metadata rowset can put a whole document inside one cell. Reading only the
    cell's own text discarded it and reported a blank cell, which no consumer could
    tell apart from a server that sent nothing -- the OpenMetadata connector
    ingested a database, a schema and zero tables that way, and called it success."""
    r = rowset.parse(synth.CSDL_IN_A_CELL)
    assert len(r) == 1
    assert r.columns == ["METADATA"]
    cell = r.rows[0]["METADATA"]
    assert "EntityType" in cell
    assert 'Name="DimProduct"' in cell
    assert 'Name="ProductKey"' in cell


def test_a_preserved_document_is_real_xml_not_a_description_of_one():
    """The value has to parse, because every consumer of it parses it."""
    import xml.etree.ElementTree as ET

    cell = rowset.parse(synth.CSDL_IN_A_CELL).rows[0]["METADATA"]
    root = ET.fromstring(cell)
    names = [el.get("Name") for el in root.iter() if el.tag.endswith("EntityType")]
    assert names == ["DimProduct"]


def test_a_scalar_cell_is_untouched():
    """The nested-document path must not change the ordinary case: these values are
    read as strings by every caller, and a stray re-serialisation would show up as
    markup in a catalog name."""
    r = rowset.parse(synth.DISCOVER_DATASOURCES_RESPONSE)
    assert r.rows[0]["DataSourceName"] == "Analysis Services"
    assert "<" not in r.rows[0]["ProviderType"]
