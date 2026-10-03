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
    """The value has to parse, because every consumer of it parses it. The root is
    the CELL -- a name the server sent -- so there is exactly one root whatever the
    cell holds."""
    import xml.etree.ElementTree as ET

    cell = rowset.parse(synth.CSDL_IN_A_CELL).rows[0]["METADATA"]
    root = ET.fromstring(cell)
    assert root.tag.rsplit("}", 1)[-1] == "METADATA"
    names = [el.get("Name") for el in root.iter() if el.tag.endswith("EntityType")]
    assert names == ["DimProduct"]


def test_a_cell_with_several_children_still_parses():
    """Concatenating a cell's children produced a multi-root fragment, and the
    contract these tests state is that the value parses. DISCOVER_SCHEMA_ROWSETS
    reaches it through the public API: its Restrictions cell holds <Name> and
    <Type> side by side."""
    import xml.etree.ElementTree as ET

    r = rowset.parse(synth.TWO_ELEMENTS_IN_A_CELL)
    cell = r.rows[0]["Restrictions"]
    root = ET.fromstring(cell)  # would raise "junk after document element"
    assert [el.tag.rsplit("}", 1)[-1] for el in root] == ["Name", "Type"]
    assert r.rows[0]["SchemaName"] == "DBSCHEMA_CATALOGS"


def test_the_namespace_survives_even_though_the_prefix_does_not():
    """ElementTree re-serialises, so a default namespace comes back as a generated
    prefix. The URI is the part consumers rely on, so that is what is asserted --
    a test pinned to `xmlns="..."` would pass only by accident of ET's spelling."""
    import xml.etree.ElementTree as ET

    cell = rowset.parse(synth.CSDL_IN_A_CELL).rows[0]["METADATA"]
    schema = next(el for el in ET.fromstring(cell).iter() if el.tag.rsplit("}", 1)[-1] == "Schema")
    assert schema.tag == "{http://schemas.microsoft.com/ado/2008/09/edm}Schema"


def test_rows_inside_a_cell_are_not_read_as_rows():
    """The cell owns its subtree. Walking the whole tree for `row` elements read
    such content twice: once as the parent's cell, once as rows of its own, with
    the inner names leaking into `columns`."""
    import xml.etree.ElementTree as ET

    r = rowset.parse(synth.ROWS_INSIDE_A_CELL)
    assert len(r) == 1
    assert r.columns == ["OUTER", "NESTED"]
    assert "INNER" not in r.columns
    # the nested rows are still there -- inside the cell, where they belong
    nested = ET.fromstring(r.rows[0]["NESTED"])
    assert len([el for el in nested.iter() if el.tag.rsplit("}", 1)[-1] == "row"]) == 2


def test_a_scalar_cell_is_untouched():
    """The nested-document path must not change the ordinary case: these values are
    read as strings by every caller, and a stray re-serialisation would show up as
    markup in a catalog name."""
    r = rowset.parse(synth.DISCOVER_DATASOURCES_RESPONSE)
    assert r.rows[0]["DataSourceName"] == "Analysis Services"
    assert "<" not in r.rows[0]["ProviderType"]
