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
