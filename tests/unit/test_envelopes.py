from ssas_xmla import envelopes


def test_discover_envelope_has_the_specified_structure():
    xml = envelopes.discover("DISCOVER_DATASOURCES").decode()
    assert f'<Envelope xmlns="{envelopes.SOAP_NS}">' in xml
    assert f'<Discover xmlns="{envelopes.XMLA_NS}">' in xml
    assert "<RequestType>DISCOVER_DATASOURCES</RequestType>" in xml
    assert "<Restrictions><RestrictionList></RestrictionList></Restrictions>" in xml
    assert "<Properties><PropertyList></PropertyList></Properties>" in xml


def test_authenticate_envelope_carries_the_token():
    xml = envelopes.authenticate("QUJD").decode()
    assert f'<Authenticate xmlns="{envelopes.XMLA_NS}">' in xml
    assert "<SspiHandshake>QUJD</SspiHandshake>" in xml


def test_catalog_is_supplied_as_a_property():
    xml = envelopes.discover("MDSCHEMA_CUBES", catalog="AWTabular").decode()
    assert "<Catalog>AWTabular</Catalog>" in xml


def test_values_are_escaped():
    xml = envelopes.execute("EVALUATE TOPN(1, 'T' & \"<x>\")").decode()
    assert "<x>" not in xml.split("<Statement>")[1].split("</Statement>")[0]
    assert "&lt;x&gt;" in xml


def test_no_builder_exists_for_a_mutating_command():
    """Constitution II: read-only by construction, not by convention."""
    surface = {n for n in dir(envelopes) if not n.startswith("_")}
    for forbidden in ("create", "alter", "delete", "refresh", "process", "tmsl"):
        assert not any(forbidden in n.lower() for n in surface), forbidden
