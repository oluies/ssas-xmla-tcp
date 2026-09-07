from ssas_xmla import envelopes


def test_discover_envelope_has_the_specified_structure():
    xml = envelopes.discover("DISCOVER_DATASOURCES").decode()
    assert f'<Envelope xmlns="{envelopes.SOAP_NS}">' in xml
    assert f'<Discover xmlns="{envelopes.XMLA_NS}">' in xml
    assert "<RequestType>DISCOVER_DATASOURCES</RequestType>" in xml
    assert "<Restrictions><RestrictionList></RestrictionList></Restrictions>" in xml
    assert "<Properties><PropertyList></PropertyList></Properties>" in xml


def test_authenticate_uses_the_ext_namespace_not_the_xmla_one():
    """A live server rejects Authenticate under the XMLA namespace outright:
    "The Authenticate element ... cannot appear under Envelope/Body". [MS-SSAS]
    Authentication shows it in the analysisservices/2003/ext namespace."""
    xml = envelopes.authenticate("QUJD").decode()
    assert f'<Authenticate xmlns="{envelopes.EXT_NS}">' in xml
    assert envelopes.EXT_NS != envelopes.XMLA_NS
    assert f'<Authenticate xmlns="{envelopes.XMLA_NS}">' not in xml
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


def test_first_request_carries_begin_session():
    """[MS-SSAS] Initialization for Non-HTTP Transport requires it."""
    xml = envelopes.discover("DISCOVER_DATASOURCES").decode()
    assert "<Header>" in xml
    assert f'<BeginSession xmlns="{envelopes.XMLA_NS}" mustUnderstand="1"/>' in xml


def test_later_requests_carry_the_session_id():
    xml = envelopes.discover("DBSCHEMA_CATALOGS", session_id="ABC-123").decode()
    assert 'SessionId="ABC-123"' in xml
    assert "BeginSession" not in xml


def test_execute_carries_the_session_header_too():
    xml = envelopes.execute("EVALUATE X", session_id="S1").decode()
    assert 'SessionId="S1"' in xml
