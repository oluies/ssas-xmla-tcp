"""Synthetic protocol material for tests.

Handshake tokens are SYNTHESIZED, never captured (research.md D6, constitution I).
A real GSS/SPNEGO token carries the principal, the realm, the target service and
often the machine name — a committed capture would be a disclosure that looks like
an opaque blob, and no scrubber can reliably redact arbitrary token structure. The
safe version is not to hold the bytes at all.
"""

from __future__ import annotations

from ssas_xmla import dime

# Deliberately not a real SPNEGO token: recognisable filler of a plausible length.
FAKE_CLIENT_TOKEN = b"SYNTHETIC-CLIENT-TOKEN-" + b"\xab" * 32
FAKE_SERVER_TOKEN = b"SYNTHETIC-SERVER-TOKEN-" + b"\xcd" * 32


def dime_message(payload: bytes, type_: bytes = dime.TYPE_TEXT_XML) -> bytes:
    """Wrap a payload as a single-record DIME message, as a server would."""
    return dime.Record(data=payload, type_=type_).encode()


def dime_message_with_options(payload: bytes, options_first_byte: int) -> bytes:
    """A server message whose OPTIONS select an encoding, for negotiation tests."""
    options = bytes([options_first_byte, 0, 0, 0])
    return dime.Record(data=payload, options=options).encode()


def chunked_dime_message(parts: list[bytes]) -> bytes:
    """A message split across several records: MB on the first, ME on the last."""
    out = []
    last = len(parts) - 1
    for i, part in enumerate(parts):
        out.append(
            dime.Record(
                data=part,
                type_=dime.TYPE_TEXT_XML if i == 0 else b"",
                mb=(i == 0),
                me=(i == last),
                cf=(i != last),
                type_t=1 if i == 0 else 0,
            ).encode()
        )
    return b"".join(out)


def trickling(wire: bytes, per_read: int = 7):
    """A channel that hands back a few bytes per read, whatever size was asked for.

    Shared rather than redefined per test: TCP fragmentation is one behaviour, and
    two copies of it drift. `per_read` is small on purpose — the reader must be
    driven by the header's declared lengths, never by the peer going quiet.
    """
    from ssas_xmla.transport import BytesChannel

    class Trickle(BytesChannel):
        def recv(self, size):
            return super().recv(per_read)

    return Trickle(wire)


AUTHENTICATE_RESPONSE = (
    '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
    '<AuthenticateResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
    "<return>{token}</return>"
    "</AuthenticateResponse></Body></Envelope>"
)

DISCOVER_DATASOURCES_RESPONSE = """<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>
<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis"><return>
<root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">
<row><DataSourceName>Analysis Services</DataSourceName>
<DataSourceDescription>Test instance</DataSourceDescription>
<ProviderName>Microsoft Analysis Services</ProviderName>
<ProviderType>MDP</ProviderType>
<AuthenticationMode>Integrated</AuthenticationMode></row>
</root></return></DiscoverResponse></Body></Envelope>"""

# The same response as above, but carrying the Session header the server returns
# to BeginSession. [MS-SSAS] "Initialization for Non-HTTP Transport": every later
# request MUST echo the SessionId, and without it the client re-sent BeginSession
# forever and opened a new server-side session per request.
DISCOVER_DATASOURCES_RESPONSE_WITH_SESSION = DISCOVER_DATASOURCES_RESPONSE.replace(
    "<Body>",
    '<Header><Session SessionId="A1B2C3" '
    'xmlns="urn:schemas-microsoft-com:xml-analysis"/></Header><Body>',
    1,
)

SOAP_FAULT = """<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>
<Fault><faultcode>XMLAnalysisError.0xC10E0002</faultcode>
<faultstring>Either the user, DOMAIN\\reader, does not have access to the
AWTabular database, or the database does not exist.</faultstring>
</Fault></Body></Envelope>"""


DBSCHEMA_CATALOGS_RESPONSE = """<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>
<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis"><return>
<root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">
<row><CATALOG_NAME>AWTabular</CATALOG_NAME><DESCRIPTION>Tabular model</DESCRIPTION>
<COMPATIBILITY_LEVEL>1600</COMPATIBILITY_LEVEL></row>
<row><CATALOG_NAME>AWMultidim</CATALOG_NAME><DESCRIPTION>Cube</DESCRIPTION></row>
</root></return></DiscoverResponse></Body></Envelope>"""

EMPTY_ROWSET_RESPONSE = (
    '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
    '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
    '<return><root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset"/></return>'
    "</DiscoverResponse></Body></Envelope>"
)

EXECUTE_RESPONSE = """<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>
<ExecuteResponse xmlns="urn:schemas-microsoft-com:xml-analysis"><return>
<root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">
<row><ProductKey>1</ProductKey><SalesAmount>1234.56</SalesAmount></row>
<row><ProductKey>2</ProductKey><SalesAmount>78.90</SalesAmount></row>
</root></return></ExecuteResponse></Body></Envelope>"""

SYNTAX_FAULT = (
    '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><Fault>'
    "<faultcode>XMLAnalysisError.0xC1210003</faultcode>"
    "<faultstring>Query (1, 8) The syntax for the query is incorrect.</faultstring>"
    "</Fault></Body></Envelope>"
)


# The DISCOVER_PROPERTIES rowset columns, in the order a server sends them
# ([MS-SSAS] "Server Response", and the DISCOVER_PROPERTIES rowset definition).
# There is no PropertyValue column; the value column is Value.
DISCOVER_PROPERTIES_COLUMNS = (
    "PropertyName",
    "PropertyDescription",
    "PropertyType",
    "PropertyAccessType",
    "IsRequired",
    "Value",
)


def discover_properties_row(name: str, value: str | None, **overrides: str) -> dict[str, str]:
    """One DISCOVER_PROPERTIES row carrying every column a server sends.

    `value=None` omits the Value element, which is what the specification's own
    example shows for a property the server has no value for -- the case that
    must stay distinguishable from a property that is absent entirely.
    """
    row = {
        "PropertyName": name,
        "PropertyDescription": name,
        "PropertyType": "string",
        "PropertyAccessType": "Read",
        "IsRequired": "false",
    }
    if value is not None:
        row["Value"] = value
    row.update(overrides)
    return row


def discover_properties_response(rows: list[dict[str, str]]) -> str:
    """A DISCOVER_PROPERTIES response shaped as [MS-SSAS] shows a server sending one.

    Synthesized from the specification's published example, never captured. That
    example carries a machine name and an account of its own (ServerName,
    UserName), and a capture would carry this site's, while the only thing a test
    needs is the element NAMES -- reading one the server does not send is the
    defect this fixture exists to make visible.

    Version values here are three-part. A real one is four (16.0.x.y), which is
    dotted-quad shaped, and the leak gate refuses a committed file containing one:
    it cannot tell a build number from an address, and failing closed is the right
    way round.
    """
    body = "".join(
        "<row>" + "".join(f"<{name}>{text}</{name}>" for name, text in row.items()) + "</row>"
        for row in rows
    )
    return (
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
        '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
        '<return><root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">'
        f"{body}"
        "</root></return></DiscoverResponse></Body></Envelope>"
    )


# A metadata rowset puts a DOCUMENT inside one cell instead of a scalar. This is the
# shape DISCOVER_CSDL_METADATA comes back in -- the model's CSDL as element children
# of <METADATA>, which is why <METADATA> has no text of its own. Synthesized from the
# shape, not captured: a real model's CSDL carries captions and column names from the
# site that owns it.
CSDL_IN_A_CELL = (
    '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
    '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
    '<return><root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">'
    "<row><METADATA>"
    '<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">'
    '<EntityType Name="DimProduct">'
    '<Property Name="ProductKey" Type="Int64" Nullable="false" />'
    "</EntityType>"
    "</Schema>"
    "</METADATA></row>"
    "</root></return></DiscoverResponse></Body></Envelope>"
)


# Two element children in ONE cell, which is the shape that made concatenating
# children wrong: DISCOVER_SCHEMA_ROWSETS puts <Name> and <Type> side by side in
# its Restrictions cell, and `<Name/><Type/>` is a fragment, not a document.
# Synthesized from that shape; the real response is 39KB of it.
TWO_ELEMENTS_IN_A_CELL = (
    '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
    '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
    '<return><root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">'
    "<row><SchemaName>DBSCHEMA_CATALOGS</SchemaName>"
    "<Restrictions><Name>CATALOG_NAME</Name><Type>xsd:string</Type></Restrictions>"
    "</row>"
    "</root></return></DiscoverResponse></Body></Envelope>"
)

# A cell whose content contains elements named `row`. No recorded response does
# this, but the parser walked the whole tree looking for rows, so a cell like it
# would have been read twice: once as its parent's cell, once as rows of its own.
ROWS_INSIDE_A_CELL = (
    '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
    '<DiscoverResponse xmlns="urn:schemas-microsoft-com:xml-analysis">'
    '<return><root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">'
    "<row><OUTER>yes</OUTER>"
    "<NESTED><row><INNER>a</INNER></row><row><INNER>b</INNER></row></NESTED>"
    "</row>"
    "</root></return></DiscoverResponse></Body></Envelope>"
)
