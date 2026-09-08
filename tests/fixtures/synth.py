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
