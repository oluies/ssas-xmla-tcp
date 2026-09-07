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

SOAP_FAULT = """<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>
<Fault><faultcode>XMLAnalysisError.0xC10E0002</faultcode>
<faultstring>Either the user, DOMAIN\\reader, does not have access to the
AWTabular database, or the database does not exist.</faultstring>
</Fault></Body></Envelope>"""
