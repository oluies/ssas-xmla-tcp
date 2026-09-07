"""SOAP envelopes for the three operations [MS-SSAS] defines.

Authenticate, Discover and Execute — the same three the HTTP binding uses, which
is why the envelopes and all response parsing are shared between bindings and only
the framing below them differs.

Read-only by construction (constitution II): there is no builder here for Create,
Alter, Delete or Refresh, and no parameter through which a statement could become
one. The capability is absent, not gated.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
XMLA_NS = "urn:schemas-microsoft-com:xml-analysis"

_AUTHENTICATE = (
    '<Envelope xmlns="{soap}"><Body>'
    '<Authenticate xmlns="{xmla}"><SspiHandshake>{token}</SspiHandshake></Authenticate>'
    "</Body></Envelope>"
)

_DISCOVER = (
    '<Envelope xmlns="{soap}"><Body><Discover xmlns="{xmla}">'
    "<RequestType>{rtype}</RequestType>"
    "<Restrictions><RestrictionList>{restr}</RestrictionList></Restrictions>"
    "<Properties><PropertyList>{props}</PropertyList></Properties>"
    "</Discover></Body></Envelope>"
)

_EXECUTE = (
    '<Envelope xmlns="{soap}"><Body><Execute xmlns="{xmla}">'
    "<Command><Statement>{stmt}</Statement></Command>"
    "<Properties><PropertyList>{props}</PropertyList></Properties>"
    "</Execute></Body></Envelope>"
)


def _properties(catalog: str | None) -> str:
    return f"<Catalog>{escape(catalog)}</Catalog>" if catalog else ""


def authenticate(token_b64: str) -> bytes:
    """Carry one GSS-API security token to the server.

    [MS-SSAS] Authentication and Encryption: the tokens ride inside SOAP, and the
    exchange repeats until GSS-API reports completion or error.
    """
    return _AUTHENTICATE.format(soap=SOAP_NS, xmla=XMLA_NS, token=token_b64).encode("utf-8")


def discover(
    request_type: str,
    restrictions: str = "",
    catalog: str | None = None,
) -> bytes:
    return _DISCOVER.format(
        soap=SOAP_NS,
        xmla=XMLA_NS,
        rtype=escape(request_type),
        restr=restrictions,
        props=_properties(catalog),
    ).encode("utf-8")


def execute(statement: str, catalog: str | None = None) -> bytes:
    return _EXECUTE.format(
        soap=SOAP_NS,
        xmla=XMLA_NS,
        stmt=escape(statement),
        props=_properties(catalog),
    ).encode("utf-8")
