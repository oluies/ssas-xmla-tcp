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
# Authenticate lives in a DIFFERENT namespace from Discover/Execute. Confirmed
# against the worked example in [MS-SSAS] "Authentication", and confirmed the hard
# way by a live server: sending Authenticate under the XMLA namespace is rejected
# with "The Authenticate element ... cannot appear under Envelope/Body".
EXT_NS = "http://schemas.microsoft.com/analysisservices/2003/ext"

_AUTHENTICATE = (
    '<Envelope xmlns="{soap}"><Body>'
    '<Authenticate xmlns="{ext}"><SspiHandshake>{token}</SspiHandshake></Authenticate>'
    "</Body></Envelope>"
)

# [MS-SSAS] "Initialization for Non-HTTP Transport": to begin the session the client
# adds a BeginSession SOAP header, and the server returns a SessionId that every
# later request MUST carry. Required by the specification; confirmed NOT sufficient
# on its own to get a post-handshake Discover accepted (see docs/discovery-brief.md).
_BEGIN_SESSION = '<Header><BeginSession xmlns="{xmla}" mustUnderstand="1"/></Header>'
_SESSION = '<Header><Session xmlns="{xmla}" mustUnderstand="1" SessionId="{sid}"/></Header>'

_DISCOVER = (
    '<Envelope xmlns="{soap}">{header}<Body><Discover xmlns="{xmla}">'
    "<RequestType>{rtype}</RequestType>"
    "<Restrictions><RestrictionList>{restr}</RestrictionList></Restrictions>"
    "<Properties><PropertyList>{props}</PropertyList></Properties>"
    "</Discover></Body></Envelope>"
)

_EXECUTE = (
    '<Envelope xmlns="{soap}">{header}<Body><Execute xmlns="{xmla}">'
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
    return _AUTHENTICATE.format(soap=SOAP_NS, ext=EXT_NS, token=token_b64).encode("utf-8")


def session_header(session_id: str | None) -> str:
    """BeginSession on the first request, Session with the id on every later one."""
    if session_id:
        return _SESSION.format(xmla=XMLA_NS, sid=escape(session_id))
    return _BEGIN_SESSION.format(xmla=XMLA_NS)


def discover(
    request_type: str,
    restrictions: str = "",
    catalog: str | None = None,
    session_id: str | None = None,
) -> bytes:
    return _DISCOVER.format(
        soap=SOAP_NS,
        xmla=XMLA_NS,
        header=session_header(session_id),
        rtype=escape(request_type),
        restr=restrictions,
        props=_properties(catalog),
    ).encode("utf-8")


def execute(statement: str, catalog: str | None = None, session_id: str | None = None) -> bytes:
    return _EXECUTE.format(
        soap=SOAP_NS,
        xmla=XMLA_NS,
        header=session_header(session_id),
        stmt=escape(statement),
        props=_properties(catalog),
    ).encode("utf-8")
