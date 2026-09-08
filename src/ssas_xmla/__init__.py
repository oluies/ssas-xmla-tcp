"""Pure-Python client for the Analysis Services native XMLA/TCP binding.

Implemented from the Microsoft Open Specifications, not by inspection of other
clients — see docs/discovery-brief.md for the citations behind each layer.

    from ssas_xmla import Credential, connect

    with connect("host", 2383, Credential(mechanism="kerberos")) as session:
        for catalog in session.catalogs():
            print(catalog.name, catalog.kind)

Guarantees this surface makes (contracts/public-api.md):

1. No unbounded waits. Every network operation is bounded by the session timeout;
   there is no option to disable it.
2. Errors are categorised, so a caller can act on the type without parsing text:
   ConnectionError, AuthenticationError, AuthorizationError, ServerError,
   NegotiationError.
3. Nothing identifying is emitted. No credential, security token, host, address,
   account, principal, realm, machine name or SID reaches a log line or an error.
4. Read-only. No operation mutating server state exists in this package.
5. No platform dependency. No Windows-only or .NET component, anywhere.
"""

from __future__ import annotations

from .auth import Credential
from .client import (
    DEFAULT_TIMEOUT,
    Catalog,
    ConnectionTarget,
    NegotiatedTerms,
    Session,
    State,
    connect,
)
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    NegotiationError,
    ProtocolError,
    ServerError,
    SsasError,
)
from .rowset import Rowset

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_TIMEOUT",
    "AuthenticationError",
    "AuthorizationError",
    "Catalog",
    "ConnectionError",
    "ConnectionTarget",
    "Credential",
    "NegotiatedTerms",
    "NegotiationError",
    "ProtocolError",
    "Rowset",
    "ServerError",
    "Session",
    "SsasError",
    "State",
    "connect",
    "__version__",
]
