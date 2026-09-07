"""The GSS-API / SPNEGO handshake, carried inside Authenticate SOAP messages.

[MS-SSAS] Authentication and Encryption:

  "To use an authenticated or encrypted connection using TCP, both the client and
   server MUST use GSS-API [RFC4178]. ... The client sends its security token using
   the Authenticate request and the server responds with its security token in the
   AuthenticateResponse message. This exchange ... continues back and forth until
   GSS-API reports completion or error."

One loop serves Kerberos and NTLM: the specification describes a mechanism-agnostic
exchange, and pyspnego presents exactly that shape, so NTLM costs nothing extra once
Kerberos works.

Nothing in this module may log a token. A SPNEGO token carries the principal, the
realm and the target service (constitution I).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import AuthenticationError, ProtocolError

_TOKEN = re.compile(r"<SspiHandshake[^>]*>(.*?)</SspiHandshake>", re.S)
_RETURN = re.compile(r"<return[^>]*>(.*?)</return>", re.S)

MAX_ROUNDS = 10  # a handshake needing more than this is a loop, not progress


@dataclass(frozen=True)
class Credential:
    """What the security layer authenticates with.

    Deliberately has no password field. Where NTLM needs one it goes straight to the
    security layer and is not retained here, so no code path can leak a credential
    by logging a Credential.
    """

    mechanism: str = "kerberos"  # or "ntlm"
    principal: str | None = None  # None means the ambient identity
    service: str = "MSOLAPSvc.3"

    def target(self, host: str) -> str:
        return f"{self.service}/{host}"


class SecurityContext(Protocol):
    """The slice of a GSS-API context this module uses. Injected so tests need no
    real credentials, no KDC and no pyspnego at import time."""

    def step(self, in_token: bytes | None = None) -> bytes | None: ...

    @property
    def complete(self) -> bool: ...


def extract_token(response_xml: str) -> str:
    """Pull the server's base64 token out of an AuthenticateResponse."""
    match = _TOKEN.search(response_xml) or _RETURN.search(response_xml)
    if match is None:
        raise ProtocolError("AuthenticateResponse carried no security token")
    return match.group(1).strip()


def build_context(credential: Credential, host: str) -> SecurityContext:
    """Create a real SPNEGO context. Imported lazily so parser tests need no pyspnego."""
    try:
        import spnego  # ty: ignore[unresolved-import]
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise AuthenticationError(
            "pyspnego is required for authentication: pip install pyspnego"
        ) from exc

    protocol = "kerberos" if credential.mechanism.lower() == "kerberos" else "ntlm"
    try:
        return spnego.client(
            username=credential.principal,
            hostname=host,
            service=credential.service,
            protocol=protocol,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AuthenticationError(
            f"could not initialise a {protocol} security context"
        ) from exc


def handshake(
    context: SecurityContext,
    send_authenticate: Any,
    max_rounds: int = MAX_ROUNDS,
) -> None:
    """Run the token exchange to completion.

    `send_authenticate(token_b64) -> response_xml` performs one round trip. The loop
    is driven by the security layer reporting completion, exactly as the spec
    describes, rather than by counting messages.
    """
    in_token: bytes | None = None
    for _ in range(max_rounds):
        try:
            out_token = context.step(in_token)
        except Exception as exc:
            # Never include the exception's text: it can carry principal and realm.
            raise AuthenticationError("security context step failed") from exc
        if context.complete and not out_token:
            return
        if out_token is None:
            raise AuthenticationError(
                "security context produced no token and did not complete"
            )
        response = send_authenticate(base64.b64encode(out_token).decode("ascii"))
        if context.complete:
            return
        encoded = extract_token(response)
        in_token = base64.b64decode(encoded) if encoded else None
    raise AuthenticationError(
        f"handshake did not complete within {max_rounds} rounds"
    )
