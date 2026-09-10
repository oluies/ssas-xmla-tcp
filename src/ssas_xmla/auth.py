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

    mechanism: str = "kerberos"  # or "ntlm" or "negotiate"
    principal: str | None = None  # None means the ambient identity
    service: str = "MSOLAPSvc.3"
    instance: str | None = None  # a named instance, if the SPN is registered that way
    use_port: bool = False  # ask for MSOLAPSvc.3/host:port, as ADOMD does on SSPI
    spn: str | None = None  # full override, service class included

    def target(self, host: str, port: int | None = None) -> str:
        """The SPN to request. NTLM ignores it; Kerberos does not.

        **The default is the portless form**, and the port is used only when
        `use_port` is set. That is deliberate, and it is a departure from the
        reference client.

        ADOMD's `CalculateNTAuthenticationSPN` calls `DsMakeSpn` *with* the port,
        producing ``MSOLAPSvc.3/<server>:<port>`` (or ``:<instance>`` for a named
        instance). But that justifies the string only on **SSPI**, where the SPN is
        used as written. This library's audience is Linux, where `pyspnego` takes
        the GSSAPI path: it builds ``service@hostname`` and imports it as
        ``gssapi.NameType.hostbased_service`` (`spnego/_gss.py`), so the host half
        goes through krb5 canonicalization *and realm determination*. Handing it
        ``server.example:2383`` leaves the trailing component ``example:2383``,
        which no ``[domain_realm]`` mapping or uppercase-domain heuristic can
        resolve -- so the port form is likely to request a ticket in the wrong
        realm on exactly the platform this library exists for.

        Neither form has been tested against a KDC. Given that, the default stays
        the shape that shipped and that GSSAPI expects, and the reference client's
        forms are available explicitly: `use_port=True`, `instance=`, or a full
        `spn=` override.
        """
        if self.spn:
            return self.spn
        if self.instance:
            return f"{self.service}/{host}:{self.instance}"
        if self.use_port and port is not None:
            return f"{self.service}/{host}:{port}"
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


def build_context(
    credential: Credential,
    host: str,
    password: str | None = None,
    port: int | None = None,
) -> SecurityContext:
    """Create a real SPNEGO context. Imported lazily so parser tests need no pyspnego.

    `password` is for the standalone (non-domain) case, where NTLM has no ambient
    identity to draw on. It is handed straight to the security layer and is never
    stored on Credential — that is what keeps repr() and any log line safe.
    """
    try:
        import spnego  # ty: ignore[unresolved-import]
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise AuthenticationError(
            "pyspnego is required for authentication: pip install pyspnego"
        ) from exc

    mechanism = credential.mechanism.lower()
    # Reject rather than silently coerce. Credential is public API and the
    # integration config feeds it straight from $SSAS_MECHANISM, so a typo used to
    # become NTLM without a word -- authenticating with a mechanism the caller did
    # not ask for.
    if mechanism not in ("kerberos", "negotiate", "ntlm"):
        raise AuthenticationError(
            f"unknown authMechanism {credential.mechanism!r}; expected kerberos, negotiate or ntlm"
        )
    protocol = "ntlm" if mechanism == "ntlm" else mechanism
    # BOTH halves are taken from target(), not just the host. spnego recomposes the
    # SPN as f"{service}/{hostname}" (`spnego/_context.py`), so passing
    # `service=credential.service` while overriding only the host silently discarded
    # the service class of a full `spn=` override -- the main reason a site sets one.
    # BOTH halves are validated, and the message reports the composed TARGET rather
    # than credential.spn. Checking only the host half left the mirror image of the
    # bug this validation exists for: `spn="/host.example"` partitions to an EMPTY
    # service, and spnego substitutes its own default --
    # `"%s/%s" % (service if service else "HOST", ...)` in spnego/_context.py -- so
    # the caller silently gets `HOST/host.example`, the same silent service-class
    # substitution from the other end. A slash inside `service` splits in the wrong
    # place for the same reason. And naming credential.spn misreported a target that
    # came from `host` rather than from an override: "got None".
    target = credential.target(host, port)
    service_part, separator, host_part = target.partition("/")
    if not separator or not service_part or not host_part or "/" in host_part:
        raise AuthenticationError(
            f"the SPN must be <service>/<host>, both halves non-empty and no "
            f"further '/'; composed {target!r}"
        )
    try:
        return spnego.client(
            username=credential.principal,
            password=password,
            hostname=host_part,
            service=service_part,
            protocol=protocol,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AuthenticationError(f"could not initialise a {protocol} security context") from exc


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
            raise AuthenticationError("security context produced no token and did not complete")
        response = send_authenticate(base64.b64encode(out_token).decode("ascii"))
        if context.complete:
            return
        encoded = extract_token(response)
        in_token = base64.b64decode(encoded) if encoded else None
    raise AuthenticationError(f"handshake did not complete within {max_rounds} rounds")
