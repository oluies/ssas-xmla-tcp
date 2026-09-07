"""Remove identifying tokens from anything that could reach a log or an exception.

Constitution principle I binds harder here than in a text protocol: this library
handles GSS/SPNEGO tokens, which carry the principal, the realm and the target
service. Nothing built from those may be logged, and no message body reaches a
caller un-scrubbed.
"""
from __future__ import annotations

import re
from collections.abc import Callable

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_SID = re.compile(r"\bS-1-(?:\d+-)+\d+\b")
_NETBIOS = re.compile(r"\bWIN-[A-Z0-9]{6,}\b")
# Kerberos principals and SPNs: user@REALM, HTTP/host.domain, MSOLAPSvc.3/host
_PRINCIPAL = re.compile(r"\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SPN = re.compile(r"\b[A-Za-z0-9]+(?:\.[0-9]+)?/[A-Za-z0-9._-]+\b")
_CONN = re.compile(
    r"(?i)(Data Source|Provider|Initial Catalog|User ID|Password|Server)=[^;<\"]*"
)


def make_scrubber(
    host: str | None = None,
    user: str | None = None,
    realm: str | None = None,
) -> Callable[[str], str]:
    """Return a function that removes identifying tokens from text.

    Literal host/user/realm are removed first because they are the tokens we know;
    the patterns then catch the shapes we do not know in advance.
    """
    literals: list[tuple[re.Pattern[str], str]] = []
    for token, label in ((host, "HOST"), (user, "USER"), (realm, "REALM")):
        if token:
            bare = re.sub(r"^\w+://", "", token).strip("/").split("/", 1)[0]
            literals.append((re.compile(re.escape(bare), re.I), f"<{label}>"))
            if bare != token:
                literals.append((re.compile(re.escape(token), re.I), f"<{label}>"))

    def scrub(text: str) -> str:
        if not text:
            return text
        for pattern, replacement in literals:
            text = pattern.sub(replacement, text)
        text = _CONN.sub(r"\1=<REDACTED>", text)
        text = _SID.sub("<SID>", text)
        text = _NETBIOS.sub("<HOST>", text)
        text = _PRINCIPAL.sub("<PRINCIPAL>", text)
        text = _SPN.sub("<SPN>", text)
        text = _IPV4.sub("<IP>", text)
        return text

    return scrub
