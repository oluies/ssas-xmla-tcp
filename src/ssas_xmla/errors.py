"""The failure categories a caller can act on.

These are distinct types rather than one error with a code because they demand
different operator actions: a connection failure means check the network, an
authentication failure means check the ticket, an authorization failure means
check permissions. Collapsing them would force callers to parse message text.
"""
from __future__ import annotations


class SsasError(Exception):
    """Base for every error this library raises.

    `detail` carries the server's own explanation where one exists. It is scrubbed
    before it gets here — see redact.make_scrubber.
    """

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message if not detail else f"{message}: {detail}")
        self.message = message
        self.detail = detail


class ConnectionError(SsasError):  # noqa: A001 - deliberate: mirrors the failure category
    """Never reached a server. Check host, port, firewall."""


class AuthenticationError(SsasError):
    """Reached the server; identity could not be established. Check ticket/keytab."""


class AuthorizationError(SsasError):
    """Identity established; access refused. Check the account's permissions."""


class ServerError(SsasError):
    """The server understood the request and rejected it. Read `detail`."""


class NegotiationError(SsasError):
    """The server declined the message encoding we asked for.

    This is its own category because it is not an ordinary failure: this library
    negotiates clear-text XML so it can skip binary XML and compression entirely.
    A refusal means that assumption is wrong and the project's scope changes, so it
    must surface loudly rather than being retried around (see research.md, D2).
    """


class ProtocolError(SsasError):
    """The bytes on the wire did not match what the specification requires."""
