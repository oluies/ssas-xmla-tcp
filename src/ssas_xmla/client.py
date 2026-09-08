"""Session assembly: the documented surface a caller builds on.

Sequences negotiate -> authenticate -> request, and turns server responses into the
categorised errors of FR-007 so a caller can act on the category without parsing
message text.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum

from . import auth, dime, envelopes, rowset, sealing
from .auth import Credential
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ServerError,
)
from .redact import make_scrubber
from .rowset import Rowset
from .transport import Channel, MessageStream, SocketChannel

DEFAULT_TIMEOUT = 30.0

_SESSION_ID = re.compile(r'SessionId="([^"]+)"')

# Fault codes/messages that mean "you are known but not permitted", as opposed to
# "the request was bad". Keeps AuthorizationError distinct from ServerError.
_DENIED_MARKERS = (
    "does not have access",
    "permission",
    "not authorized",
    "access is denied",
)


def _catalog_kind(row: dict) -> str:
    """Report the model kind only when the server states it.

    COMPATIBILITY_LEVEL does NOT distinguish the two: multidimensional databases
    use 1050/1100/1103, so any MD database created on SQL Server 2012 or later
    reports 1100+ and a ">= 1100 means tabular" rule labels it tabular. That is
    exactly the confident-and-wrong answer this function was written to avoid, so
    the level is not consulted at all.

    Determining the kind reliably needs a probe -- DISCOVER_CSDL_METADATA succeeds
    for tabular and faults for multidimensional -- which is a request, not a field,
    and so belongs to the caller rather than to row parsing.
    """
    kind = (row.get("CATALOG_TYPE") or "").strip().lower()
    if kind in ("tabular", "multidimensional"):
        return kind
    return "unknown"


class State(Enum):
    UNCONNECTED = "unconnected"
    NEGOTIATED = "negotiated"
    AUTHENTICATED = "authenticated"
    CLOSED = "closed"
    FAILED = "failed"


@dataclass(frozen=True)
class Catalog:
    """A model within an instance, as the server reports it.

    `kind` is derived rather than asserted: DBSCHEMA_CATALOGS does not name the
    model type directly, so it is inferred from the rowset and left as "unknown"
    when the server gives nothing to go on. Guessing here would be worse than
    saying so — the caller can still ask the instance directly.
    """

    name: str
    description: str = ""
    kind: str = "unknown"  # "tabular" | "multidimensional" | "unknown"


@dataclass(frozen=True)
class ConnectionTarget:
    """Where to connect. No default port: a default would invite guessing between a
    default instance's well-known port and a named instance's pinned one, and
    guessing wrong presents as a hang."""

    host: str
    port: int
    timeout: float = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("host is required")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be in 1..65535")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive; unbounded waits are not offered")


@dataclass
class NegotiatedTerms:
    """Settled once per session and immutable thereafter."""

    content_type: str = "text/xml"
    request_binary: bool = False
    response_binary: bool = False
    request_compressed: bool = False
    response_compressed: bool = False
    protection: bool = False


@dataclass
class Session:
    """An authenticated conversation with an instance."""

    target: ConnectionTarget
    credential: Credential
    terms: NegotiatedTerms = field(default_factory=NegotiatedTerms)
    state: State = State.UNCONNECTED
    _stream: MessageStream | None = field(default=None, repr=False)
    _scrub: object = field(default=None, repr=False)
    _first_record: bool = field(default=True, repr=False)
    _session_id: str | None = field(default=None, repr=False)
    _context: object = field(default=None, repr=False)

    # -- lifecycle ------------------------------------------------------------
    def open(
        self,
        channel: Channel | None = None,
        context=None,
        password: str | None = None,
    ) -> Session:
        """Connect, negotiate and authenticate. A returned session is usable."""
        self._scrub = make_scrubber(
            host=self.target.host,
            user=self.credential.principal,
        )
        try:
            chan = channel or SocketChannel(self.target.host, self.target.port, self.target.timeout)
            self._stream = MessageStream(chan)
            self.state = State.NEGOTIATED
            ctx = context or auth.build_context(self.credential, self.target.host, password)
            auth.handshake(ctx, self._send_authenticate)
            # Everything after the handshake is sealed with this context. The
            # server enforces it: an unsealed message is dropped with no error
            # and nothing in its log.
            self._context = ctx
            self.terms.protection = True
            self.state = State.AUTHENTICATED
            return self
        except Exception:
            self.state = State.FAILED
            raise

    def close(self) -> None:
        """Idempotent. Closing an already-failed session is not an error."""
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        self.state = State.CLOSED

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- requests -------------------------------------------------------------
    def discover(
        self,
        request_type: str,
        restrictions: Mapping[str, str] | None = None,
        catalog: str | None = None,
    ) -> Rowset:
        """Issue a metadata request and return its rows."""
        self._require_authenticated()
        payload = envelopes.discover(
            request_type, restrictions, catalog, session_id=self._session_id
        )
        return self._roundtrip_rowset(payload)

    def discover_datasources(self) -> Rowset:
        """The reader-accessible probe this milestone exists to prove."""
        return self.discover("DISCOVER_DATASOURCES")

    def catalogs(self) -> list[Catalog]:
        """Every catalog this account may see.

        An empty list means "none visible to this account" and is a valid answer,
        distinct from AuthorizationError (FR-007) — a server that refuses raises,
        a server with nothing to show returns nothing.
        """
        rows = self.discover("DBSCHEMA_CATALOGS")
        return [
            Catalog(
                name=row.get("CATALOG_NAME", ""),
                description=row.get("DESCRIPTION", ""),
                kind=_catalog_kind(row),
            )
            for row in rows
            if row.get("CATALOG_NAME")
        ]

    def tables(self, catalog: str) -> Rowset:
        """The tables or cube-equivalents in one catalog."""
        return self.discover("DBSCHEMA_TABLES", catalog=catalog)

    def columns(self, catalog: str) -> Rowset:
        """The columns of every table in one catalog, with their types."""
        return self.discover("DBSCHEMA_COLUMNS", catalog=catalog)

    def execute(self, statement: str, catalog: str | None = None) -> Rowset:
        """Run a read-only analytic statement.

        Read-only by construction: envelopes has no builder for a mutating command,
        so no argument here can reach one.
        """
        self._require_authenticated()
        return self._roundtrip_rowset(
            envelopes.execute(statement, catalog, session_id=self._session_id)
        )

    # -- internals ------------------------------------------------------------
    def _require_authenticated(self) -> None:
        if self.state is not State.AUTHENTICATED:
            raise AuthenticationError(f"session is {self.state.value}, not authenticated")

    def _send_authenticate(self, token_b64: str) -> str:
        assert self._stream is not None
        # NEGO stays clear on the very first record and is set on every later one.
        options = dime.OPTIONS_CLEAR_TEXT if self._first_record else dime.OPTIONS_NEGOTIATED
        self._first_record = False
        self._stream.send_message(sealing.BOM + envelopes.authenticate(token_b64), options)
        text = self._stream.receive_message().decode("utf-8", errors="replace")
        # Every authenticate response is fault-checked, including the terminal one.
        # For NTLM the client context completes the moment it emits its last token,
        # so the handshake loop returns without looking at the reply -- a "Logon
        # failure" there would otherwise be dropped, the session would reach
        # AUTHENTICATED, and the error would resurface mis-attributed to whatever
        # request ran next.
        self._raise_for_fault(text, during_authentication=True)
        return text

    def _roundtrip_rowset(self, payload: bytes) -> Rowset:
        assert self._stream is not None
        if self._context is None:
            raise AuthenticationError("no security context; the session is not open")
        self._stream.send_message(
            sealing.seal_message(self._context, payload), dime.OPTIONS_NEGOTIATED
        )
        raw = self._stream.receive_message()
        text = sealing.unseal_message(self._context, raw).decode("utf-8", errors="replace")
        self._capture_session_id(text)
        self._raise_for_fault(text)
        return rowset.parse(text)

    def _capture_session_id(self, text: str) -> None:
        """Remember the SessionId the server hands back to BeginSession.

        [MS-SSAS] "Initialization for Non-HTTP Transport": every request after the
        first MUST carry it. Without this the client re-sent BeginSession forever
        and opened a new server-side session per request.
        """
        if self._session_id is not None:
            return
        found = _SESSION_ID.search(text)
        if found:
            self._session_id = found.group(1)

    def _raise_for_fault(self, text: str, during_authentication: bool = False) -> None:
        code, message = rowset.find_fault(text)
        if code is None and message is None:
            return
        scrub = self._scrub or (lambda s: s)
        detail = scrub(message or code or "")[:300]
        lowered = (message or "").lower()
        if any(marker in lowered for marker in _DENIED_MARKERS):
            raise AuthorizationError("the account was refused access", detail)
        if during_authentication:
            # A fault during the handshake is an identity problem, not a bad
            # request -- keeping it in the right FR-007 category is the whole
            # point of having separate categories.
            raise AuthenticationError("authentication was refused", detail)
        raise ServerError("the server rejected the request", detail)


def connect(
    host: str,
    port: int,
    credential: Credential | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    channel: Channel | None = None,
    context=None,
    password: str | None = None,
) -> Session:
    """Open an authenticated session. Raises one of the categorised errors.

    `password` is only for a standalone server, where NTLM has no ambient identity.
    It reaches the security layer directly and is never held on the session.
    """
    target = ConnectionTarget(host=host, port=port, timeout=timeout)
    session = Session(target=target, credential=credential or Credential())
    return session.open(channel=channel, context=context, password=password)
