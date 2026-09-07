"""Session assembly: the documented surface a caller builds on.

Sequences negotiate -> authenticate -> request, and turns server responses into the
categorised errors of FR-007 so a caller can act on the category without parsing
message text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from . import auth, envelopes, rowset
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

# Fault codes/messages that mean "you are known but not permitted", as opposed to
# "the request was bad". Keeps AuthorizationError distinct from ServerError.
_DENIED_MARKERS = (
    "does not have access",
    "permission",
    "not authorized",
    "access is denied",
)


class State(Enum):
    UNCONNECTED = "unconnected"
    NEGOTIATED = "negotiated"
    AUTHENTICATED = "authenticated"
    CLOSED = "closed"
    FAILED = "failed"


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

    # -- lifecycle ------------------------------------------------------------
    def open(self, channel: Channel | None = None, context=None) -> Session:
        """Connect, negotiate and authenticate. A returned session is usable."""
        self._scrub = make_scrubber(
            host=self.target.host,
            user=self.credential.principal,
        )
        try:
            chan = channel or SocketChannel(
                self.target.host, self.target.port, self.target.timeout
            )
            self._stream = MessageStream(chan)
            self.state = State.NEGOTIATED
            ctx = context or auth.build_context(self.credential, self.target.host)
            auth.handshake(ctx, self._send_authenticate)
            self.terms.protection = bool(getattr(ctx, "protection", False))
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
        self, request_type: str, restrictions: str = "", catalog: str | None = None
    ) -> Rowset:
        """Issue a metadata request and return its rows."""
        self._require_authenticated()
        payload = envelopes.discover(request_type, restrictions, catalog)
        return self._roundtrip_rowset(payload)

    def discover_datasources(self) -> Rowset:
        """The reader-accessible probe this milestone exists to prove."""
        return self.discover("DISCOVER_DATASOURCES")

    def execute(self, statement: str, catalog: str | None = None) -> Rowset:
        """Run a read-only analytic statement.

        Read-only by construction: envelopes has no builder for a mutating command,
        so no argument here can reach one.
        """
        self._require_authenticated()
        return self._roundtrip_rowset(envelopes.execute(statement, catalog))

    # -- internals ------------------------------------------------------------
    def _require_authenticated(self) -> None:
        if self.state is not State.AUTHENTICATED:
            raise AuthenticationError(
                f"session is {self.state.value}, not authenticated"
            )

    def _send_authenticate(self, token_b64: str) -> str:
        assert self._stream is not None
        self._stream.send_message(envelopes.authenticate(token_b64))
        return self._stream.receive_message().decode("utf-8", errors="replace")

    def _roundtrip_rowset(self, payload: bytes) -> Rowset:
        assert self._stream is not None
        self._stream.send_message(payload)
        text = self._stream.receive_message().decode("utf-8", errors="replace")
        self._raise_for_fault(text)
        return rowset.parse(text)

    def _raise_for_fault(self, text: str) -> None:
        code, message = rowset.find_fault(text)
        if code is None and message is None:
            return
        scrub = self._scrub or (lambda s: s)
        detail = scrub(message or code or "")[:300]
        lowered = (message or "").lower()
        if any(marker in lowered for marker in _DENIED_MARKERS):
            raise AuthorizationError("the account was refused access", detail)
        raise ServerError("the server rejected the request", detail)


def connect(
    host: str,
    port: int,
    credential: Credential | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    channel: Channel | None = None,
    context=None,
) -> Session:
    """Open an authenticated session. Raises one of the categorised errors."""
    target = ConnectionTarget(host=host, port=port, timeout=timeout)
    session = Session(target=target, credential=credential or Credential())
    return session.open(channel=channel, context=context)
