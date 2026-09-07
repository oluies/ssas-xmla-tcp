# Public Interface Contract

The surface a third-party tool builds on (FR-015). Behaviour is normative; names are
indicative and settle during implementation.

## Opening a session

Takes a connection target and a credential; returns an authenticated session or raises one of
the categorised errors. Performs framing negotiation and the security handshake before
returning, so a returned session is always usable.

- Bounded by the target's timeout at every network wait; never blocks indefinitely (FR-009).
- Raises `NegotiationError` if the server declines the requested encoding, rather than
  silently accepting another (FR-012).
- Supports use as a context manager, so a session closes on the way out of a block including
  on error.

## Reading metadata

Takes a request type and optional restrictions; returns a `Rowset`.

- An empty rowset means "nothing visible to this account" and is distinct from
  `AuthorizationError` (FR-007).
- Server-side rejections surface the server's own text (FR-008).

## Executing a query

Takes a read-only analytic query and an optional catalog; returns a `Rowset`.

- **Read-only by construction** (constitution II): there is no parameter, flag or alternate
  entry point through which a mutating command can be issued. The capability is absent, not
  gated.
- A malformed query surfaces the server's explanation rather than a generic failure.

## Closing

Releases the socket and the security context. Idempotent. Closing an already-failed session is
not an error.

## Guarantees

1. **No unbounded waits.** Every network operation is bounded by the session timeout.
2. **Errors are categorised**, per the table in `data-model.md`, so a caller can act on the
   category without parsing message text.
3. **Nothing identifying is emitted.** No credential, security token, host, address, account,
   principal, realm, machine name or security identifier appears in any log line or error
   message, at any level (FR-010, constitution I).
4. **Read-only.** No operation mutates server state.
5. **No platform dependency.** No Windows-only or .NET component is required, anywhere.

## Non-goals for this feature

Port discovery via the redirector; binary XML and compressed encodings; any write, refresh or
administrative operation; connection pooling; async. Each is a separate feature if wanted, not
a quiet extension of this one.
