# Architecture

A pure-Python client for the SQL Server Analysis Services **native XMLA/TCP binding**.

The whole design follows from one constraint: everything must be implementable from the
Microsoft Open Specifications and testable without a server. Where those two pull against
each other — a binary protocol is not obviously testable offline — the seam described under
[Testability](#testability-the-byte-seam) is how they are reconciled.

## Why this exists

SSAS speaks XMLA over two bindings: HTTP through the `msmdpump` ISAPI extension hosted in
IIS, and a native TCP binding. Every existing client for the native one is Windows-only —
ADOMD.NET and the MSOLAP OLE DB provider are COM/.NET, `pyadomd` wraps ADOMD.NET through the
CLR, and DuckDB's `msolap` extension states "Windows-only support due to COM dependencies".
The `xmla` Python package speaks XMLA but only over HTTP, which is what forces the IIS
deployment in the first place.

So a Linux consumer that wants SSAS metadata must stand up IIS in front of every instance.
This library removes that requirement.

## The layers

Strictly bottom-up: no lower layer imports a higher one.

```
        client.py     session lifecycle, request/response, error categories
            |
         auth.py      GSS-API/SPNEGO handshake carried inside SOAP
            |
      transport.py    socket lifecycle, timeouts, message reassembly
            |
         dime.py      DIME record framing and content-type negotiation
            |
          socket
```

`envelopes.py` (SOAP construction), `rowset.py` (response parsing), `redact.py` (scrubbing)
and `errors.py` (the failure categories) are used across layers and depend on nothing but the
standard library.

### `dime.py` — framing

[MS-SSAS] requires Direct Internet Message Encapsulation on TCP. A record is a 12-byte header
— 5-bit VERSION pinned to 1, the MB/ME/CF/TYPE_T flags, then OPTIONS/ID/TYPE/DATA lengths —
followed by those four fields, **each padded separately to a 4-byte boundary**. The declared
lengths exclude their own padding, which is the detail that makes a naive reader desync: a
record whose payload has arrived but whose padding has not is *incomplete*, not decoded.

Content type is negotiated through the first OPTIONS byte. Binary XML ([MS-BINXML]) and
XPRESS compression are optional, so this client requests neither and implements neither. That
single decision is what keeps the library small.

### `transport.py` — reassembly

Framing is not message boundaries. A peer may split one message across several reads, or pack
several messages into one segment. The reader is therefore driven by the header's declared
lengths, keeps a buffer across calls, and consumes exactly one message at a time.

Incompleteness is signalled by an `IncompleteMessage` exception type, never by inspecting an
error message. Detecting "need more bytes" by substring-matching was a real defect: a chunked
message split at a record boundary raises a different message and was treated as fatal.

### `auth.py` — the handshake

[MS-SSAS] carries GSS-API security tokens **inside SOAP**: `Authenticate` out,
`AuthenticateResponse` back, repeating until the mechanism reports completion. One loop serves
Kerberos and NTLM because the specification's exchange is mechanism-agnostic, and `pyspnego`
presents that same shape.

`Authenticate` uses a **different namespace** from Discover and Execute —
`http://schemas.microsoft.com/analysisservices/2003/ext`, not the XMLA namespace. A live
server rejects the wrong one outright.

Every authenticate response is fault-checked, including the terminal one. For NTLM the client
context completes as it emits its last token, so a handshake that returns without inspecting
that reply silently drops a "Logon failure" and reports success.

### `client.py` — session and errors

Sequences negotiate → authenticate → request, captures the `SessionId` the server returns to
`BeginSession` and carries it on every later request, and maps faults onto five categories a
caller can act on without parsing text: `ConnectionError`, `AuthenticationError`,
`AuthorizationError`, `ServerError`, `NegotiationError`.

`Credential` has **no password field**. Where NTLM needs one on a standalone server it is
passed to the security layer directly and never retained, so no `repr` or log line can leak
it.

## Testability: the byte seam

`transport.Channel` is a protocol with `send`/`recv`/`close`. The default implementation wraps
a real socket; tests supply recorded bytes. Everything above the socket is therefore ordinary
unit-testable code, and the suite runs with sockets disabled — no stub server to keep in sync,
no live instance required.

Handshake fixtures are **synthesized, never captured**. A real GSS/SPNEGO token carries the
principal, the realm, the target service and often the machine name; a committed capture would
be a disclosure that merely looks like an opaque blob, and no scrubber can reliably redact
arbitrary token structure. Captures of *post*-authentication traffic are permitted and are
scrubbed.

## Constraints that shape the code

- **Read-only by construction.** No operation that creates, alters, refreshes or deletes a
  server-side object exists in the package. A test asserts the absence structurally, so the
  capability cannot arrive unnoticed.
- **One runtime dependency.** `pyspnego`, plus the standard library. A CI job asserts the
  declared set rather than merely that an install succeeds.
- **Nothing identifying is emitted.** Scrubbing is anchored to real service-principal classes
  rather than a generic `word/word` shape — a generic pattern destroyed the very diagnostics
  it was meant to preserve, turning `text/xml` and `Envelope/Body` into `<SPN>`.
- **No unbounded waits.** Every network operation is bounded by the session timeout; there is
  no option to disable it.

## Addressing

Instances are addressed by host and a **pinned port**. The named-instance redirector on TCP
2382 is not used: its wire format has no public specification, and it was verified empirically
not to speak the [MC-SQLR] framing that resolves database-engine instances on UDP 1434. A
firewall rule is needed either way, so pinning the port in `msmdsrv.ini` costs the operator
nothing.

## Current status

The framing, negotiation and authentication layers are confirmed working against a live
instance. Post-authentication messages are **GSS-sealed**, and reproducing that sealing is the
remaining blocker — see `docs/discovery-brief.md`, which records what has been measured, what
has been ruled out, and what to try next.
