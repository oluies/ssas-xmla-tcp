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
      sealing.py      per-message seal + the 4-byte frame header
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

### `sealing.py` — the post-authentication frame

Every message after the handshake is sealed and wrapped in a 4-byte header:

    uint16 dataSize | uint16 tokenSize | ciphertext | token

**Ciphertext first, token second** — the inverse of the GSS ordering `pyspnego` emits, and
getting it backwards is silently fatal: the server closes the connection with no error and
logs nothing. [MS-SSAS] does not document this layer; it was recovered by decompiling
`AdomdClient` (`TcpSecureStream.WriteHeader` / `WriteInBlockMode`).

Two details that cost days to rediscover, both now in the module docstring:

- The UTF-8 BOM is sealed as its **own frame** before the body, because the reference client
  writes it through a `StreamWriter` whose preamble is a separate write.
- `RESP_XPRESS` in the DIME OPTIONS byte makes the server return XPRESS-compressed XML, which
  arrives as convincing binary noise rather than an error. The reference client sets it; this
  one must not, having no decompressor.

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

## How messages get split

Three independent splits can apply to one message, each handled at a different layer. They
compose, and a large response hits all three at once — `DBSCHEMA_COLUMNS` on a modest model
returns over 1300 rows, well past every threshold below.

### 1. Sealed-frame chunking — `sealing.py`

A payload longer than `MAX_CHUNK` becomes several sealed frames, each with its own header,
ciphertext and token. `unseal_message` walks them by their declared sizes and concatenates the
plaintext.

`MAX_CHUNK` is 2888, which is the reference client's `cbMaxToken` for NTLM — it reuses that
value as the data chunk size. Nothing forces us to match it: smaller chunks are always valid,
just more frames. The real ceiling is **65535**, because `dataSize` is a `uint16`;
`seal_frame` raises rather than silently truncating past it. For Kerberos the reference client
would use a larger chunk, and 2888 remains safe.

### 2. DIME record chunking — `dime.py`

A message too large for one record is split across several, with **CF** set on all but the
last, **MB** on the first and **ME** on the last. `decode_message_at` reassembles until it
sees `ME`. Per [MS-SSAS] a chunked sequence is contained within one message and never spans
messages, so the boundary is unambiguous.

### 3. TCP fragmentation — `transport.py`

Reads are driven by the header's **declared lengths**, never by the peer going quiet, and the
buffer persists across calls. Two failures here were real bugs rather than hypotheticals:

- Incompleteness was once detected by substring-matching an exception message, so a chunked
  message split at a record boundary — which raises a *different* message — was treated as
  fatal. It is now a distinct `IncompleteMessage` type, meaning "read more", never
  "malformed".
- The reader once consumed its whole buffer per message, silently discarding anything a peer
  packed into the same segment. It now consumes exactly one message and keeps the remainder.

Padding counts too: a record whose declared bytes have arrived but whose 4-byte padding has
not is **incomplete**, not decoded. Treating it as complete left the pad bytes in the stream,
where they were read as the next message's header and surfaced as a bogus
"unsupported DIME version" — a desync disguised as a protocol error.

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

**Working.** Discover, catalog listing and DAX execution all complete against a live SQL
Server 2022 instance over NTLM, on both a tabular and a multidimensional named instance.
