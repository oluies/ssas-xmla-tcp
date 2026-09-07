# Discovery brief — pure-Python SSAS XMLA over TCP

Captured 2026-09-07. Everything below is sourced from Microsoft Open Specifications or a
verified survey of existing tools. Where a fact could not be confirmed it is marked
**UNVERIFIED** and MUST be settled empirically before it is designed against.

## Why this exists

SQL Server Analysis Services speaks XMLA over two bindings: HTTP (through the `msmdpump`
ISAPI extension hosted in IIS) and a native TCP binding. Every non-Windows client today is
forced onto the HTTP binding, because no client outside the Windows/COM/.NET stack
implements the TCP one.

That forces an IIS deployment in front of every SSAS instance that a Linux consumer needs to
read — an extra host, an extra auth surface, and in practice a blocker when IIS is not
available on the SSAS box.

## Landscape survey — nothing implements this

| Tool | Transport | Verdict |
|---|---|---|
| `xmla` (may-day/olap) | HTTP/SOAP only; its docs target `msmdpump.dll`, auth via `HTTPKerberosAuth` | Does not speak TCP |
| `pyadomd` | Wraps ADOMD.NET through the .NET CLR | Windows/.NET |
| DuckDB `msolap` extension | Requires the MSOLAP.8 OLE DB provider; "Windows-only support due to COM dependencies" | Windows/COM |
| ADOMD.NET / MSOLAP provider | Native, Microsoft-supplied | Windows/.NET |

No DuckDB extension and no Python library speaks the native TCP binding. This would be the
first.

## Reusable building blocks

- **Kaitai Struct** publishes a formal DIME message spec that generates a Python parser.
- **`python-dime`** (jwilk-archive) exists on PyPI — likely stale, useful as a reference.
- **`pyspnego`** covers GSS-API/SPNEGO token generation for both Kerberos and NTLM.

## What the specification pins down

### Framing — [MS-SSAS] TCP

Messages MUST be composed using Direct Internet Message Encapsulation (DIME). A DIME message
is one or more records; the record layout is fully specified:

- `VERSION` (5 bits) MUST be 1
- `MB` / `ME` — first / last record of a message
- `CF` — set on every chunked record except the last; a chunked sequence MUST be contained
  within one DIME message and MUST NOT span messages
- `TYPE_T` (4 bits) — 1 for the record beginning a message, 0 for consecutive records
- `OPTIONS_LENGTH` (16) / `ID_LENGTH` (16) / `TYPE_LENGTH` (16) / `DATA_LENGTH` (32),
  each field padded to a 4-byte boundary

### Content type negotiation — the fact that makes this tractable

Binary XML and compression are OPTIONAL, and the content type MUST be negotiated for the
duration of the connection through the first byte of `OPTIONS`:

| Bit | Meaning |
|---|---|
| `NEGO` | negotiation complete |
| `REQ_SX` | client request is binary XML |
| `REQ_XPRESS` | client request is compressed |
| `RESP_SX` | server response is binary XML |
| `RESP_XPRESS` | server response is compressed |

| TYPE_LENGTH | TYPE | Content |
|---|---|---|
| 8 | `text/xml` | clear text XML |
| 14 | `application/sx` | binary XML |
| 22 | `application/xml+xpress` | compressed XML |
| 21 | `application/sx+xpress` | compressed binary XML |

A client MAY therefore negotiate `text/xml` and skip [MS-BINXML] and XPRESS entirely.

**UNVERIFIED / RISK:** the [MS-SSSO] overview states the SSAS protocols "use binary XML
[MS-BINXML]", which is in tension with [MS-SSAS] TCP declaring it optional and negotiated.
[MS-SSAS] is the normative document, but a real server MAY refuse or misbehave on a
`text/xml` negotiation. Settle this in the first spike; if `text/xml` is refused,
[MS-BINXML] moves from out-of-scope to required and the estimate changes materially.

### Authentication — [MS-SSAS] Authentication and Encryption

An authenticated or encrypted TCP connection MUST use GSS-API [RFC4178] (SPNEGO). Security
tokens are carried *inside SOAP*: the client sends `Authenticate` (AuthenticateSoapIn), the
server replies `AuthenticateResponse` (AuthenticateSoapOut), repeating until GSS-API reports
completion or error. Afterwards each side asks GSS-API whether encryption or hashing is on
for the connection. SSPI is the default for TCP, covering NTLM, Kerberos and Anonymous.

**RISK:** if GSS-API negotiates sealing, every subsequent message must be wrapped and
unwrapped. `pyspnego` supports this; it is additional work, not a blocker.

### Operations

`Authenticate`, `Discover` and `Execute` — the same three the HTTP binding uses, so SOAP
envelopes and all response parsing are shared between bindings.

## Named-instance resolution — a real specification gap

A default instance listens on 2383. A named instance is assigned a dynamic port, and the SQL
Server Browser listens on **TCP 2382** to redirect. Note this is TCP, and it is separate from
the database engine's UDP 1434 discovery.

[MS-SSSO] routes named-instance resolution to SSRP [MC-SQLR] — but SSRP "is always
implemented on top of the UDP Transport Protocol [RFC768]". It therefore covers the database
engine on UDP 1434, **not** the Analysis Services redirector on TCP 2382.

**UNVERIFIED:** no public Open Specifications document appears to define the TCP 2382
exchange. Product documentation describes the behaviour but not the wire format.

**Mitigation that removes the risk:** an SSAS named instance can be pinned to a static port
via the `Port` property in `msmdsrv.ini`. A firewall rule is required either way, so pinning
the port costs nothing and lets the client connect directly, with the redirector deferred.
The first milestone SHOULD assume a pinned port and treat 2382 as a later, empirically
derived addition.

## Normative references

- [MS-SSAS] TCP — https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssas/f172a52f-f69e-4051-8b3a-627433e978fb
- [MS-SSAS] Authentication and Encryption — https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssas/be84959b-ec40-4f5a-b18b-b271b0901668
- [MS-SSAS] Transport — https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssas/cc9c04c8-df61-40aa-b9bf-49d06b3ac888
- [MS-SSSO] Analysis Services — https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssso/e8ec30a5-3c27-478b-9921-74e0d4d7f12b
- [MS-SSSO] Named SQL Server Instance Resolution — https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssso/0a4ddedb-9121-4908-b721-ad8f0958f728
- [MC-SQLR] SQL Server Resolution Protocol — https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/1ea6e25f-bff9-4364-ba21-5dc449a601b7
- [MS-BINXML] Binary XML — https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-binxml/
- [DIME] — https://go.microsoft.com/fwlink/?LinkId=89847
- [RFC4178] SPNEGO — https://www.rfc-editor.org/rfc/rfc4178

## Decisions taken at discovery

| Question | Decision |
|---|---|
| Repository | Separate from the OpenMetadata connector — that repo pins `openmetadata-ingestion`, which a protocol library must not drag in |
| Milestone shape | Spike the handshake first, then build toward a general-purpose client library |
| Auth in scope | Kerberos and NTLM. Anonymous is not a target |
| Instance shape | Named instance — so port resolution matters (see the gap above) |


## Live findings, 2026-09-07 (first run against a real instance)

Fixture: SQL Server 2022, two **named** instances `TAB` and `MD`, pinned to ports 2383 and
2384 (`Port` in `msmdsrv.ini`; they were on dynamic ports 49682/49683 before). Authentication
is NTLM with a local reader account — the box is standalone, so there is no domain and no
Kerberos.

**Settled — these are no longer UNVERIFIED:**

- **DIME framing is correct.** The header this client emits is byte-identical to the worked
  example in [MS-SSAS] "Authentication": `0E 10 00 04 00 00 00 08 ...` — VERSION 1, MB/ME set,
  OPTIONS_LENGTH 4, TYPE_LENGTH 8.
- **Clear-text `text/xml` is ACCEPTED.** The server parsed our payload and replied in kind,
  with no binary-XML or compression negotiation. **D2's assumption holds and the milestone's
  scope stands** — [MS-BINXML] and XPRESS remain out of scope. This was the project's largest
  single risk.
- **The GSS/SPNEGO handshake completes.** Two round trips: client token -> server challenge ->
  client response -> `<SspiHandshake/>` empty, context reports complete. Matches the spec's
  worked example exactly.

**Corrected — the spec was right and this client was wrong:**

- `Authenticate` is NOT in the XMLA namespace. It belongs to
  `http://schemas.microsoft.com/analysisservices/2003/ext`, while Discover and Execute use
  `urn:schemas-microsoft-com:xml-analysis`. Sending it under the XMLA namespace is rejected:
  *"The Authenticate element ... cannot appear under Envelope/Body"*.

**STILL OPEN — the remaining blocker:**

- **A Discover issued after a completed handshake resets the connection.** The server accepts
  the authentication, then drops the connection on the next message. Ruled out so far: setting
  the `NEGO` OPTIONS bit on post-handshake messages (as the spec's third example message does),
  and GSS-wrapping the payload with the completed context. Both still reset.

  **Ruled out by experiment** (each on a fresh connection, all reset identically):

  | variant | result |
  |---|---|
  | `BeginSession` SOAP header, per [MS-SSAS] "Initialization for Non-HTTP Transport" | reset |
  | UTF-8 BOM prefix, as the spec's example client messages carry (`EF BB BF`) | reset |
  | `NEGO` OPTIONS bit set on the post-handshake message | reset |
  | `NEGO` clear | reset |
  | payload GSS-wrapped with the completed context | reset |
  | no SOAP header at all | reset |

  The `BeginSession` header IS required by the specification and is now known-correct
  structure, so it should stay in the implementation regardless — it simply is not
  sufficient on its own.

  **What the server says: nothing.** `msmdsrv.log` records the service starting and
  listening on the pinned port, but logs no entry whatsoever for these connections. The
  reset therefore happens below the level SSAS logs, which argues against a permissions or
  XML-validity problem and for a framing/transport-state mismatch after the handshake.

  **Recommended next step, and it is not more guessing:** run a real client against the
  instance *on the box itself* (SSMS, or ADOMD.NET over `localhost:2383`) with a packet
  capture, then diff its post-handshake bytes against ours. Every layer up to and including
  authentication is now confirmed working, so the divergence is in a small, bounded window
  — one capture should show it outright. This is the discovery-driven approach the
  constitution requires (principle IV): record what the wire actually carries rather than
  inferring further from the specification.


## TCP 2382 redirector — tested, still undocumented (2026-09-07)

[MC-SQLR] specifies named-instance resolution over **UDP 1434** for the database engine:

    request : 0x04 | InstanceName (MBCS) | 0x00        (CLNT_UCAST_INST)
    response: 0x05 | RespSize (2 bytes)  | RespData    (semicolon-delimited, carries `tcp;`)

The obvious hypothesis was that the SQL Browser speaks the same framing on **TCP 2382** for
Analysis Services. **It does not.** Against a live browser (service running, port open at both
firewalls, TCP connect succeeds), all of these time out with no response at all:

| sent | result |
|---|---|
| `0x04` + `TAB` + NUL (CLNT_UCAST_INST) | no response |
| `0x04` + `MD` + NUL | no response |
| `0x03` (CLNT_UCAST_EX, enumerate) | no response |
| bare instance name, no opcode | no response |

So the earlier conclusion holds, now on evidence rather than on absence of a document: the
TCP 2382 exchange is not publicly specified and is not MC-SQLR over TCP. **D4 stands** — pin
the instance port in `msmdsrv.ini` and address it directly. A firewall rule is needed either
way, so this costs the operator nothing.


## Why the post-handshake Discover was reset — SOLVED (2026-09-07)

Captured a complete, working ADOMD.NET 160 session against the live instance through a
logging TCP relay (ADOMD -> relay -> 2383). The client-to-server records tell the whole story:

| record | TYPE | OPTIONS | payload |
|---|---|---|---|
| 1 | `text/xml` | `0x10` = RESP_XPRESS | plaintext XML `Authenticate` (BOM-prefixed) |
| 2 | `text/xml` | `0x11` = NEGO \| RESP_XPRESS | plaintext XML `Authenticate` |
| 3+ | `text/xml` | `0x11` = NEGO \| RESP_XPRESS | **binary — GSS-sealed, not XML** |

**Every message after the handshake is sealed.** That is why all six of our plaintext variants
were reset: the server was never going to accept cleartext XML post-authentication, no matter
what SOAP header or NEGO bit accompanied it. Our one GSS-wrap attempt was the right instinct
but wrong in detail — it did not set RESP_XPRESS, and the sealed payload carries its own small
framing header (record 3 begins `03 00 10 00` before the ciphertext) that we did not reproduce.

**Two corrections to earlier conclusions:**

- **T031 needs restating.** Clear-text `text/xml` is accepted *for the handshake only*. It is
  NOT the steady-state encoding. The DIME TYPE stays `text/xml` throughout, so the type field
  alone does not tell you whether the payload is plaintext — which is exactly how this misled
  us. [MS-BINXML] is still out of scope (the sealed payload is not binary XML), but "clear text
  works" was too broad a reading.
- **`check_negotiated()` is wrong as written.** The real client sets `RESP_XPRESS` from its
  very first record, so our guard would reject a correct exchange. The bit is a client
  *request*, not a server imposition; only the server's chosen response encoding should be
  enforced.

**Next: implement sealing.** Decode the small pre-ciphertext header on record 3, then wrap
each post-handshake payload with the completed context. The capture is the reference.

**The capture was NOT committed**, and must never be: records 1 and 2 contain real
`SspiHandshake` tokens carrying the principal, realm and machine name. It was deleted from the
server after analysis. This is D6 in practice — the reason synthetic handshake fixtures exist.


### The sealed-message framing — measured, not yet reproduced

Two independent captures of a real ADOMD.NET client agree on the layout of the first sealed
message (record 3). Byte offsets, with the two captures side by side:

    offset  0  1  2  3 | 4  5  6 | 7 .. 22                          | 23 ...
    cap A   03 00 10 00 | 8e 70 87 | 01 00 00 00 <8-byte checksum> 01 00 00 00 | 08 ...
    cap B   03 00 10 00 | 13 2f 2f | 01 00 00 00 <8-byte checksum> 01 00 00 00 | 08 ...

- Bytes 0-3 are **constant**: `03 00 10 00`, reading naturally as uint16(3), uint16(16) where
  16 is the NTLM signature length.
- Bytes 4-6 **vary between captures** — three bytes, not obviously a length or a constant.
- Bytes 7-22 are a textbook NTLM signature: version `01 00 00 00`, 8-byte checksum, seqnum 1.
  `pyspnego.wrap_winrm()` produces a byte-for-byte structurally identical 16-byte header, so
  our signature generation is right; only its placement is not.

**Framings tried live, all reset:** header+sig+data; header+3 zero bytes+sig+data;
sig+data with no header; header+data+sig; header+3-byte length+sig+data.

**The most promising untested lead is not framing at all.** A real client negotiates specific
NTLM flags — `NTLMSSP_NEGOTIATE_SEAL`, `NTLMSSP_NEGOTIATE_KEY_EXCH`, 128-bit — and if
`pyspnego`'s default context does not request confidentiality, the session key material is not
set up for the RC4 sealing the server expects. Every sealed message we send would then be
garbage to it *regardless of framing*, which fits the evidence better than five wrong framings
in a row does. Check `spnego.client(..., options=...)` / `context_req` for confidentiality
before trying more byte layouts.

Both captures were deleted from the server and locally after analysis. They contain real
`SspiHandshake` tokens carrying the principal, realm and machine name, and MUST NOT be
committed (D6).
