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
