# Open questions — the post-authentication framing

A research brief for an agent picking this up cold. **Read `docs/discovery-brief.md` first**;
this lists only what is still unknown, and states what is already settled so none of it gets
re-derived.

## The one blocker, stated precisely

Framing, content-type negotiation and the GSS-API/SPNEGO handshake all work against a live
instance. The handshake completes. The very next message — a `Discover` — makes the server
reset the connection, every time, with no entry in `msmdsrv.log`.

A real ADOMD.NET client's first post-handshake message looks like this (two independent
captures agree):

    offset  0  1  2  3 | 4  5  6   | 7 .................. 22          | 23 ...
            03 00 10 00 | 3 varying | NTLM signature: version(4),      | ciphertext
                        |  bytes    | checksum(8), seqnum(4) = 1       |

**Settled — do not re-investigate:**

- Sealing is correct. Our `pyspnego.wrap_winrm()` signature is structurally identical to the
  real client's: 16 bytes, version `01 00 00 00`, 8-byte checksum, 4-byte sequence number.
  **The problem is the wrapper, not the cryptography.**
- Confidentiality flags were never missing: `spnego.client`'s default `context_req` is 62,
  which already includes `confidentiality` and `integrity`.
- Clear-text `text/xml` is accepted for the handshake. The DIME `TYPE` field stays `text/xml`
  even once the payload is ciphertext, which is what made this hard to see.
- `Authenticate` uses `http://schemas.microsoft.com/analysisservices/2003/ext`, not the XMLA
  namespace.
- The `BeginSession` SOAP header is required by the spec and is implemented, but is not
  sufficient on its own.
- Nine framing permutations have been tried and all reset. **Do not try a tenth by guessing.**

**Still unknown:**

1. What are bytes 4–6? Three is not a natural width for a length or a flag field, which
   suggests the whole leading region is being read wrongly rather than one field being absent.
2. What sequence number should the first post-handshake message carry, and what advances the
   counter during the SSAS handshake? Ours starts at 0; the real client's is 1. Advancing ours
   with a throwaway wrap was necessary but not sufficient.

---

## Questions, ordered by expected value

### A. Decompile ADOMD.NET — by far the highest-value line

`Microsoft.AnalysisServices.AdomdClient.dll` is **managed .NET**, present on the test box at
`C:\Program Files\Microsoft.NET\ADOMD.NET\160\`. Its framing logic is directly readable with
ILSpy, dnSpy or `ikdasm`. This beats any further inference from the specification.

1. What writes the bytes between the DIME payload start and the SSPI signature? Look for the
   type that calls `EncryptMessage`/`SspiEncrypt` and whatever composes its output buffers.
2. Is `03 00 10 00` a serialized `SecBufferDesc` (`ulVersion`, `cBuffers`), or a private
   header? What are the field widths?
3. What are bytes 4–6 — padding, a partial length, a buffer-type tag, or the tail of a
   differently-aligned field?
4. What sequence number does it use for the first sealed message, and where does it advance?
5. Does it seal *every* post-handshake message, or only some?

### B. The specification's remaining corners

6. Does **[MS-SSAS] Appendix A (Product Behavior)** describe the sealed-message layout? It is
   the one documentary source not yet consulted, and the TCP section's footnotes point into it.
7. Is there an [MS-SSAS] section on message processing or sequencing rules for the TCP binding
   covering post-authentication messages specifically?
8. Does any *other* Microsoft protocol document the same wrapper? The shape resembles a
   serialized SSPI buffer list; [MS-RPCE]'s `sec_trailer` and WinRM's
   `HTTP-SPNEGO-session-encrypted` encoding are the obvious comparisons.

### C. Get the plaintext instead of inferring it

9. Can a real ADOMD.NET session be captured **together with its session key**, so its
   ciphertext can be decrypted and the wrapper read directly? A small .NET or PowerShell
   harness on the box that both talks to the instance and exposes the negotiated key would
   settle bytes 4–6 outright.
10. Can SSAS itself be made to log the raw request — Extended Events, the flight recorder, or
    SQL Server Profiler against Analysis Services?
11. Does ADOMD.NET have a trace or diagnostic switch that dumps pre-encryption bytes?

### D. Prior art not yet checked

12. Has anyone implemented this binding outside the Microsoft stack — Mono's Analysis Services
    work, `olap4j`, a Java XMLA client, or an old SSAS TCP dissector?
13. Is there a Wireshark dissector for the Analysis Services protocol, and if so what does it
    call the region at offsets 0–6?

### E. Cheap experiments, only after A–C narrow it

14. If bytes 4–6 turn out to be ignorable padding, does `03 00 10 00` + three zero bytes +
    signature + ciphertext work once the sequence number is also right? (Tried with seqnum 0
    and with one burn; both reset. Worth one retry with the *correct* seqnum once known.)
15. Is sealing mandatory, or merely what the real client chooses? Does the server accept an
    unsealed message if the handshake requests no confidentiality at all?

---

## What "done" looks like

`python -m ssas_xmla.probe --host <host> --port <pinned>` prints the instance's data sources.
That unblocks T029/T030/T031 and the whole US2/US3 branch of the task list.

## Test environment

A live SQL Server 2022 host with two **named** Analysis Services instances (`TAB` and `MD`),
both pinned to static ports, plus the `msmdpump` HTTP endpoints for comparison — the HTTP path
already works end to end and is a useful control. Access details live in the operator's
gitignored `.env`, never in this repository.
