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

---

# Answers — 2026-09-08

Written against the questions above without access to the test box, the captures, or
`AdomdClient.dll`. Confidence is stated per item, and every claim that can be checked
against data you already hold says how.

## The 30-second test that should be run before anything else

**The header is probably 8 bytes, not 7 — and if so, question 1 and question 2 are the
same mistake.**

`03 00 10 00` reads naturally as two little-endian `uint16`s: **3** and **16**. Those are
exactly the two constants an `EncryptMessage` call site would serialize first:

- `cBuffers = 3` — the standard SSPI sealing layout is `SECBUFFER_TOKEN`,
  `SECBUFFER_DATA`, `SECBUFFER_PADDING`
- `cbBuffer = 16` for the token — NTLM's `cbSecurityTrailer` is 16, which is precisely the
  signature length you already match byte for byte

If that reading is right, the next field is the **length of the data buffer**, as a
`uint32` at offsets 4–7. Ciphertext under NTLM is the same length as plaintext and is far
below 16 MB, so its top byte is `00` — which is why offsets 4–6 look like "three varying
bytes" and offset 7 looks like the start of something else.

That would put the layout at:

    0..1   uint16  cBuffers = 3
    2..3   uint16  token length = 16
    4..7   uint32  data (ciphertext) length
    8..23  NTLM signature: version(4) 01 00 00 00, checksum(8), seqnum(4)
    24..   ciphertext

**The test.** In any capture you already have:

1. Is `bytes[8:12] == 01 00 00 00`? If yes, the 8-byte header is confirmed and the current
   parse is off by one.
2. Does `uint32_le(bytes[4:8]) == len(message) - 24`? If yes, it is settled outright.

If instead `bytes[7:11] == 01 00 00 00`, this hypothesis is wrong and the region really is
7 bytes — which would be genuinely odd and worth saying so loudly.

### Why this matters more than it looks: the seqnum may be a misread

The brief treats "the real client's sequence number is 1" as an observation. It is an
**inference from the same offset that is in doubt.** If the signature actually starts at 8,
then what was read as `version | checksum | seqnum` is shifted one byte left, and the
"seqnum = 1" being chased is an artifact of the misalignment, not a fact about the protocol.

That would explain the otherwise puzzling result recorded above — *"advancing ours with a
throwaway wrap was necessary but not sufficient"*. Under the 8-byte reading, the first
post-handshake message would carry **seqnum 0**, exactly what pyspnego produces unaided, and
the only real defect is the 4-byte prefix.

**Check `bytes[20:24]` in the capture.** Under the 8-byte layout that is the true seqnum
field.

### And why "burn a throwaway wrap" cannot be the fix regardless

Worth recording so it is not retried. With connection-oriented NTLM and extended session
security, sealing is a **continuous RC4 keystream** across the session, and each message also
consumes 8 bytes of it encrypting the checksum. A discarded `wrap()` therefore advances the
keystream by roughly `len(payload) + 8` bytes, and the server's decryptor — which has seen no
such message — is then permanently desynchronised. A reset is the expected outcome.

The exception is `NTLMSSP_NEGOTIATE_DATAGRAM`, where the key is re-derived per message from
the sequence number and jumping is harmless. **Check the negotiated flags.** If DATAGRAM is
absent (very likely for a stream binding), then a seqnum of 1 could only mean one genuinely
sealed message preceded it, and the useful question becomes *which* — not how to fake the
counter.

## Why `wrap_winrm()` is close but wrong

This also explains why the signature matches while the message is rejected. WinRM's encoding
is:

    uint32 token_length (= 16, i.e. the bytes 10 00 00 00) | signature | ciphertext

The SSAS shape under the hypothesis above is:

    uint16 3 | uint16 16 | uint32 data_length | signature | ciphertext

Both contain the bytes `10 00`, in different positions and different field widths. A
permutation search that treated the prefix as "a length" would never produce
`03 00 | 10 00 | len32`, which may be why nine attempts all failed the same way.

If the test confirms the layout, the change is small — emit that 8-byte prefix yourself
around `spnego`'s raw `wrap()` output rather than using `wrap_winrm()`.

## A — decompiling ADOMD.NET

**Highest value, and I agree it beats further inference.** Concretely, in ILSpy:

- Search the whole assembly for `EncryptMessage` and `DecryptMessage` — the `DllImport`
  declarations pin the interop type, and its callers are the framing code.
- Search for `cbSecurityTrailer` / `QueryContextAttributes` with
  `SECPKG_ATTR_SIZES`. Whatever reads the trailer size is what writes the `10 00`.
- Search for `SecBufferDesc` and `SecBuffer`. If the managed struct is serialized field by
  field, questions 2 and 3 answer themselves from the write order.
- For question 5, look for whether the seal call sits on the single "send a message" path or
  on a branch — one call site means every post-handshake message is sealed.

Note the same logic exists in `Microsoft.AnalysisServices.dll` (AMO) and in the native
`msmdlocal.dll`; the managed ADOMD assembly is the readable one, so start there.

## B — the specification's corners

**6, 7:** Plausible but I cannot confirm the content of Appendix A from here. Worth an hour,
not more — Appendix A is typically behaviour notes keyed to product versions rather than
layout, so treat it as a tiebreaker for something the decompile suggests, not as a primary
source.

**8 — the comparison is the useful part.** The closest documented shapes are:

| Protocol | Shape | Position |
|---|---|---|
| WinRM SPNEGO body | `uint32 token_len | token | ciphertext` | leading |
| [MS-RPCE] `sec_trailer` | 8 bytes: `auth_type, auth_level, pad_len, reserved, context_id(4)` | **trailing** |
| [MS-NNS] NegotiateStream | `uint32 length | payload` | leading |

None matches. That non-match is itself informative: it points away from "a documented
wire format" and toward "a serialized SSPI buffer list", which is what the `3, 16` reading
says it is.

## C — getting the plaintext instead of inferring it

**9 — there is a cheaper route than a key-exposing harness.** If the session negotiates
**NTLM** (not Kerberos) and you know the account's password, **Wireshark can decrypt NTLMSSP
sealed traffic directly** — set the NTLMSSP preference for the account password and it
derives the session key from the captured challenge/response. You then read the wrapper and
the plaintext with no code at all. Force NTLM by connecting to the instance by IP rather than
SPN-resolvable hostname, or by disabling Kerberos for the test account.

That is almost certainly the fastest path to a definitive answer, and it needs nothing on
the box.

**10:** SSAS Extended Events exist and can trace `Discover Begin`/`Command Begin`, but they
sit **above** decryption — a sealed message the server rejects at the transport layer will
never reach them. Their real value here is negative confirmation: if an xEvent fires, the
wrapper was accepted and the problem is elsewhere. Given the brief says the reset leaves no
`msmdsrv.log` entry, expect nothing, which is itself worth knowing.

**11:** I am not aware of a documented ADOMD.NET switch that dumps pre-encryption bytes.
Do not spend long looking; option 9 dominates it.

## D — prior art

**12, 13:** To the best of my knowledge — and this should be verified rather than trusted —
there is **no** public non-Microsoft implementation of the SSAS TCP binding, and no Wireshark
dissector for it. `olap4j`, `XMLA4J` and the Python `xmla` package are all HTTP/SOAP only,
consistent with the survey in the discovery brief. Wireshark dissects DIME generically but
has no Analysis Services dissector that would name the region at offsets 0–6.

If that holds, D is a dead end and the effort belongs in A and C.

### D-bis — prior art you already own: `hugr-lab/mssql-extension`

The survey above looked outward. There is a working SPNEGO/GSS-API implementation in your
own `mssql-extension` repository, and it settles more of the handshake than the brief
assumes — while confirming, by its absence, exactly where the SSAS problem is.

**What is there, and directly portable:**

| file | what transfers |
|---|---|
| `src/include/tds/auth/iauthenticator.hpp` | three-method interface (`InitialBytes` / `NextBytes` / `Free`), modelled on `microsoft/go-mssqldb` — a clean shape to port to Python |
| `src/tds/auth/krb5_authenticator.cpp` (23 KB) | GSSAPI: SPNEGO OID handling, credential modes (ccache / keytab / raw), SPN forms |
| `src/tds/auth/winsspi_authenticator.cpp` | **the same SSPI API ADOMD.NET calls** — `InitializeSecurityContextW`, context handle retained across calls |
| `src/tds/tds_connection.cpp` `AuthenticateIntegrated()` | the SPNEGO continuation loop: feed each server token back until the context completes |
| inline GSSAPI OID DER constants | macOS `GSS.framework` declares `GSS_C_NT_HOSTBASED_SERVICE` etc. but does not export them |

**What is NOT there — and it is precisely this blocker:**

    $ grep -rn "gss_wrap|gss_unwrap|EncryptMessage|DecryptMessage|QueryContextAttributes|cbSecurityTrailer" src/
    (nothing)

**TDS never seals with the security context.** It obtains confidentiality from **TLS**,
negotiated separately during PRELOGIN; the GSS/SSPI context authenticates and is then never
touched again. There is no per-message wrapper, no sequence numbering and no `SecBuffer`
serialization anywhere in that codebase.

That difference is the useful part. TDS and the SSAS TCP binding solve confidentiality in
opposite ways — TDS wraps the whole **stream** in TLS, SSAS seals individual **messages**
with the context. So this prior art cannot tell you the wrapper layout, which is the one
thing still unknown. It does tell you the handshake half is a solved, readable problem, and
narrows the remaining gap to the 4–8 bytes discussed at the top of this reply.

**Three things that do carry over:**

1. `winsspi_authenticator.cpp` keeps the `CtxtHandle` alive across calls. That is the handle
   you would pass to `QueryContextAttributes(SECPKG_ATTR_SIZES)` to read `cbSecurityTrailer`
   — **16 for NTLM**, which is the `10 00` in the header under the hypothesis above. The
   file shows where the handle lives, even though it never asks it for sizes.
2. A flag asymmetry worth knowing, given the settled note that `context_req = 62` already
   includes confidentiality. The Windows leg requests
   `ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY` (`winsspi_authenticator.cpp:210`), but the
   POSIX leg requests `MUTUAL | REPLAY | SEQUENCE | INTEG` with **no `GSS_C_CONF_FLAG`**
   (`krb5_authenticator.cpp:533`). Harmless there because nothing wraps — but do not copy
   the POSIX flag set verbatim, since sealing needs confidentiality on both legs.
3. SPN derivation there is `MSSQLSvc/<fqdn>:<port>`. Analysis Services uses a different
   service class, `MSOLAPSvc.3/<fqdn>` — worth confirming against the test box. A wrong SPN
   class fails during the handshake rather than after it, which is *not* the symptom here,
   so this is a check to rule out rather than a suspect.

`test/kerberos/` in that repo is also a self-contained KDC + server + client docker-compose
stack needing no real Active Directory. The KDC half is reusable if a Kerberos harness is
wanted, though SSAS itself still needs a Windows host.

**Revision to the paragraph above:** D is not entirely a dead end. There is no prior art for
the *TCP binding*, which stands — but there is prior art for the *authentication*, it is
yours, and it is C++ you can read rather than IL you have to decompile.

## E — the cheap experiments

**14:** Do not run this until the test at the top has been run. Under the 8-byte hypothesis
"three zero bytes" is wrong by construction — the field is a 4-byte length and must carry the
actual ciphertext length, not zeros. That single difference may be the whole bug, and it is
not in the permutation space that was searched.

**15 — worth doing early, it is genuinely cheap and diagnostic.** Build a context with
`context_req` that excludes `confidentiality`, and send the `Discover` signed-only or clear.
If the server accepts it, you have a working probe immediately and the entire sealing
question becomes an optimisation rather than a blocker. If it resets identically, you have
learned the reset is not about the seal wrapper at all — which would redirect the whole
investigation. Either outcome is worth the ten minutes.

## Suggested order

1. The `bytes[8:12]` / `uint32_le(bytes[4:8])` check against an existing capture — minutes,
   no new tooling, and it may close questions 1, 2 and 3 together.
2. Question 15 — ten minutes, and either result is informative.
3. Wireshark NTLMSSP decryption with the account password (question 9) — the definitive
   answer if 1 is ambiguous.
4. Only then the decompile (A), which is thorough but slower than any of the above.

## Confidence

- The `3, 16` reading of `03 00 10 00`: **moderate-to-high**. Both constants are exactly
  what an SSPI seal call site would emit, and 16 is independently corroborated by the
  signature length already matching.
- The 4-byte data length at offsets 4–7: **moderate**, and directly falsifiable by the test.
- The seqnum being a misread artifact: **speculative but cheap to check**, and it would
  explain a result the brief already records as anomalous.
- The RC4 desynchronisation argument against burning a wrap: **high**, standard NTLM
  extended-session-security behaviour.
- D (no prior art): **believed, unverified.**


---

# Test results — 2026-09-08, run against the live instance

Ran the two experiments the answers rank first and second. A third capture was taken and
deleted afterwards; it carried real `SspiHandshake` tokens.

## Test 1 — the 8-byte header hypothesis: HALF confirmed, half refuted

Record 3 payload, third independent capture:

    03 00 10 00 4b a4 14 01 00 00 00 66 2e 5f 8c 46 4f 13 d1 01 00 00 00 08 ...
    payload length 563

| check | predicted | observed | verdict |
|---|---|---|---|
| `uint16(bytes[0:2])` | 3 = cBuffers | **3** | **CONFIRMED** |
| `uint16(bytes[2:4])` | 16 = token length | **16** | **CONFIRMED** |
| `uint32(bytes[4:8])` | 539 = len − 24 | 18,129,995 | **REFUTED** |
| `bytes[8:12]` | `01 00 00 00` | `00 00 00 66` | **REFUTED** |
| `bytes[7:11]` | — | `01 00 00 00` | 7-byte reading holds |

**So the `3, 16` reading is right and the length field is not.** The signature genuinely
begins at offset **7**, and `bytes[19:23]` is `01 00 00 00`, so **seqnum = 1 stands — it is
not a misread artifact.** The anomaly the answers hoped to dissolve is real.

The unexplained region is therefore still exactly three bytes, and now confirmed to sit
between a genuine `cBuffers/token-length` pair and a genuine NTLM signature. Across three
captures: `8e 70 87`, `13 2f 2f`, `4b a4 14` — no constant, no plausible length.

## Test 2 (question 15) — sealing is MANDATORY

Sent a clear-text `Discover` after a completed handshake, with three different context
requests:

| context_req | result |
|---|---|
| default (62, includes confidentiality) | reset |
| confidentiality explicitly excluded | reset |
| integrity only | reset |

All reset identically. **The server requires the sealed wrapper regardless of what the
handshake negotiated**, so this is not a mismatch between requested and used protection, and
there is no unsealed fallback to build a working probe on.

## Where that leaves it

Both remaining unknowns from the top of this document survive:

1. The three bytes at offsets 4–6 — now bounded on both sides by confirmed structure, which
   makes them *more* puzzling, not less.
2. The sequence number, confirmed as 1 rather than dissolved.

The RC4-desynchronisation argument against burning a throwaway wrap is accepted and will not
be retried; if seqnum 1 is genuine then one sealed message legitimately precedes the first
Discover, and **identifying that message is now the sharpest question in this document.**

Next, per the suggested order: **Wireshark NTLMSSP decryption with the account password**
(question 9) — it reads the wrapper and the plaintext directly and needs nothing on the box —
then the ADOMD.NET decompile (A).

## Test 3 (question 9) — NTLM decryption is NOT viable on a single host

Attempted the Wireshark/NTLM-decryption route. It fails for a structural reason worth
recording, because it is not obvious and will otherwise be attempted again.

**The tokens are SPNEGO-wrapped, not raw NTLMSSP.** They are base64 inside `<SspiHandshake>`
inside SOAP inside DIME, and the base64 decodes to an ASN.1 GSS-API token
(`60 6c 06 06 2b 06 01 05 05 02` = SPNEGO OID) with the NTLMSSP message nested inside. So
Wireshark never recognises them as NTLMSSP and never offers to decrypt, whatever preference is
set. Unwrapping by hand is easy — search for `NTLMSSP\0` — and that part works.

**The blocker is the authentication itself.** The only ADOMD.NET available is on the same
machine as the instance, so Windows uses its same-machine shortcut. The AUTHENTICATE message
is 108 bytes with **no user, no domain, no NTLMv2 response and no encrypted session key**:

    AUTHENTICATE 108B  user=None domain=None  nt_response=0B  enc_key=0B

Without an NTLMv2 response there is no `SessionBaseKey` to derive, so **no session key can be
recovered from the wire** and the sealed payload cannot be decrypted. Tried:

| attempt | result |
|---|---|
| connecting to `localhost` | local shortcut, no derivable key |
| explicit credentials in the connection string | **ADOMD over native TCP does integrated auth only** — refused outright; explicit credentials are an HTTP-binding feature |
| connecting via the host's own public IP instead of loopback | still the local shortcut |

**What would make it viable:** ADOMD.NET on a *second* Windows machine, so the exchange is a
genuine network logon. Then the capture carries a real NTLMv2 response, the key derives, and
the wrapper and plaintext can be read directly. Everything else needed is already written and
working — SPNEGO unwrapping, `Authenticate.unpack`, and the `pyspnego` key-derivation
primitives (`md4`, `hmac_md5`, `rc4k`, `sealkey`).

**Consequence:** with one Windows host, question 9 is unavailable and **the ADOMD.NET
decompile (section A) is now the best remaining route** — and it needs no server at all.

## Test 4 — the seqnum anomaly is EXPLAINED: SPNEGO, not raw NTLM

Prompted by the Samba comparison. `auth/ntlmssp/ntlmssp_sign.c` shows the standard NTLM seal
output is exactly `[16-byte signature][ciphertext]` with no extra bytes
(`gensec_ntlmssp_seal_packet`), and `seq_num` starts at **0**, incrementing per sealed message.
So a first sealed message carrying seqnum 1 means something already signed once.

It did. **The real client speaks SPNEGO; this client was speaking raw NTLM.** The captured
tokens are ASN.1 GSS-API (`60 .. 06 06 2b 06 01 05 05 02` — the SPNEGO OID) with NTLMSSP
nested inside, while `spnego.client(protocol="ntlm")` emits bare NTLMSSP. SPNEGO computes a
**`mechListMIC`**, which signs and therefore consumes sequence number 0 — leaving 1 for the
first sealed message.

Measured directly:

| protocol | first seal seqnum |
|---|---|
| `protocol="ntlm"` (what this client used) | **0** |
| `protocol="negotiate"` (what the real client uses) | **1** ✅ matches |

**So the client should use `negotiate`, not `ntlm`.** That is a real defect independent of the
remaining blocker, and it explains an anomaly that two earlier rounds treated as mysterious.

**Still not sufficient.** With SPNEGO the exchange runs two rounds, the server then returns an
empty token, and `pyspnego` still reports `complete=False`; the Discover resets as before. Two
possibilities, untested: the SPNEGO exchange needs a further leg this loop does not drive
(a final `mechListMIC` verification), or the reset is still the three-byte wrapper.

**Remaining unknown is now singular:** the three bytes at offsets 4–6. The seqnum question is
closed, sealing is confirmed correct, and the protocol selection is understood.

## Prior-art checks — all three negative for the wrapper

| repo | verdict |
|---|---|
| `samba-team/samba` | Useful for NTLM semantics and it settled the seqnum question. But its seal output is `sig ‖ ciphertext` with no wrapper, so it cannot explain bytes 4–6. **SMB is not similar**: SMB3 seals with a 52-byte Transform Header, DCE/RPC uses a trailing 8-byte `sec_trailer`. Neither matches. |
| `microsoft/Analysis-Services` | 1014 files of tooling and samples (AlmToolkit, BismNormalizer, job-graph events). Consumes ADOMD/AMO as a library; contains no wire-protocol code. |
| `S-C-O-U-T/Pyadomd` | Three Python files, a pythonnet wrapper around ADOMD.NET. No wire protocol. |

This strengthens the earlier conclusion: there is no prior art for the TCP wrapper, and the
ADOMD.NET decompile is the route to those three bytes.
