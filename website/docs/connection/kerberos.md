---
title: Kerberos
sidebar_position: 3
---

# Kerberos

:::warning UNVERIFIED

Kerberos has **never been run against a KDC**. It is expected to work, the framing work it
needs is done, and the guards that would catch it failing are in place — but nothing on this
page is backed by a live Kerberos session. Treat it as a reasoned position, not a result.

:::

`Credential(mechanism="kerberos")` is the **default**, which means the first thing most people
run is the path that is not yet proven. That is why `--mechanism ntlm` appears in every
example in [Getting Started](../getting-started.md).

## What the decompile settled

The question that mattered was whether the post-handshake frame is mechanism-specific. It is
not. In `AdomdClient`, dispatch between the two framing styles is decided solely by
`IsSchannelSspi()`, and Negotiate, Kerberos and NTLM all land in `SecurityMode.Block` — the
same `WriteInBlockMode`, the same 4-byte header, the same DATA-then-TOKEN order.

**The framing is mechanism-agnostic.** Three things do differ, and all three are handled:

| Difference | How it is handled |
|---|---|
| `tokenSize` is not 16 — it is `max(cbSecurityTrailer, cbMaxSignature)`, queried at runtime, and an AES etype gives substantially more | nothing hardcodes it: `seal_frame` writes `len(token)`, `unseal_message` reads the declared size. A test pins this with a 60-byte token |
| The chunk size differs — `maxEncryptionBufferSize = min(cbMaxToken, 65535)`, and Kerberos's `cbMaxToken` is far larger than NTLM's 2888 and grows with the PAC | keeping 2888 is correct. Smaller chunks are always valid; they just will not byte-match a Kerberos capture |
| Padding | **cannot be framed at all** — see below |

## Padding is the one thing that cannot be framed

ADOMD uses two buffers on this path, DATA and TOKEN. There is no PADDING buffer, and no header
field carrying the *unpadded* plaintext length. So padding bytes would sit inside `dataSize`
with nothing to strip them by, and the server would receive XML with trailing bytes it cannot
remove.

`seal_frame` therefore **raises `ProtocolError`** when the negotiated mechanism reports padding,
naming the limitation, rather than sending a body the server fails to parse for reasons it
cannot report.

This is a **runtime guard, not a refusal of Kerberos**. NTLM reports zero padding, and the AES
etypes are expected to as well. If you hit it, the probe says so and tells you to retry with
NTLM ([exit 7](../reference/errors.md#protocolerror)).

Lifting the guard needs one of two things: a Kerberos-capable fixture that shows the actual
padding of the AES etypes, or the reference client's answer for where the unpadded length is
carried.

## `wrap_winrm`, not `wrap`

One thing framing does not solve on its own. `pyspnego`'s plain `wrap()` for Kerberos returns
a **contiguous** GSS_Wrap token with the plaintext encrypted inside it under RRC rotation —
there is no fixed offset to slice the ciphertext out at, so it cannot be split into the
frame's DATA and TOKEN halves.

This library uses `wrap_winrm`, which is the detached `wrap_iov` form — header, data, padding
— and is exactly the shape the frame needs. That contract is pinned by a hermetic test that
runs a real `pyspnego` client against a real `pyspnego` server over NTLM: ciphertext at
plaintext length, detached token, keystream and sequence continuity across chunks. No KDC
required for that one.

## The SPN

The SPN matters far more under Kerberos than under NTLM, which ignores the target entirely.

Per `CalculateNTAuthenticationSPN`, the reference client asks for
`MSOLAPSvc.3/<server>:<port>` — `DsMakeSpn` is called *with* the port — or
`MSOLAPSvc.3/<server>:<instance>` for a named instance.

**This library does not follow that by default, deliberately.** `Credential.target()` produces
the **portless** `MSOLAPSvc.3/<server>`:

```python
Credential().target("ssas.example.com", 2383)
# 'MSOLAPSvc.3/ssas.example.com'
```

The reasoning: the ADOMD citation justifies the port form only on **SSPI**, where the SPN is
used as written. On the **GSSAPI** path this library actually takes, `pyspnego` builds
`service@hostname` and imports it as `gssapi.NameType.hostbased_service`, so the host half goes
through krb5 canonicalization *and realm determination*. Handing it `ssas.example.com:2383`
leaves a trailing component of `example.com:2383`, which no `[domain_realm]` mapping and no
uppercase-domain heuristic resolves — a ticket request in the wrong realm, on exactly the first
real Kerberos attempt.

Neither form is KDC-tested. Given that, the default stays the shape that shipped and that
GSSAPI expects, and the reference client's forms are **opt-in**:

```python
Credential(use_port=True)              # MSOLAPSvc.3/<host>:<port>
Credential(instance="TAB")             # MSOLAPSvc.3/<host>:TAB
Credential(spn="MSOLAPSvc.3/ssas.example.com")   # full override, service class included
```

and on the probe:

```bash
python -m ssas_xmla.probe --host ssas.example.com --port 2383 --instance TAB
python -m ssas_xmla.probe --host ssas.example.com --port 2383 --use-port
python -m ssas_xmla.probe --host ssas.example.com --port 2383 --spn MSOLAPSvc.3/ssas.example.com
```

Without those flags a named instance registered as `MSOLAPSvc.3/host:TAB` reports
"AUTHENTICATION FAILED — check ticket or keytab", which points at the wrong cause entirely.
The probe's failure message names the SPN the run actually asked for, so the mismatch is
visible rather than inferred.

## What would settle it

Three tiers, in increasing cost. Two are already in the test suite:

| Tier | What it proves | Cost |
|---|---|---|
| Kerberos-shaped fake contexts | nothing assumes a 16-byte token; a padding mechanism is refused; the frame shape is identical across mechanisms | free, hermetic |
| real `pyspnego` client ↔ server over NTLM | the `wrap_winrm` contract itself — ciphertext at plaintext length, detached token, keystream and sequence continuity across chunks | free, hermetic, no KDC |
| **a live Kerberos session** | the AES etypes' actual padding and token size | needs a KDC **and a domain** |

The third is not merely unwritten — it is not currently possible. The test fixture is a
**standalone workgroup machine**, so its SSAS can only do NTLM. Real verification needs that
box promoted to a domain controller, or a run against a domain-joined production instance.

If you have a domain-joined instance and run this, the result is worth an issue either way.
