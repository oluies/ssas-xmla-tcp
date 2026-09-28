---
title: The sealed frame
sidebar_position: 3
---

# The sealed frame

This is the layer [MS-SSAS] does not document, and the one that took the longest. Every
message after the handshake is sealed and wrapped in a 4-byte header:

```text
+--------+--------+---------------------------+----------------+
| uint16 | uint16 |        ciphertext         |     token      |
| dataSize        |                           |                |
|        tokenSize|                           |                |
+--------+--------+---------------------------+----------------+
   little-endian
```

**Ciphertext first, token second** — the inverse of the GSS ordering `pyspnego` emits.

:::danger Getting the order backwards is silently fatal

The server closes the connection with no error and logs nothing. There is no diagnostic to
work from; nine attempts went into rediscovering this.

:::

The layer was recovered by decompiling `AdomdClient` — `TcpSecureStream.WriteHeader` and
`WriteInBlockMode`.

## Three details that cost days

**The UTF-8 BOM is sealed as its own frame**, before the body. The reference client writes the
body through a `StreamWriter` whose preamble is a separate write, so the BOM arrives as a
complete frame of its own rather than as the first three bytes of the body's frame.

**Sealing is mandatory.** It is not an optimisation the client can skip. An unsealed
post-handshake message is dropped by the server with no error and nothing in its log — the
same silent failure as the wrong byte order, from a different cause.

**The handshake itself is not sealed.** Sealing starts after it. `sealing.py` therefore sits
outside the layer stack entirely: it imports only `errors`, and `client.py` applies it to
outgoing messages after the handshake completes.

## Chunking

A payload longer than `MAX_CHUNK` becomes several sealed frames, each with its own header,
ciphertext and token. `unseal_message` walks them by their declared sizes and concatenates the
plaintext.

`MAX_CHUNK` is **2888**, which is the reference client's `cbMaxToken` for NTLM — it reuses
that value as the data chunk size. Nothing forces a match: smaller chunks are always valid,
just more frames.

The real ceiling is **65535**, because `dataSize` is a `uint16`. `seal_frame` raises rather
than silently truncating past it.

## What varies by mechanism, and what does not

The framing is **mechanism-agnostic**: in `AdomdClient`, dispatch between the two framing
styles is decided solely by `IsSchannelSspi()`, and Negotiate, Kerberos and NTLM all land in
`SecurityMode.Block` — the same `WriteInBlockMode`, the same 4-byte header, the same
DATA-then-TOKEN order.

Three things do vary:

| | NTLM | Kerberos |
|---|---|---|
| `tokenSize` | 16 | `max(cbSecurityTrailer, cbMaxSignature)`, queried at runtime; larger with an AES etype |
| chunk size | `cbMaxToken` = 2888 | `min(cbMaxToken, 65535)`, larger, and grows with the PAC |
| padding | zero | **unknown — and this is the blocker** |

`tokenSize` is never hardcoded: `seal_frame` writes `len(token)` and `unseal_message` reads
the declared size. A test pins that with a 60-byte token from a Kerberos-shaped fake context.

## Why padding cannot be framed

ADOMD uses two buffers on this path, DATA and TOKEN. There is no PADDING buffer, and **no
header field carrying the unpadded plaintext length**. So padding bytes would sit inside
`dataSize` with nothing to strip them by, and the server would receive XML with trailing bytes
it cannot remove — failing to parse for a reason it cannot report.

`seal_frame` raises `ProtocolError` when the negotiated mechanism reports padding, naming the
limitation. It is a runtime guard, not a refusal of Kerberos: NTLM reports zero padding and
the AES etypes are expected to as well. See [Kerberos](../connection/kerberos.md#padding-is-the-one-thing-that-cannot-be-framed).

## `wrap_winrm`, not `wrap`

`pyspnego`'s plain `wrap()` for Kerberos returns a **contiguous** GSS_Wrap token with the
plaintext encrypted inside it under RRC rotation — no fixed offset to slice the ciphertext out
at, so it cannot be split into the frame's two halves at all.

This library uses `wrap_winrm`, the detached `wrap_iov` form — header, data, padding — which
is the shape the frame needs. The contract is pinned by a hermetic test running a real
`pyspnego` client against a real `pyspnego` server over NTLM: ciphertext at plaintext length,
detached token, and keystream and sequence continuity across chunks.

## Failure modes to recognise

| Symptom | Cause |
|---|---|
| connection closed, no error, nothing in the server log | token/data order reversed, an unsealed message, or wrong negotiation bits |
| an empty rowset where rows were expected | the unsealed payload was not XML — wrong context, desynchronised sequence, or a mechanism whose framing differs. The client raises `ProtocolError` for this rather than returning the empty rowset |
| convincing binary noise instead of XML | `RESP_XPRESS` was set and the server compressed the response |
| `ProtocolError` naming padding | the negotiated mechanism pads; retry with NTLM |
