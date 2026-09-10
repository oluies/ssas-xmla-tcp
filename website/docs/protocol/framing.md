---
title: DIME framing
sidebar_position: 2
---

# DIME framing

[MS-SSAS] requires messages on TCP to be composed using **Direct Internet Message
Encapsulation**. A DIME message is one or more records.

## The record

A 12-byte header, then four variable-length fields:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|VERSION|M|M|C|  RSRV |TYPE_T |     OPTIONS_LENGTH              |
|(5 bit)|B|E|F|       |(4 bit)|                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         ID_LENGTH             |        TYPE_LENGTH            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         DATA_LENGTH                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  OPTIONS  |  ID  |  TYPE  |  DATA   -- each padded to 4 bytes  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `VERSION` (5 bits) **must** be 1.
- `MB` / `ME` — first / last record of a message.
- `CF` — set on every chunked record except the last. A chunked sequence **must** be contained
  within one DIME message and **must not** span messages, so the boundary is unambiguous.
- `TYPE_T` (4 bits) — 1 for the record beginning a message, 0 for consecutive records.

## The padding rule that bites

Each of the four fields is padded **separately** to a 4-byte boundary, and **the declared
lengths exclude their own padding**.

That is the detail that makes a naive reader desync. A record whose payload has arrived but
whose padding has not is **incomplete**, not decoded. Treating it as complete leaves the pad
bytes in the stream, where they are read as the next message's header and surface as a bogus
"unsupported DIME version" — a desync disguised as a protocol error.

This was a real bug, not a hypothetical. It now lives in `dime.decode_record`, which raises
`IncompleteMessage` for that case; `transport.py` translates it into "read more".

## Content type negotiation

The content type is negotiated **for the duration of the connection** through the first byte
of `OPTIONS`:

| Bit | Constant | Meaning |
|---|---|---|
| `0x01` | `NEGO` | negotiation complete |
| `0x02` | `REQ_SX` | client request is binary XML |
| `0x04` | `REQ_XPRESS` | client request is compressed |
| `0x08` | `RESP_SX` | server response is binary XML |
| `0x10` | `RESP_XPRESS` | server response is compressed |

| `TYPE_LENGTH` | `TYPE` | Content |
|---|---|---|
| 8 | `text/xml` | clear text XML |
| 14 | `application/sx` | binary XML |
| 22 | `application/xml+xpress` | compressed XML |
| 21 | `application/sx+xpress` | compressed binary XML |

Binary XML and compression are **optional**, so this client requests neither and implements
neither. That single decision is what keeps the library small — no [MS-BINXML] decoder, no
XPRESS decompressor.

`NEGO` stays **clear on the very first record** and is set on every later one. Wrong
negotiation bits are silently fatal: the server closes the connection with no error and logs
nothing.

:::danger Do not set `RESP_XPRESS`

The reference client sets it. This one must not. `RESP_XPRESS` makes the server return
XPRESS-compressed XML, which arrives as convincing binary noise rather than as an error — and
this library has no decompressor to tell the difference.

:::

### If the server declines clear text

[MS-SSAS] declares the encoding optional and negotiated, but the [MS-SSSO] overview states the
SSAS protocols "use binary XML [MS-BINXML]". [MS-SSAS] is the normative document, and a live
SQL Server 2022 instance accepts a `text/xml` negotiation — but the tension is real and is
recorded as such.

If a server refuses, the client raises [`NegotiationError`](../reference/errors.md#negotiationerror)
rather than silently accepting another encoding. That is its own error category precisely
because it is not an ordinary failure: it means the assumption this library is built on is
wrong for that server, [MS-BINXML] moves from out-of-scope to required, and **the project's
scope changes**. It must surface loudly rather than be retried around.

## Reassembly

Framing is not message boundaries. A peer may split one message across several reads, or pack
several messages into one segment. So the reader:

- is driven by the header's **declared lengths**, never by the peer going quiet,
- keeps a buffer **across calls**, and
- consumes **exactly one message at a time**, keeping the remainder.

Both halves of that were real bugs. The reader once consumed its whole buffer per message,
silently discarding anything a peer packed into the same segment. And incompleteness was once
detected by substring-matching an exception message, so a chunked message split at a record
boundary — which raises a *different* message — was treated as fatal. Incompleteness is now a
distinct `IncompleteMessage` type, meaning "read more", never "malformed".
