---
title: Limitations
sidebar_position: 3
---

# Limitations

Each of these is a deliberate boundary, not an oversight. Where one is a candidate for future
work, it is a separate feature rather than a quiet extension of this one.

## Kerberos is unverified

NTLM is exercised end to end against a live SQL Server 2022 instance. Kerberos has never run
against a KDC — the test fixture is a standalone workgroup machine, so its SSAS can only do
NTLM. The framing work Kerberos needs is done and two of the three verification tiers are in
the suite, but the result is not in hand. [Full detail](../connection/kerberos.md).

**A mechanism that pads the plaintext cannot be framed at all**, and `seal_frame` raises
rather than sending a body the server cannot parse.

## No port discovery

Instances are addressed at a **pinned port**. The named-instance redirector on TCP 2382 has no
public wire-format specification, and was tested empirically not to speak the [MC-SQLR]
framing that resolves database-engine instances on UDP 1434.

Pinning the port in `msmdsrv.ini` costs nothing — a firewall rule is needed either way.

## No binary XML, no compression

[MS-BINXML] and XPRESS are optional in [MS-SSAS] and negotiated. This client requests clear
text and implements neither, which is what keeps it to one dependency. If a server declines
clear text the client raises [`NegotiationError`](./errors.md#negotiationerror) rather than
falling back — there is nothing to fall back to.

## Read-only, by construction

No operation that creates, alters, refreshes or deletes a server-side object exists in the
package. The SOAP envelope builder has no constructor for a mutating command, so no argument
to any public method can reach one, and a test asserts that absence structurally.

This is not a gate that could be opened by configuration. If you need to write to a model,
this is the wrong library.

## No connection pooling, no async

One session is one socket, synchronous. Pooling and an async interface are each a separate
feature if wanted.

## Values are strings

A `Rowset` returns exactly what the server sent, as text. There is no type mapping, no
coercion, no nullability inference — deliberately, because every consumer has its own mapping
and would have to undo a guessed one.

## `Catalog.kind` can be `"unknown"`

It is derived from `DBSCHEMA_CATALOGS.TYPE` on two observations (tabular reports `3`,
multidimensional `0`). Anything else reports `"unknown"` rather than guessing.
`COMPATIBILITY_LEVEL` is deliberately not consulted — it does not distinguish the two, and a
">= 1100 means tabular" rule mislabels every modern multidimensional database.

## No unbounded waits, and no way to ask for one

Every network operation is bounded by the session timeout. There is no option to disable it at
any layer. A long query needs a larger session timeout, not an unbounded one.

## Platform

Python 3.10–3.13. Linux is the target and CI runs there. Nothing is Windows-specific, but
Windows is not what this exists for — on Windows, ADOMD.NET already works.
