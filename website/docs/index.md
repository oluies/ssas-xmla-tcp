---
title: Overview
sidebar_position: 1
slug: /
---

# SSAS XMLA over TCP

[![CI](https://github.com/oluies/ssas-xmla-tcp/actions/workflows/ci.yml/badge.svg)](https://github.com/oluies/ssas-xmla-tcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/oluies/ssas-xmla-tcp/blob/main/pyproject.toml)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-3776ab)](./getting-started.md)

`ssas-xmla-tcp` is a pure-Python client for the SQL Server Analysis Services **native
XMLA/TCP binding** — the one ADOMD.NET uses, not the HTTP one. It lets a Linux process read
SSAS metadata and run analytic queries **without an IIS / `msmdpump` deployment** in front of
the instance, and without any Windows or .NET component anywhere.

```python
from ssas_xmla import Credential, connect

with connect("ssas.example.com", 2383, Credential(mechanism="ntlm")) as session:
    for catalog in session.catalogs():
        print(catalog.name, catalog.kind)

    rows = session.execute("EVALUATE TOPN(5, Sales)", catalog="Retail")
    for row in rows:
        print(row)
```

One runtime dependency — [`pyspnego`](https://pypi.org/project/pyspnego/) — plus the standard
library. Nothing else.

→ **[Getting Started](./getting-started.md)** · **[Connecting](./connection/index.md)** ·
**[The protocol](./protocol/index.md)** · **[Limitations](./reference/limitations.md)**

## Why it exists

SSAS speaks XMLA over two bindings, and until now only one of them was reachable from Linux:

| Client | Binding | Runs on Linux? |
|---|---|---|
| ADOMD.NET, MSOLAP OLE DB | native TCP | no — COM/.NET |
| `pyadomd` | native TCP | no — wraps ADOMD.NET through the CLR |
| DuckDB `msolap` extension | native TCP | no — "Windows-only support due to COM dependencies" |
| the `xmla` PyPI package | HTTP only | yes, but needs IIS + `msmdpump` in front of every instance |
| **this library** | **native TCP** | **yes** |

So the practical cost of reading SSAS from Linux has been an IIS deployment per instance.
This library removes that requirement.

It is built from the [Microsoft Open Specifications](./protocol/index.md#normative-references),
not by inspection of other clients — with one documented exception, the post-authentication
frame, which [MS-SSAS] does not specify at all and which was recovered by decompiling
`AdomdClient` ([The sealed frame](./protocol/sealing.md)).

## Status

**Working over NTLM.** `Discover` completes over the native TCP binding, catalogs list, and
DAX queries return rows, from pure Python:

```console
$ python -m ssas_xmla.probe --host ssas.example.com --port 2383 --mechanism ntlm
OK - 1 data source(s):
  - SSAS\TAB  Microsoft Analysis Services
```

Verified against SQL Server 2022 Analysis Services, on both a tabular and a multidimensional
named instance, over NTLM.

**Kerberos is UNVERIFIED.** The framing is mechanism-agnostic and Kerberos is expected to
work, but it has never run against a KDC, and there is one shape the frame provably cannot
carry — a mechanism that pads the plaintext. `seal_frame` raises rather than sending a body
the server cannot parse. The whole of that argument, including what would settle it, is in
[Kerberos](./connection/kerberos.md).

## What it does not do

Deliberately, and each is a separate feature rather than a quiet extension:

- **No port discovery.** Instances are addressed at a **pinned port**; the named-instance
  redirector on TCP 2382 has no public specification. See [Addressing](./connection/index.md#addressing).
- **No binary XML, no compression.** Both are optional in [MS-SSAS] and negotiated; this
  client asks for clear text and [fails loudly](./reference/errors.md#negotiationerror) if the
  server declines.
- **No writes, ever.** Read-only *by construction*: no operation that creates, alters,
  refreshes or deletes a server-side object exists in the package, and a test asserts the
  absence structurally. The capability is absent, not gated.
- No connection pooling, no async.

## Two rules that are not negotiable

- **Handshake fixtures are synthesized, never captured.** A GSS/SPNEGO token carries the
  principal, the realm, the target service and often the machine name. A committed capture is
  a disclosure that merely looks like an opaque blob.
- **Nothing identifying is emitted.** No credential, token, host, address, account, principal,
  realm, machine name or SID reaches a log line or an error message, at any level. A CI gate
  scans every tracked file for those tokens.
