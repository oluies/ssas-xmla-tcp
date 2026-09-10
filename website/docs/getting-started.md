---
title: Getting Started
sidebar_position: 2
---

# Getting Started

## Prerequisites

- **Python 3.10 or newer.** Linux is the target; nothing here is Windows-specific, and no
  .NET or COM component is used anywhere.
- **An Analysis Services instance on a known, pinned TCP port.** A default instance listens on
  2383. A named instance gets a dynamic port and would normally be found through the
  redirector on TCP 2382 — which this client does not use, so pin the port first
  ([Addressing](./connection/index.md#addressing)).
- **A credential.** A domain account over NTLM or Kerberos, or — on a standalone server — a
  local account with its password supplied through the environment.

## Step 1: install

```bash
pip install ssas-xmla-tcp
```

Or from a checkout:

```bash
pip install -e ".[dev]"
```

The install pulls exactly one runtime dependency, `pyspnego`. If it pulls more, that is a bug:
CI has a job that asserts the declared dependency set is *exactly* `pyspnego`, because a
protocol library that drags in a platform SDK is not reusable by the audience it exists for.

## Step 2: probe the instance

Before writing any code, run the probe. It answers one question — is this instance readable
over the native binding, with no IIS in front of it? — and names the stage that failed if not.

```bash
python -m ssas_xmla.probe --host ssas.example.com --port 2383 --mechanism ntlm
```

```console
OK - 1 data source(s):
  - SSAS\TAB  Microsoft Analysis Services
```

`--mechanism ntlm` is not decoration. The default is `kerberos`, and NTLM is the only
mechanism exercised end to end — see [Kerberos](./connection/kerberos.md) for why the
difference matters and what the frame cannot carry.

On a standalone (non-domain) server, NTLM has no ambient identity to draw on, so supply the
password **through the environment, never on the command line** — argv is visible in the
process list to every other user on the machine:

```bash
export SSAS_PASSWORD='...'
python -m ssas_xmla.probe --host ssas.example.com --port 2383 \
    --mechanism ntlm --principal 'DOMAIN\reader'
```

Every outcome is informative, and each has its own exit code:

| Exit | Result | Meaning |
|---|---|---|
| 0 | a list of data sources | working — the binding is usable with no IIS |
| 2 | `ConnectionError` | never reached a server. Check host, port, firewall |
| 3 | `AuthenticationError` | reached the server; identity not established |
| 4 | `NegotiationError` | the server declined clear-text encoding — this **changes the project's scope** |
| 5 | `AuthorizationError` | identity fine; the account may not read. Check permissions |
| 6 | `ServerError` | the server understood the request and rejected it |
| 7 | `ProtocolError` | the bytes did not match the specification |

The full table, including what to do about each, is in [Errors](./reference/errors.md).

## Step 3: read something

```python
from ssas_xmla import Credential, connect

credential = Credential(mechanism="ntlm", principal="DOMAIN\\reader")

with connect("ssas.example.com", 2383, credential, password="...") as session:
    for catalog in session.catalogs():
        print(f"{catalog.name:30} {catalog.kind}")
```

```console
Retail                         tabular
Adventure Works                multidimensional
```

`connect()` negotiates framing and completes the security handshake before it returns, so a
returned `Session` is always usable. It is a context manager: the socket and the security
context are released on the way out of the block, including on error.

## Step 4: query

```python
rows = session.execute("EVALUATE TOPN(10, Sales, Sales[Amount], DESC)", catalog="Retail")

print(rows.columns)
for row in rows:
    print(row["Sales[Amount]"])
```

A [`Rowset`](./reference/api.md#rowset) is a list of dictionaries with the column names the
server returned. There is no `execute` variant that mutates: the SOAP envelope builder has no
constructor for a mutating command, so no argument can reach one.

## Where to go next

- [Connecting](./connection/index.md) — targets, timeouts, session lifecycle, addressing
- [NTLM](./connection/ntlm.md) and [Kerberos](./connection/kerberos.md) — the mechanisms
- [Reading metadata](./reading/metadata.md) — `Discover` and the schema rowsets
- [Troubleshooting](./reference/troubleshooting.md) — the failures that look like something else
