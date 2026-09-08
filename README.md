# ssas-xmla-tcp

A pure-Python client for the **SQL Server Analysis Services native XMLA/TCP binding**, so
Linux consumers can read SSAS metadata without an IIS / `msmdpump` deployment in front of the
instance.

Every other client for this binding is Windows-only: ADOMD.NET and the MSOLAP OLE DB provider
are COM/.NET, `pyadomd` wraps ADOMD.NET through the CLR, and DuckDB's `msolap` extension states
"Windows-only support due to COM dependencies". The `xmla` Python package speaks XMLA but only
over HTTP, which is what requires the IIS pump in the first place.

Built from the Microsoft Open Specifications — see [`docs/discovery-brief.md`](docs/discovery-brief.md)
for the citations behind each layer. Claims not yet backed by a recorded fixture are marked
**UNVERIFIED** there rather than presented as fact.

## Status

**Working.** A `Discover` completes over the native TCP binding, catalogs list, and DAX
queries return rows — from pure Python, with no IIS and no Windows components:

```
$ python -m ssas_xmla.probe --host HOST --port 2383
OK - 1 data source(s):
  - HOST\TAB  Microsoft Analysis Services
```

Verified against SQL Server 2022 Analysis Services, both a tabular and a multidimensional
named instance, over NTLM.

The layer that took the longest is the post-authentication frame, which [MS-SSAS] does not
document. It was recovered by decompiling `AdomdClient` and is implemented in
[`sealing.py`](src/ssas_xmla/sealing.py); the reasoning is in
[`docs/discovery-brief.md`](docs/discovery-brief.md).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the layers fit together.

## Requirements

- Python 3.10+, Linux. No Windows or .NET components, anywhere.
- An instance reachable on a **known, pinned TCP port**. This release does not use the
  named-instance redirector — its wire format has no public specification, and pinning the port
  is server configuration that costs nothing since a firewall rule is needed either way.
- A domain credential: a Kerberos ticket or keytab, or NTLM credentials.

## Install

```bash
pip install -e ".[dev]"
```

## Verify a connection

```bash
python -m ssas_xmla.probe --host HOST --port PORT
```

Every outcome is informative:

| Result | Meaning |
|---|---|
| a list of data sources | working — the binding is usable with no IIS |
| `AuthenticationError` | reached the server; identity not established. Check ticket/keytab |
| `AuthorizationError` | identity fine; the account may not read. Check permissions |
| `ConnectionError` | never reached a server. Check host, port, firewall |
| `NegotiationError` | the server declined clear-text encoding — **this changes the project's scope**, see D2 in `specs/001-ssas-xmla-tcp/research.md` |

## Tests

```bash
pytest                              # offline suite, sockets disabled
pytest --cov --cov-report=term-missing   # with coverage (floor: 90%)
./tests/hooks/test_leak_gate.sh     # the commit gate's boundary cases
```

Sockets are disabled by default and the suite must pass on a machine that has never contacted
an Analysis Services instance. Anything needing a live server is marked `integration`, is
skipped unless `SSAS_HOST` and friends are set, and is granted socket access explicitly.

To run the integration tests against a real instance:

```bash
export SSAS_HOST=... SSAS_PORT=...        # the instance's PINNED port
export SSAS_MECHANISM=ntlm SSAS_PRINCIPAL=...
export SSAS_PASSWORD=...                  # standalone servers only; never on the command line
pytest -m integration
```

CI runs four jobs: lint (`ruff check` + `format --check`), the offline suite under coverage on
Python 3.10–3.13, a dependency-surface job asserting the runtime dependency set is exactly
`pyspnego`, and a leak gate that scans every tracked file for identifying tokens.

## Two rules that are not negotiable

- **Handshake fixtures are synthesized, never captured.** A GSS/SPNEGO token carries the
  principal, the realm, the target service and often the machine name. A committed capture is a
  disclosure that merely looks like an opaque blob.
- **Read-only by construction.** No operation that creates, alters, refreshes or deletes a
  server-side object exists in this codebase. The capability is absent, not gated.

## Licence

Apache-2.0.
