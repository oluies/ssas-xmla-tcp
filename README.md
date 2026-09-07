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

Milestone 1 (the offline stack: framing, transport, authentication, one metadata request) is
under construction. See [`specs/001-ssas-xmla-tcp/`](specs/001-ssas-xmla-tcp/).

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
pytest
```

Sockets are disabled by default. The suite must pass on a machine that has never contacted an
Analysis Services instance; anything needing a live server is marked `integration` and excluded.

## Two rules that are not negotiable

- **Handshake fixtures are synthesized, never captured.** A GSS/SPNEGO token carries the
  principal, the realm, the target service and often the machine name. A committed capture is a
  disclosure that merely looks like an opaque blob.
- **Read-only by construction.** No operation that creates, alters, refreshes or deletes a
  server-side object exists in this codebase. The capability is absent, not gated.

## Licence

Apache-2.0.
