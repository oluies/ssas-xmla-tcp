# ssas-xmla-tcp

A pure-Python client for the **SQL Server Analysis Services native XMLA/TCP binding**, so
Linux consumers can read SSAS metadata without an IIS / `msmdpump` deployment in front of the
instance.

**Documentation: <https://oluies.github.io/ssas-xmla-tcp/>** — getting started, the two
authentication mechanisms and what is verified about each, the wire protocol layer by layer,
the Python API, and troubleshooting. Source in [`website/`](website/).

The vendor's clients for this binding are all Windows-only: ADOMD.NET and the MSOLAP OLE DB
provider are COM/.NET, `pyadomd` wraps ADOMD.NET through the CLR, and DuckDB's `msolap`
extension states "Windows-only support due to COM dependencies". The `xmla` Python package
speaks XMLA but only over HTTP, which is what requires the IIS pump in the first place.

One other project reaches this binding from Linux:
[`xmla-extention`](https://hugr-lab.github.io/xmla-extention/), an independent C++ DuckDB
extension on MIT krb5. It does not use this library and this library does not depend on it;
reach for it when the result should land in DuckDB, and for this one when you want SSAS
metadata inside a Python process with a single dependency and no native toolchain.

Built from the Microsoft Open Specifications — see [`docs/discovery-brief.md`](docs/discovery-brief.md)
for the citations behind each layer. Claims not yet backed by a recorded fixture are marked
**UNVERIFIED** there rather than presented as fact.

## Status

**Working over NTLM.** A `Discover` completes over the native TCP binding, catalogs list, and
DAX queries return rows — from pure Python, with no IIS and no Windows components:

```
$ python -m ssas_xmla.probe --host HOST --port 2383 --mechanism ntlm
OK - 1 data source(s):
  - HOST\TAB  Microsoft Analysis Services
```

Verified against SQL Server 2022 Analysis Services, both a tabular and a multidimensional
named instance, over NTLM.

**Kerberos is UNVERIFIED.** The handshake is mechanism-agnostic and should work, but the frame
layer was recovered from, and has only ever been exercised against, an NTLM session: the chunk
size is NTLM's `cbMaxToken`, the token length is NTLM's, and — the part that actually bites —
the frame has no field carrying the *unpadded* plaintext length. `spnego` reports zero padding
for NTLM and non-zero for the GSS/Kerberos path, so a padding mechanism would hand the server
XML with trailing bytes it cannot strip. `seal_frame` therefore **refuses** a mechanism that
pads, naming the limitation, rather than producing a corrupt body. Lifting this needs either a
Kerberos-capable fixture or the reference client's answer for the unpadded length; see
[`docs/discovery-brief.md`](docs/discovery-brief.md).

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
python -m ssas_xmla.probe --host HOST --port PORT --mechanism ntlm
```

`--mechanism ntlm` is not decoration: the default is `kerberos`, and a padding mechanism
cannot be carried by this frame layout, so `seal_frame` refuses it (exit 7). NTLM is the only
path exercised end to end — see [Status](#status).

Every outcome is informative:

| Result | Meaning |
|---|---|
| a list of data sources | working — the binding is usable with no IIS |
| `AuthenticationError` | reached the server; identity not established. Check ticket/keytab |
| `AuthorizationError` | identity fine; the account may not read. Check permissions |
| `ConnectionError` | never reached a server. Check host, port, firewall |
| `NegotiationError` | the server declined clear-text encoding — **this changes the project's scope**, see D2 in `specs/001-ssas-xmla-tcp/research.md` |
| `ProtocolError` (exit 7) | the bytes did not match the specification. If it names padding, the negotiated mechanism pads and this frame has no field for the unpadded length — retry with `--mechanism ntlm` |

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
