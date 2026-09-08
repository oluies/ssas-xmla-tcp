# Quickstart

## Prerequisites

- Python 3.10+ on Linux. No Windows or .NET components.
- An Analysis Services instance reachable on a **known, pinned TCP port**. If it is a named
  instance, pin its port in server configuration first — this feature does not use the
  redirector, and a firewall rule is needed either way. See D4 in `research.md`.
- A domain credential: a valid Kerberos ticket or keytab, or NTLM credentials.

## Install

```bash
pip install -e .          # from a checkout
```

## Verify a connection

The first thing to run, and the whole of milestone 1:

```bash
python -m ssas_xmla.probe --host <host> --port <port>
```

Expected outcomes, all of them informative:

| Result | Meaning |
|---|---|
| A list of data sources | Working. The binding is usable without IIS. |
| `AuthenticationError` | Reached the server; identity not established. Check ticket or keytab. |
| `AuthorizationError` | Identity fine; the account may not read. Check permissions. |
| `ConnectionError` | Never reached a server. Check host, port, firewall. |
| `NegotiationError` | The server declined clear-text encoding. **Stop and re-read D2** — this changes the project's scope. |

## Run the tests

```bash
pytest                    # sockets disabled by default; no server needed
```

The suite must pass on a machine that has never contacted an Analysis Services instance
(constitution III). If a test needs a live server, it is an integration test and belongs
outside the default run.

## Capture fixtures (developers)

```bash
python tools/capture.py --host <host> --port <port> --out tests/fixtures/
```

Writes scrubbed captures. Two rules, both non-negotiable:

- **Handshake tokens are synthesized, never captured** (D6). A security token carries the
  principal, realm, target service and often the machine name — a captured handshake is a
  disclosure that looks like a binary blob.
- Every capture passes the leak gate before it is committed. Regenerating fixtures means
  re-running that check.
