---
title: Python API
sidebar_position: 1
---

# Python API

Everything below is exported from the package root:

```python
from ssas_xmla import (
    connect, Session, Credential, ConnectionTarget, Catalog, Rowset,
    NegotiatedTerms, State, DEFAULT_TIMEOUT,
    SsasError, ConnectionError, AuthenticationError, AuthorizationError,
    ServerError, NegotiationError, ProtocolError,
)
```

## `connect()`

```python
def connect(
    host: str,
    port: int,
    credential: Credential | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    channel: Channel | None = None,
    context=None,
    password: str | None = None,
) -> Session
```

Opens a socket, negotiates framing and completes the security handshake, then returns an
authenticated `Session`. Raises one of the [categorised errors](./errors.md) on any failure —
there is no half-open result.

`password` is only for a standalone server, where NTLM has no ambient identity. It reaches the
security layer directly and is never held on the session or the credential.

`channel` and `context` are injection points for testing (the [byte seam](../protocol/index.md#testability-the-byte-seam));
production callers leave them unset.

`DEFAULT_TIMEOUT` is `30.0` seconds.

## `Credential`

```python
@dataclass(frozen=True)
class Credential:
    mechanism: str = "kerberos"      # or "ntlm" or "negotiate"
    principal: str | None = None     # None means the ambient identity
    service: str = "MSOLAPSvc.3"
    instance: str | None = None      # a named instance, if the SPN is registered that way
    use_port: bool = False           # ask for MSOLAPSvc.3/host:port, as ADOMD does on SSPI
    spn: str | None = None           # full override, service class included
```

**No password field**, deliberately — see [Connecting](../connection/index.md#credentials).

### `Credential.target(host, port=None) -> str`

The SPN this credential will request. Resolution order:

1. `spn` if set — used verbatim, service class included
2. `instance` if set — `{service}/{host}:{instance}`
3. `use_port` and a port — `{service}/{host}:{port}`
4. otherwise — `{service}/{host}` (**the default: portless**)

NTLM ignores the result entirely. Kerberos does not; the reasoning behind the portless default
is on the [Kerberos page](../connection/kerberos.md#the-spn).

## `ConnectionTarget`

```python
@dataclass(frozen=True)
class ConnectionTarget:
    host: str
    port: int
    timeout: float = 30.0
```

Validated on construction: `host` must be non-empty, `port` must be in `1..65535`, and
`timeout` must be positive — unbounded waits are not offered. **There is no default port.**

## `Session`

A context manager. `close()` is idempotent, and closing an already-failed session is not an
error.

| Member | Signature | Notes |
|---|---|---|
| `open` | `(channel=None, context=None, password=None) -> Session` | connect, negotiate, authenticate; resets all per-connection state and closes any previous stream |
| `close` | `() -> None` | releases the socket and the security context |
| `discover` | `(request_type, restrictions=None, catalog=None) -> Rowset` | any XMLA request type |
| `discover_datasources` | `() -> Rowset` | `DISCOVER_DATASOURCES` |
| `catalogs` | `() -> list[Catalog]` | `DBSCHEMA_CATALOGS` |
| `tables` | `(catalog) -> Rowset` | `DBSCHEMA_TABLES` |
| `columns` | `(catalog) -> Rowset` | `DBSCHEMA_COLUMNS` |
| `execute` | `(statement, catalog=None) -> Rowset` | read-only analytic statement |
| `state` | `State` | see below |
| `terms` | `NegotiatedTerms` | settled once per session |

Calling a request method on a session that is not `AUTHENTICATED` raises `AuthenticationError`
naming the actual state.

## `State`

```python
State.UNCONNECTED | State.NEGOTIATED | State.AUTHENTICATED | State.CLOSED | State.FAILED
```

## `NegotiatedTerms`

Settled once per session and immutable thereafter.

| Field | Default | Meaning |
|---|---|---|
| `content_type` | `"text/xml"` | the negotiated encoding |
| `request_binary` | `False` | [MS-BINXML] on requests — never enabled |
| `response_binary` | `False` | [MS-BINXML] on responses — never enabled |
| `request_compressed` | `False` | XPRESS on requests — never enabled |
| `response_compressed` | `False` | XPRESS on responses — never enabled |
| `protection` | `False` → `True` | set once the handshake completes and sealing is in force |

## `Catalog`

```python
@dataclass(frozen=True)
class Catalog:
    name: str
    description: str = ""
    kind: str = "unknown"   # "tabular" | "multidimensional" | "unknown"
```

`kind` is derived from `DBSCHEMA_CATALOGS.TYPE` and reports `"unknown"` rather than guessing —
see [Reading metadata](../reading/metadata.md#catalogkind--and-what-it-will-not-guess).

## `Rowset`

```python
@dataclass(frozen=True)
class Rowset:
    columns: list[str]
    rows: list[dict[str, str]]
```

Supports `len()` and iteration over `rows`. Values are **strings**; interpreting them is the
caller's business.

## Errors

Every error derives from `SsasError`, which carries `message` and an optional `detail` holding
the server's own explanation, scrubbed. See [Errors](./errors.md).

## The probe

```bash
python -m ssas_xmla.probe --host HOST --port PORT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `--host` | required | |
| `--port` | required | the instance's **pinned** TCP port |
| `--mechanism` | `kerberos` | `kerberos` or `ntlm` |
| `--principal` | ambient | |
| `--service` | `MSOLAPSvc.3` | the SPN's service class |
| `--instance` | — | ask for `MSOLAPSvc.3/<host>:<instance>` |
| `--use-port` | off | ask for `MSOLAPSvc.3/<host>:<port>` |
| `--spn` | — | full SPN override |
| `--timeout` | `30.0` | seconds |

The password comes from `$SSAS_PASSWORD` and **only** from there — never from argv, which is
visible in the process list to every other user on the machine.
