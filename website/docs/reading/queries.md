---
title: Running queries
sidebar_position: 2
---

# Running queries

```python
rows = session.execute("EVALUATE TOPN(10, Sales, Sales[Amount], DESC)", catalog="Retail")

for row in rows:
    print(row)
```

`execute()` takes a read-only analytic statement and an optional catalog, and returns a
[`Rowset`](../reference/api.md#rowset). DAX is what has been exercised against a live
instance; MDX goes over the same `Execute` operation.

The statement is XML-escaped before it reaches the envelope, so a query containing `<`, `>` or
`&` is carried correctly rather than producing a malformed request.

## Read-only by construction

There is no parameter, flag or alternate entry point through which a mutating command can be
issued. This is not access control that could be misconfigured — the SOAP envelope module has
**no builder for a mutating command**, so no argument to `execute()` can reach one. The
capability is absent, not gated.

A test asserts that absence structurally over the whole package, so the capability cannot
arrive unnoticed in a later change.

If you need to write to a model, this is the wrong library, and that is the intended answer.

## Errors carry the server's own text

A malformed query surfaces the server's explanation rather than a generic failure:

```python
from ssas_xmla import ServerError

try:
    session.execute("EVALUATE NoSuchTable", catalog="Retail")
except ServerError as exc:
    print(exc.detail)   # the server's message, scrubbed and truncated
```

`detail` is scrubbed before it reaches you — no host, address, account, principal, realm,
machine name or SID survives — and truncated to 300 characters. The scrubbing is anchored to
real service-principal classes rather than a generic `word/word` shape, because a generic
pattern destroyed the very diagnostics it was meant to preserve, turning `text/xml` and
`Envelope/Body` into `<SPN>`.

See [Errors](../reference/errors.md) for which category you get and what each one means.

## Timeouts

Every network wait, including the one for a long query's response, is bounded by the session
timeout set at `connect()`. There is no way to disable it. A query expected to take longer
than the default 30 seconds needs a larger timeout on the session:

```python
with connect("ssas.example.com", 2383, credential, timeout=300.0) as session:
    rows = session.execute(long_running_dax, catalog="Retail")
```

There is no per-query timeout: the bound belongs to the connection, and a query that outlives
it fails the session rather than leaving a socket in an unknown state.
