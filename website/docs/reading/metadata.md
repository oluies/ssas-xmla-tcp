---
title: Reading metadata
sidebar_position: 1
---

# Reading metadata

Metadata comes back from XMLA's `Discover` operation. `Session.discover()` is the general
form; the named helpers are convenience wrappers over it.

```python
rows = session.discover("DBSCHEMA_TABLES", catalog="Retail")
print(rows.columns)
for row in rows:
    print(row["TABLE_NAME"])
```

## The helpers

| Method | Request type | Returns |
|---|---|---|
| `session.discover_datasources()` | `DISCOVER_DATASOURCES` | `Rowset` — the probe's request |
| `session.catalogs()` | `DBSCHEMA_CATALOGS` | `list[Catalog]` |
| `session.tables(catalog)` | `DBSCHEMA_TABLES` | `Rowset` |
| `session.columns(catalog)` | `DBSCHEMA_COLUMNS` | `Rowset` |
| `session.discover(type, restrictions, catalog)` | anything | `Rowset` |

Any XMLA request type the server supports works through `discover()` — `MDSCHEMA_CUBES`,
`MDSCHEMA_MEASURES`, `DISCOVER_PROPERTIES`, and the rest. The library does not maintain an
allowlist of request types.

## Restrictions

Restrictions are passed as a **mapping**, not as XML:

```python
rows = session.discover(
    "DBSCHEMA_COLUMNS",
    restrictions={"TABLE_NAME": "Sales"},
    catalog="Retail",
)
```

Every value is XML-escaped, and every *name* is validated against an identifier pattern before
it reaches the envelope. This is not incidental tidiness: `restrictions` was the one parameter
on the public surface through which caller text reached the wire unfiltered, so a value
containing `<` or `&` produced a malformed envelope, and a crafted one could close
`RestrictionList` and inject sibling elements. An invalid name raises `ValueError` locally
rather than being sent.

## An empty rowset is an answer

```python
catalogs = session.catalogs()
if not catalogs:
    print("nothing visible to this account")
```

An empty result means "nothing visible to this account" and is **distinct from
`AuthorizationError`**. A server that refuses raises; a server with nothing to show returns
nothing. Both are correct outcomes and the caller can tell them apart without parsing text.

That distinction is why an unparseable response is not allowed to arrive looking like an empty
rowset. After unsealing, the client checks that the payload is actually an XML envelope and
raises `ProtocolError` if it is not — because the likeliest failure of a cipher layer (wrong
context, desynchronised sequence number, a mechanism whose framing differs) produces exactly
that indistinguishable emptiness.

## `Catalog.kind` — and what it will not guess

```python
for catalog in session.catalogs():
    print(catalog.name, catalog.description, catalog.kind)
```

`kind` is one of `"tabular"`, `"multidimensional"` or `"unknown"`. It is derived from
`DBSCHEMA_CATALOGS.TYPE` — **`TYPE`, not `CATALOG_TYPE`**, which no server emits — using two
observations from a live SQL Server 2022 pair: the tabular instance reports `3` and the
multidimensional one `0`. Any other value reports `"unknown"`.

Two things deliberately *not* done here:

- **`COMPATIBILITY_LEVEL` is not consulted.** Multidimensional databases use 1050/1100/1103,
  so any MD database created on SQL Server 2012 or later reports 1100+ and a
  ">= 1100 means tabular" rule labels it tabular. Confidently wrong is worse than `"unknown"`.
- **No probing request is issued to settle it.** `DISCOVER_CSDL_METADATA` succeeds for tabular
  and faults for multidimensional, which does distinguish them — but that is a request, not a
  field, and it belongs to the caller rather than to row parsing.

If you need the kind reliably, issue that probe yourself:

```python
from ssas_xmla import ServerError

def is_tabular(session, catalog: str) -> bool:
    try:
        session.discover("DISCOVER_CSDL_METADATA", catalog=catalog)
        return True
    except ServerError:
        return False
```

## Values are strings

A `Rowset` carries ordered `columns` and `rows` of **string** values. Interpreting them —
types, nullability, coercion — is the caller's business; the library does not guess at a type
mapping that every consumer would then have to undo.

```python
rows = session.columns("Retail")
len(rows)          # row count
rows.columns       # ordered column names
for row in rows:   # dicts keyed by column name
    ...
```

## Large responses

A `DBSCHEMA_COLUMNS` on a modest model returns well over a thousand rows, and a response that
size gets split three independent ways — sealed-frame chunking, DIME record chunking, and
plain TCP fragmentation. All three compose, all three are handled below the API, and none of
them is visible here. The mechanics are in [The protocol](../protocol/index.md#how-messages-get-split).
