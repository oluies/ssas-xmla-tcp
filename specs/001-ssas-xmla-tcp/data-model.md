# Phase 1 Data Model

The library holds no persistent storage. These are the in-memory entities the protocol layers
exchange, derived from the spec's Key Entities.

## ConnectionTarget

Where to connect and how long to wait.

| Field | Meaning | Validation |
|---|---|---|
| `host` | Hostname or address of the instance | Non-empty |
| `port` | TCP port; pinned, never discovered (D4) | 1–65535 |
| `timeout` | Seconds bounding every network wait (FR-009) | > 0; no unbounded option exists |

No default port. A default would invite guessing between a default instance's well-known port
and a named instance's pinned one, and guessing wrong presents as a hang.

## Credential

What the security layer authenticates with. The library never reads or stores these itself
(constitution): it names a principal and lets the security layer resolve it from the ambient
ticket cache, keytab or environment.

| Field | Meaning |
|---|---|
| `mechanism` | Kerberos or NTLM |
| `principal` | Optional; omitted means "use the ambient identity" |
| `service` | The target service name the token is requested for |

**Never carries a password field.** Where NTLM needs one, it is supplied to the security layer
directly and is not retained on this object — so no code path can log a credential by
logging a `Credential`.

## NegotiatedTerms

Settled once per session during framing negotiation, immutable thereafter.

| Field | Meaning |
|---|---|
| `content_type` | `text/xml` in this milestone (D2) |
| `request_binary` / `response_binary` | Both false in this milestone |
| `request_compressed` / `response_compressed` | Both false in this milestone |
| `protection` | Whether the security layer turned on message protection |

Recorded as data rather than assumed, so FR-012 can report exactly what a server settled on
when it differs from what was requested.

## Session

An authenticated conversation, from handshake to close.

| Field | Meaning |
|---|---|
| `target` | The `ConnectionTarget` |
| `terms` | The `NegotiatedTerms` |
| `state` | `unconnected → negotiated → authenticated → closed`, plus `failed` |

**State transitions**: negotiation precedes authentication; only an `authenticated` session
accepts metadata or query requests. A `failed` session is terminal and is never retried in
place — a caller opens a new one, so a half-authenticated session can never serve a request.

## Message

One logical request or response, possibly split across several framing records.

| Field | Meaning |
|---|---|
| `payload` | The SOAP envelope bytes |
| `content_type` | As negotiated |
| `records` | How many framing records carried it |

Chunking is a framing concern: a sequence is contained within one message and never spans
messages, so the reassembly boundary is well defined.

## Catalog

A model within an instance, as reported by the server.

| Field | Meaning |
|---|---|
| `name` | Catalog name |
| `kind` | Tabular or multidimensional |

Only catalogs the account may see appear. An empty list is a valid answer meaning "none
visible", and is reported distinctly from a refusal (FR-007).

## Rowset

The shape every metadata and query response reduces to: ordered column names plus rows of
values. Deliberately untyped at this layer — interpreting values belongs to the caller, and
the connector already owns that mapping for its own purposes.

## ProtocolError

The four categories of FR-007, kept distinct because they demand different operator actions.

| Category | Means | Operator action |
|---|---|---|
| `ConnectionError` | Never reached a server | Check host, port, firewall |
| `AuthenticationError` | Reached it; identity not established | Check ticket, keytab, principal |
| `AuthorizationError` | Identity established; access refused | Check account permissions |
| `ServerError` | Server understood and rejected the request | Read the server's own message |
| `NegotiationError` | Server declined the requested encoding (FR-012) | Re-estimate scope — see D2 |

Each carries the server's own explanation where one exists (FR-008), scrubbed of identifying
tokens before it reaches a log or a caller (FR-010).
