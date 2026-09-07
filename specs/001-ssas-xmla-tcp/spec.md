# Feature Specification: Native XMLA/TCP client for Analysis Services

**Feature Branch**: `001-ssas-xmla-tcp`

**Created**: 2026-09-07

**Status**: Draft

**Input**: A pure-Python client library for SQL Server Analysis Services over the native XMLA/TCP binding, removing the IIS/msmdpump dependency for non-Windows consumers.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Prove the connection is reachable at all (Priority: P1)

An integrator on Linux has an Analysis Services instance they can reach on the network and a
domain account that may read it. They have no IIS in front of it and cannot get one. They run
a single command naming the host, the port and the account, and learn within seconds whether
a metadata conversation is possible — a list of the server's data sources, or a plain
statement of what refused them.

**Why this priority**: This is the whole risk of the project in one slice. Every unknown that
could sink the effort — whether the framing is right, whether a plain-text conversation is
accepted, whether the security handshake completes from a non-Windows host — is either
settled or exposed by this one exchange. Nothing else is worth building until it succeeds,
and if it cannot succeed the project should stop here having spent days rather than weeks.

**Independent Test**: Run the probe against a live instance with a valid read-only account and
observe a data source listing. Delivers immediate standalone value: it is the diagnostic that
tells an operator whether their instance is reachable without IIS.

**Acceptance Scenarios**:

1. **Given** a reachable instance and a valid domain account, **When** the integrator runs the
   probe, **Then** they see the server's data sources listed and a clear success indication.
2. **Given** a reachable instance and an account with no read permission, **When** the probe
   runs, **Then** it reports that the account was refused, distinctly from a network failure.
3. **Given** an unreachable host or wrong port, **When** the probe runs, **Then** it reports a
   connection failure naming which stage failed, and never hangs indefinitely.
4. **Given** a server that refuses a plain-text conversation, **When** the probe runs, **Then**
   it says so explicitly rather than failing obscurely, because that answer determines whether
   the project needs a substantially larger scope.

---

### User Story 2 - Read a model's structure (Priority: P2)

A data engineer points the library at an instance and retrieves the shape of the models it
holds — the catalogs, their tables or cubes, the columns and their types — without installing
Windows components and without an intermediary web server.

**Why this priority**: This is the first genuinely useful capability, and the one that lets an
existing metadata consumer switch bindings. It depends entirely on Story 1 having succeeded.

**Independent Test**: Against a live instance, retrieve a catalog listing and the structure of
one model, and compare it field by field with what the same instance returns over its web
binding. Equivalence is the pass condition.

**Acceptance Scenarios**:

1. **Given** an authenticated connection, **When** the engineer requests the catalog list,
   **Then** they receive every catalog their account may see, and no others.
2. **Given** a named catalog, **When** the engineer requests its structure, **Then** the
   result matches what the same account sees over the web binding.
3. **Given** a request for information the account may not read, **When** it is issued,
   **Then** the refusal is surfaced as a refusal, with no partial or silently empty result.

---

### User Story 3 - Query a model and use the library in other tools (Priority: P3)

A tool author embeds the library to run analytic queries against a model and receive rows
back, and to build their own integration on a documented, stable interface.

**Why this priority**: This turns a working transport into a reusable component and is what
makes the library valuable beyond its first consumer. It is deliberately last because it is
ordinary work once Stories 1 and 2 hold.

**Independent Test**: Issue an analytic query through the public interface and receive the
same rows the same query returns through an established client.

**Acceptance Scenarios**:

1. **Given** an authenticated connection, **When** a valid analytic query is issued, **Then**
   rows are returned matching an established client's result for the same query.
2. **Given** a malformed query, **When** it is issued, **Then** the server's own explanation
   is surfaced to the caller rather than being swallowed.
3. **Given** a long-running query, **When** the caller has set a time limit, **Then** the call
   ends at that limit and reports having done so.

---

### Edge Cases

- A server insists on an encoding or compression the client did not ask for.
- The security handshake needs several round trips, or completes but then requires every
  later message to be protected.
- Credentials are valid but expire mid-session, on a long metadata sweep.
- The account is valid for the host but has no rights to the instance.
- A response is large enough to be split across many chunks, or arrives split differently
  than expected.
- A named instance's port has moved since it was last recorded.
- The connection drops midway through a response.
- A model contains catalogs the account may see and catalogs it may not.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The library MUST establish an authenticated session with an Analysis Services
  instance over its native network binding, without requiring a web server in front of it.
- **FR-002**: The library MUST authenticate using an existing domain credential, supporting
  both Kerberos and NTLM. Anonymous access is out of scope.
- **FR-003**: The library MUST run on Linux without any Windows-only or .NET component, since
  removing that dependency is the entire purpose.
- **FR-004**: The library MUST retrieve metadata about an instance and the models it holds.
- **FR-005**: The library MUST execute read-only analytic queries and return their rows.
- **FR-006**: The library MUST NOT offer any operation that creates, alters, refreshes or
  deletes server-side objects.
- **FR-007**: The library MUST distinguish, in what it reports, between a network failure, an
  authentication failure, an authorization refusal, and a server-side error about the request.
- **FR-008**: The library MUST surface the server's own explanation when the server rejects a
  request, rather than replacing it with a generic message.
- **FR-009**: The library MUST apply a caller-configurable time limit to every network wait
  and MUST NOT block indefinitely under any failure.
- **FR-010**: The library MUST NOT write credentials, hostnames, addresses, account names,
  machine names or security identifiers into any log line, error message or recorded fixture.
- **FR-011**: The library MUST let a caller address a named instance whose port is known in
  advance, without depending on a discovery service.
- **FR-012**: The library MUST report clearly when a server declines the message encoding it
  requested, because that outcome changes the project's scope.
- **FR-013**: The automated test suite MUST pass with no network access, running against
  recorded exchanges rather than a live server.
- **FR-014**: The library MUST be installable and usable without the presence of any other
  metadata platform or its dependencies.
- **FR-015**: The library MUST provide a documented interface that a third-party tool can
  build on, with published behaviour for each failure in FR-007.

### Key Entities

- **Instance**: A running Analysis Services server, addressed by host and port, holding
  catalogs. May be a default or a named instance.
- **Session**: An authenticated conversation with an instance, from credential exchange to
  close, carrying negotiated terms that hold for its lifetime.
- **Catalog**: A model within an instance — tabular or multidimensional — that an account may
  or may not be permitted to see.
- **Metadata request**: A read-only enquiry about an instance or catalog, returning rows.
- **Query**: A read-only analytic request against a catalog, returning rows.
- **Recorded exchange**: A captured request/response pair, stripped of every identifying
  token, that lets the suite run without a server.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An integrator with a reachable instance and valid credentials gets a definitive
  reachable-or-not answer within 30 seconds of their first command, having installed nothing
  beyond the library itself.
- **SC-002**: A Linux host with no Windows or .NET components installed can read model
  metadata that previously required a web server in front of the instance.
- **SC-003**: Metadata retrieved over the native binding matches, field for field, what the
  same account retrieves for the same models over the web binding.
- **SC-004**: The full automated suite passes with networking disabled, on a machine that has
  never contacted an Analysis Services instance.
- **SC-005**: Every one of the four failure categories in FR-007 produces a message that names
  which stage failed, verified by a test per category.
- **SC-006**: A reviewer scanning the repository finds no credential, hostname, address,
  account name, machine name or security identifier in any committed file.
- **SC-007**: The existing metadata connector reads the same models through this library as it
  does through its web binding, with no change to how its results are configured or consumed.
- **SC-008**: A third-party developer can go from install to a first successful metadata read
  using only the published documentation.

## Assumptions

- The instance is a **named instance pinned to a known static port**. Port discovery is
  deliberately excluded from this feature: the redirector's wire format has no public
  specification (see `docs/discovery-brief.md`), a firewall rule is needed either way, and
  pinning the port costs the operator nothing. Discovery may follow once the exchange has been
  observed empirically.
- A plain-text message encoding will be accepted. The governing specification declares richer
  encodings optional and negotiated, but an overview document asserts they are used. FR-012
  exists precisely so this assumption fails loudly and early. **If it fails, scope grows
  materially** and the milestone must be re-estimated before continuing.
- The account is read-only, consistent with FR-006, and the instance is reachable from where
  the library runs — a matter of firewall configuration, not of this feature.
- Recorded exchanges can be captured from a live instance during development and scrubbed
  before being committed.
- Transport-level encryption is whatever the security handshake settles on. Where the server
  requires later messages to be protected, the library honours it; it does not offer its own
  independent encryption.
- Server-side write operations are permanently out of scope, not merely deferred.
- The first consumer is the existing Analysis Services metadata connector, but no requirement
  here depends on it, and the library takes no dependency on it or on its platform.
