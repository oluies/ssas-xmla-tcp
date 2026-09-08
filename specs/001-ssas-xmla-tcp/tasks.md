# Tasks: Native XMLA/TCP client for Analysis Services

**Feature**: `001-ssas-xmla-tcp` | **Plan**: [plan.md](./plan.md) | **Spec**: [spec.md](./spec.md)

**Tests are REQUIRED for this feature.** Not by preference — constitution Principle III
(Offline-First Hermetic Tests) is NON-NEGOTIABLE and FR-013 requires the suite to pass with no
network. Test tasks are therefore first-class, not optional extras.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable — different file, no dependency on an incomplete task
- **[US1/US2/US3]**: the user story a task serves; absent for Setup, Foundational and Polish

## Path Conventions

Library code in `src/ssas_xmla/`, tests in `tests/`, developer tooling in `tools/`.
`tools/` is deliberately outside `src/` — it touches a live credentialed server and must not
be importable from the shipped library.

---

## Phase 1: Setup (Shared Infrastructure)

- [ ] T001 Create `pyproject.toml` with hatchling backend, `requires-python = ">=3.10"`, the single runtime dependency `pyspnego`, and a `dev` extra of `pytest`, `pytest-socket`, `ruff`
- [ ] T002 [P] Create the package skeleton `src/ssas_xmla/__init__.py` with `__version__` and an empty public surface
- [ ] T003 [P] Configure ruff in `pyproject.toml` (line-length 100, select E/F/I/B/UP) matching the connector's settings
- [ ] T004 Create `tests/conftest.py` enabling `--disable-socket --allow-unix-socket` by default and exposing a fixture loader that reads bytes from `tests/fixtures/`
- [ ] T005 [P] Create `.github/workflows/ci.yml` running lint and the offline suite on Python 3.10–3.12, with no network access and no service containers

**Checkpoint**: `pytest` runs green on an empty suite with sockets disabled.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Blocking**: every user story depends on this phase. No story work starts until the checkpoint holds.

- [ ] T006 Implement the five error categories of FR-007 in `src/ssas_xmla/errors.py`: `ConnectionError`, `AuthenticationError`, `AuthorizationError`, `ServerError`, `NegotiationError`, each carrying an optional server-supplied explanation
- [ ] T007 [P] Implement token scrubbing in `src/ssas_xmla/redact.py` — strip host, address, principal, realm, service principal name, machine name and security identifier from any text before it reaches a log or an exception (FR-010)
- [ ] T008 [P] Write `tests/unit/test_redact.py` asserting each identifying token class is removed, including a realm-qualified principal and a NetBIOS-style machine name
- [ ] T009 Implement DIME record encode/decode in `src/ssas_xmla/dime.py`: 5-bit VERSION fixed at 1, MB/ME/CF/TYPE_T flags, OPTIONS/ID/TYPE/DATA lengths each padded to a 4-byte boundary, citing the [MS-SSAS] TCP section at each field
- [ ] T010 Implement content-type negotiation in `src/ssas_xmla/dime.py`: the first OPTIONS byte (NEGO, REQ_SX, REQ_XPRESS, RESP_SX, RESP_XPRESS), requesting `text/xml` with binary and compression off (D2)
- [ ] T011 [P] Write `tests/unit/test_dime.py` covering round-trip encode/decode, a chunked sequence reassembling within one message, the 4-byte padding boundaries, and a rejected VERSION other than 1
- [ ] T012 [P] Write `tests/unit/test_negotiation.py` asserting the requested OPTIONS bits, and that a server response selecting binary XML or compression raises `NegotiationError` rather than being accepted (FR-012)
- [ ] T013 Implement `src/ssas_xmla/transport.py` with an injected send/receive byte seam defaulting to a real socket, applying a caller-supplied timeout to every wait so nothing blocks indefinitely (FR-009)
- [ ] T014 [P] Write `tests/unit/test_transport.py` driving the seam from recorded bytes, asserting timeout enforcement and that a mid-response disconnect raises `ConnectionError`
- [ ] T015 Build the synthetic handshake-token generator in `tests/fixtures/synth.py` — handshake fixtures are **synthesized, never captured** (D6, constitution I); a real security token carries the principal, realm and target service
- [ ] T016 [P] Write `tests/unit/test_offline_gate.py` asserting the suite genuinely runs with sockets disabled, so a future regression cannot quietly reintroduce a network dependency

**Checkpoint**: framing and transport are exercisable on recorded bytes with sockets disabled.

---

## Phase 3: User Story 1 - Prove the connection is reachable (Priority: P1) 🎯 MVP

**Goal**: one successful `DISCOVER_DATASOURCES` round trip against a live named instance at a pinned port.

**Independent test**: run the probe against a live instance with a read-only account and see its data sources listed; every failure mode names the stage that failed.

**This phase carries the project's entire risk.** It exercises framing, negotiation and the security handshake at once. If it cannot pass, the project stops here having spent days.

### Tests for User Story 1

- [ ] T017 [P] [US1] Write `tests/unit/test_envelopes.py` asserting the `Authenticate` and `Discover` SOAP envelopes match the structure [MS-SSAS] specifies
- [ ] T018 [P] [US1] Write `tests/unit/test_auth.py` driving a multi-round-trip token exchange to completion using synthetic tokens from T015, and asserting no token or principal ever reaches a log record
- [ ] T019 [P] [US1] Write `tests/unit/test_client_session.py` asserting state moves `unconnected → negotiated → authenticated`, that a request on an unauthenticated session is refused, and that a failed session is terminal
- [ ] T020 [P] [US1] Write `tests/unit/test_error_categories.py` asserting each of the five categories is raised for its own condition, one test per category (SC-005)

### Implementation for User Story 1

- [ ] T021 [US1] Implement SOAP envelope construction for `Authenticate` and `Discover` in `src/ssas_xmla/envelopes.py`
- [ ] T022 [US1] Implement the GSS-API/SPNEGO exchange loop in `src/ssas_xmla/auth.py` using `pyspnego`, carrying tokens inside `Authenticate`/`AuthenticateResponse` until the mechanism reports completion, with one code path serving both Kerberos and NTLM (D3)
- [ ] T023 [US1] Detect in `src/ssas_xmla/auth.py` whether the completed security context negotiated message protection, record it on the session terms in `src/ssas_xmla/client.py`, and wrap/unwrap subsequent messages when it is on
- [ ] T024 [US1] Implement `ConnectionTarget`, `Credential`, `NegotiatedTerms` and `Session` in `src/ssas_xmla/client.py` per `data-model.md`, with no password field on `Credential` so no code path can log a credential
- [ ] T025 [US1] Implement session open and close in `src/ssas_xmla/client.py`, sequencing negotiate → authenticate, supporting context-manager use, and making close idempotent
- [ ] T026 [US1] Implement `discover_datasources()` in `src/ssas_xmla/client.py` — the single exchange this milestone exists to prove
- [ ] T027 [US1] Implement the probe CLI in `src/ssas_xmla/probe.py` taking `--host` and `--port`, printing the data sources or the failure category, per `quickstart.md`
- [ ] T028 [US1] Write `tools/capture.py` to record post-authentication exchanges against a live instance, scrubbing before writing and never recording handshake tokens (D6)
- [ ] T029 [US1] Capture and commit scrubbed `DISCOVER_DATASOURCES` fixtures under `tests/fixtures/xmla/`, then re-run the leak gate
- [ ] T030 [US1] Add a live integration test in `tests/integration/test_live_discover.py`, marked so it is excluded from the default offline run
- [ ] T031 [US1] Record the outcome of the clear-text negotiation in `docs/discovery-brief.md`, replacing the **UNVERIFIED** marker with observed fact — and if the server refused clear text, stop and re-estimate rather than absorbing [MS-BINXML] into this feature (D2)

**Checkpoint**: MVP. A Linux host with no Windows or .NET components reads from SSAS with no IIS in front of it.

---

## Phase 4: User Story 2 - Read a model's structure (Priority: P2)

**Goal**: retrieve catalogs and the structure of a model, matching what the HTTP binding returns.

**Independent test**: retrieve a catalog listing and one model's structure, and compare field by field against the same account's results over the HTTP binding.

### Tests for User Story 2

- [ ] T032 [P] [US2] Write `tests/unit/test_rowset.py` covering rowset parsing from recorded responses, including a namespaced rowset and an empty result
- [ ] T033 [P] [US2] Write `tests/unit/test_discover_metadata.py` asserting catalog listing, restriction handling, and that an empty listing is distinct from `AuthorizationError` (FR-007)

### Implementation for User Story 2

- [ ] T034 [US2] Implement XMLA rowset parsing in `src/ssas_xmla/rowset.py`, returning ordered column names plus rows, leaving value typing to the caller
- [ ] T035 [US2] Implement `Catalog` and generic `discover(request_type, restrictions)` in `src/ssas_xmla/client.py`
- [ ] T036 [US2] Implement catalog listing and per-catalog structure retrieval in `src/ssas_xmla/client.py`
- [ ] T037 [US2] Surface server-side rejections in `src/ssas_xmla/client.py` carrying the server's own explanation via `src/ssas_xmla/errors.py`, scrubbed, rather than a generic message (FR-008)
- [ ] T038 [P] [US2] Capture and commit scrubbed metadata fixtures under `tests/fixtures/xmla/`, re-running the leak gate
- [ ] T039 [US2] Add a parity test in `tests/integration/test_binding_parity.py` comparing native-binding metadata against the HTTP binding for the same account and models (SC-003), marked as integration

**Checkpoint**: metadata reads work and provably match the HTTP binding.

---

## Phase 5: User Story 3 - Query a model and expose a stable interface (Priority: P3)

**Goal**: run read-only analytic queries and offer a documented public interface others can build on.

**Independent test**: issue an analytic query through the public interface and get the same rows an established client returns for that query.

### Tests for User Story 3

- [ ] T040 [P] [US3] Write `tests/unit/test_execute.py` covering a successful query, a malformed query surfacing the server's own text, and timeout enforcement on a long-running query
- [ ] T041 [P] [US3] Write `tests/unit/test_readonly_surface.py` asserting **by construction** that no mutating command can be built or issued — no public entry point, argument or flag reaches one (constitution II)

### Implementation for User Story 3

- [ ] T042 [US3] Implement the `Execute` SOAP envelope in `src/ssas_xmla/envelopes.py` for read-only statements only
- [ ] T043 [US3] Implement `execute(statement, catalog)` in `src/ssas_xmla/client.py` returning a `Rowset`, with no code path that constructs a create, alter, refresh or delete command
- [ ] T044 [US3] Fix the public surface in `src/ssas_xmla/__init__.py` — exports, and the five guarantees from `contracts/public-api.md`
- [ ] T045 [P] [US3] Capture and commit scrubbed query-response fixtures under `tests/fixtures/xmla/`, re-running the leak gate
- [ ] T046 [US3] Add a live query test in `tests/integration/test_live_execute.py` comparing rows against an established client, marked as integration

**Checkpoint**: the library is usable by a third party for metadata and queries.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T047 [P] Write `README.md` — what this is, why it exists, the install and probe path from `quickstart.md`, and the pinned-port prerequisite
- [ ] T048 [P] Document each public entry point against `contracts/public-api.md`, so a third-party developer can go from install to a first metadata read on the docs alone (SC-008)
- [ ] T049 [P] Update `docs/discovery-brief.md` to resolve every remaining **UNVERIFIED** marker with what the fixtures now show, or state plainly that it is still open
- [ ] T050 Audit every log statement and exception path across `src/ssas_xmla/` for identifying tokens, and add `tests/unit/test_no_token_logging.py` failing if any token class reaches a log record (SC-006, constitution I)
- [ ] T051 [P] Assert the dependency surface in `tests/unit/test_dependency_surface.py` — `pyspnego` plus the standard library only, and the library imports with nothing else installed
- [ ] T052 [P] Add `.env.example` with placeholders for the integration-test target and confirm `.env` is listed in `.gitignore`
- [ ] T053 Run the full offline suite in `tests/` on a machine that has never contacted an Analysis Services instance and confirm it passes (SC-004)
- [ ] T054 Wire `ssas-openmetadata-connector`'s `src/ssas_om/client.py` to read through this library behind a feature switch, and confirm it returns the same models it reads over HTTP (SC-007)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)** → no dependencies
- **Phase 2 (Foundational)** → depends on Phase 1; **blocks all user stories**
- **Phase 3 (US1)** → depends on Phase 2
- **Phase 4 (US2)** → depends on Phase 3 (needs a working authenticated session)
- **Phase 5 (US3)** → depends on Phase 3; independent of Phase 4 in principle, though rowset parsing (T034) is shared and lands in Phase 4
- **Phase 6 (Polish)** → depends on the stories it documents; T054 depends on Phase 4

### User Story Dependencies

Unusually for this template, the stories are **not** independent. US2 and US3 both require an
authenticated session, which is US1's entire deliverable. This is inherent: a protocol stack
cannot be sliced so that a higher layer ships without the one beneath it. US1 is genuinely
independently valuable, though — it ships as a working diagnostic.

US2 and US3 are independent **of each other** and can proceed in parallel once US1 holds,
with the caveat that T034 (rowset parsing) is shared and is scheduled in US2.

### Within Each User Story

Tests before implementation. Models before the services using them. Fixtures before the tests
consuming them (T015 before T018; T029 before T030).

### Parallel Opportunities

- Phase 1: T002, T003, T005 in parallel after T001
- Phase 2: T007/T008 alongside T009; T011, T012, T014, T016 once their subjects exist
- Phase 3: T017–T020 in parallel (four different test files, no shared state)
- Phase 4: T032 and T033 in parallel
- Phase 6: T047, T048, T049, T051, T052 in parallel

## Parallel Example: User Story 1

```text
# The four US1 test files touch nothing in common — write them together:
T017 tests/unit/test_envelopes.py
T018 tests/unit/test_auth.py
T019 tests/unit/test_client_session.py
T020 tests/unit/test_error_categories.py
```

## Implementation Strategy

### MVP First (User Story 1 only)

Phases 1 → 2 → 3, then stop and evaluate. That is T001–T031, and it answers the only question
that matters: can a Linux host authenticate and read from SSAS over the native binding at all?

Two outcomes are both wins. It works, and US2/US3 become ordinary work on a proven foundation.
Or it does not, and the project ends after days rather than weeks — which is precisely why the
risky exchange is the first deliverable rather than the last.

### Incremental Delivery

1. **US1** ships a diagnostic tool useful on its own to any operator asking "is this instance reachable without IIS?"
2. **US2** ships metadata reads — the point at which the connector could switch bindings
3. **US3** ships queries and a stable public interface for third parties

### Decision Gate at T031

T031 is a stop-and-check, not a documentation chore. If the server refused clear-text
encoding, [MS-BINXML] and compression become required, and this feature must be re-estimated
before Phase 4 begins. Absorbing that silently would turn a bounded milestone into an open one.

## Notes

- One task per commit, reviewed before the next begins (constitution V).
- The leak gate runs on every commit and is never bypassed. Regenerating fixtures re-runs it.
- Any protocol claim not yet backed by a fixture stays marked **UNVERIFIED** in the docs. An
  assumption presented as fact is a defect.
