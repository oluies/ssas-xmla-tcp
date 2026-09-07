# Implementation Plan: Native XMLA/TCP client for Analysis Services

**Branch**: `001-ssas-xmla-tcp` | **Date**: 2026-09-07 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-ssas-xmla-tcp/spec.md`

## Summary

Build a pure-Python client for the Analysis Services native TCP binding so Linux consumers can
read SSAS metadata without an IIS/`msmdpump` deployment in front of the instance.

The approach is layered and deliberately front-loads risk. A DIME framing codec carries SOAP
envelopes over a socket; a content-type negotiation settles on clear-text XML so that binary
XML and compression can be skipped; a GSS-API/SPNEGO handshake runs inside
`Authenticate`/`AuthenticateResponse` SOAP messages until the mechanism reports completion.
Milestone 1 stops the moment one `DISCOVER_DATASOURCES` round trip succeeds, because that
single exchange exercises every unknown at once. Only then do metadata reads (P2) and query
execution plus the public interface (P3) get built on top.

## Technical Context

**Language/Version**: Python 3.10+ (matching the first consumer's floor)

**Primary Dependencies**: `pyspnego` for GSS-API/SPNEGO token generation (Kerberos and NTLM).
Standard library only for sockets, framing and XML. No platform SDK, per constitution.

**Storage**: N/A — the library holds no persistent state. Recorded fixtures are test data.

**Testing**: `pytest` with `pytest-socket` (`--disable-socket`), against byte-level fixtures.

**Target Platform**: Linux primarily; no Windows-only or .NET component on any platform.

**Project Type**: Single library, importable and independently installable.

**Performance Goals**: Not a throughput project. The one binding constraint is FR-009: every
network wait is bounded by a caller-configurable timeout and nothing blocks indefinitely.

**Constraints**: Clear-text XML negotiation only in M1 — if a server refuses it, scope changes
materially and the milestone is re-estimated rather than silently expanded (FR-012). Named
instance at a statically pinned port; no port discovery. Read-only operations only.

**Scale/Scope**: M1 is one round trip. The full library covers three operations
(`Authenticate`, `Discover`, `Execute`) and rowset parsing.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Status |
|---|---|---|
| I. No Secret Leakage | Fixtures are raw authenticated-session bytes; every GSS token must be synthesized or scrubbed before commit | **PASS by design** — the fixture pipeline (Phase 1) synthesizes handshake tokens rather than capturing them, so no real token ever reaches disk. Non-handshake captures pass the leak gate. |
| II. Read-Only by Construction | No mutating operation may exist in the codebase | **PASS** — the public surface is `Discover` and read-only `Execute`. TMSL/`Create`/`Alter`/`Delete` command construction is absent, not merely unexposed. |
| III. Offline-First Hermetic Tests | Suite passes with sockets disabled | **PASS** — the socket is injected behind a byte-level seam (see Structure Decision); every layer is testable on recorded bytes. |
| IV. Spec-Governed Protocol Work | Every emitted byte traceable to normative text | **PASS** — `docs/discovery-brief.md` carries the citations; unresolved points are marked UNVERIFIED and are exactly what M1 settles. |
| V. Spec-Driven with Review Gates | Pipeline order, one task per commit | **PASS** — this plan follows a committed spec on its own branch. |

**No violations. Complexity Tracking is therefore omitted.**

One gate deserves emphasis rather than a tick. Principle I is the reason the handshake fixture
strategy is a design decision and not a testing detail: a captured SPNEGO token carries the
principal, realm and target service. The plan's answer is that handshake tokens are
**synthesized, never captured** — Phase 1 fixes this before any capture tooling is written.

## Project Structure

### Documentation (this feature)

```text
specs/001-ssas-xmla-tcp/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   └── public-api.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
src/ssas_xmla/
├── __init__.py          # public surface; version
├── dime.py              # DIME record encode/decode + content-type negotiation
├── transport.py         # socket lifecycle, timeouts, message send/receive
├── auth.py              # GSS-API/SPNEGO loop over Authenticate SOAP
├── envelopes.py         # SOAP envelope construction for the three operations
├── rowset.py            # XMLA rowset → rows
├── client.py            # session assembly; the documented public interface
└── errors.py            # the four failure categories of FR-007

tests/
├── conftest.py          # socket-disabled default; fixture loading
├── fixtures/
│   ├── dime/            # synthetic + captured records
│   └── xmla/            # scrubbed response bodies
└── unit/                # one module per src module

tools/
└── capture.py           # fixture capture against a live instance; scrubs before writing
```

**Structure Decision**: A single flat library package. Each protocol layer is one module with
one responsibility, ordered bottom-up so a lower layer never imports a higher one:
`dime` → `transport` → `auth` → `client`.

The critical structural choice is the **byte-level seam**. `transport.py` takes an injected
object exposing send/receive of bytes, defaulting to a real socket. Every layer above it is
therefore exercisable against recorded bytes with sockets disabled, satisfying Principle III
without a live server or a stub process. This mirrors the injectable-transport pattern that
already works in `ssas-openmetadata-connector`, one layer lower down the stack.

`tools/capture.py` is deliberately outside `src/`: it is developer tooling that touches a live
credentialed server, and it must not be importable from the shipped library.
