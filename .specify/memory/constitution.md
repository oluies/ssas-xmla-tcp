<!--
Sync Impact Report
- Version change: (none) → 1.0.0  (initial ratification for this project)
- Derived from the ssas-openmetadata-connector constitution v1.0.0; principles I, III
  and V carry over in spirit, II and IV are rewritten for a protocol library.
- Principles defined: I No Secret Leakage; II Read-Only by Construction; III Offline-First
  Hermetic Tests; IV Spec-Governed Protocol Work; V Spec-Driven with Review Gates
- Added sections: Security & Data-Handling Constraints; Development Workflow & Quality Gates
- Removed from the source constitution: the OpenMetadata version pin, the Hetzner fixture
  host, the msmdpump/HTTP-Basic transport note, and the docker/ssas-stub reference — none
  apply to a standalone protocol library.
- Templates reviewed for alignment:
    ✅ .specify/templates/plan-template.md  (Constitution Check gate references these principles)
    ✅ .specify/templates/spec-template.md   (no mandatory-section conflicts)
    ✅ .specify/templates/tasks-template.md  (test-discipline + review-gate task types covered)
- Deferred TODOs: none
-->

# ssas-xmla-tcp Constitution

## Core Principles

### I. No Secret Leakage (NON-NEGOTIABLE)

Credentials, hostnames, addresses, account names, realm and domain names, service principal
names, machine/NetBIOS names and security identifiers MUST come only from the environment or
a gitignored file, and MUST NEVER appear in a committed file, test fixture, log line, error
message or commit message.

This binds harder here than in a text protocol. Captured fixtures are **raw bytes of an
authenticated session**, and a GSS-API/SPNEGO token is a structured object carrying the
principal, the realm, the target service and often the machine name. A committed handshake
capture is therefore a disclosure unless every token is either synthesized or scrubbed. A
fixture containing a real security token MUST NOT be committed under any circumstance, and
the scrub MUST be re-verified whenever fixtures are regenerated.

Rationale: a byte-level capture looks opaque and is not. Treating binary fixtures as
inherently safe is the specific mistake this principle exists to prevent.

### II. Read-Only by Construction

The library MUST expose no operation that creates, alters, refreshes or deletes a
server-side object. This is a property of what the code contains, not of what callers
choose to call: an operation that could mutate server state MUST NOT exist in the codebase,
so no configuration, argument or mistake can reach one.

Rationale: the library authenticates with real domain credentials against production
analytic servers. Absence of the capability is the only guarantee that survives misuse.

### III. Offline-First Hermetic Tests (NON-NEGOTIABLE)

Unit tests MUST run with sockets disabled against recorded byte-level fixtures and MUST NOT
depend on any server being reachable. A unit-test run MUST pass on a machine that has never
contacted an Analysis Services instance. Live servers are for integration and acceptance runs
only, and those MUST be separable from the default suite.

Rationale: the target is a credentialed server inside someone's network. A suite that needs
it is not reproducible, cannot run in CI, and cannot be run by a contributor at all.

### IV. Spec-Governed Protocol Work

Every byte the library emits or accepts MUST be traceable to normative text in the Microsoft
Open Specifications, cited at the point of implementation. Blog posts, forum answers and
inference from other implementations are not sources.

Where observed bytes and the specification disagree, the observation wins and MUST be
recorded as a fixture with the divergence documented against the spec section it
contradicts — the specification's own product-behaviour appendix is the first place to look
before concluding the document is wrong. A behavioural assumption MUST be backed by a
fixture before code depends on it.

Rationale: this is a clean-room implementation of an undocumented-in-practice binding. Its
only defensible foundation is the published specification plus recorded evidence of what a
real server does.

### V. Spec-Driven with Review Gates

Work MUST proceed through the spec-kit pipeline (constitution → specify → clarify → plan →
tasks). Each implementation task MUST be committed on its own and reviewed before the next
begins.

Rationale: small reviewed increments catch defects early and keep spec and code aligned.

## Security & Data-Handling Constraints

- Credentials reach the library from the environment, a ticket cache or a keytab. The library
  MUST NOT read, write or persist a credential itself.
- Security tokens MUST NEVER be logged, at any level, in any form — not truncated, not
  hashed, not base64. The same applies to raw message bodies until they have been scrubbed.
- The library MUST NOT depend on any metadata platform, its SDK or its transitive
  dependencies. Keeping the dependency surface minimal is a hard requirement, not a
  preference: pulling a platform SDK into a protocol library is what this repository was
  separated from `ssas-openmetadata-connector` to avoid.
- The library MUST NOT require any Windows-only or .NET component, on any platform.
- Where the security layer negotiates message protection, the library MUST honour it and MUST
  NOT substitute or add encryption of its own design.

## Development Workflow & Quality Gates

- The leak-gate hook (`.githooks/pre-commit`) runs on every commit; a finding is a hard block,
  never bypassed for convenience.
- Regenerating fixtures MUST re-run the leak check, and a non-zero identifying-token count is
  a release blocker.
- Every commit is small and scoped to one task.
- A change that weakens a NON-NEGOTIABLE principle MUST be rejected in review.
- Unverified protocol claims MUST be marked as such in documentation until a fixture settles
  them. An assumption presented as fact is a defect.

## Governance

This constitution supersedes other practices for this project. Amendments MUST be recorded in
this file with a Sync Impact Report and a semantic-version bump: MAJOR for removing or
redefining a principle, MINOR for adding a principle or materially expanding guidance, PATCH
for clarifications that change no requirement.

**Version**: 1.0.0 | **Ratified**: 2026-09-07 | **Last Amended**: 2026-09-07
