# Phase 0 Research: Native XMLA/TCP client

Grounding evidence is in `docs/discovery-brief.md`; this records the *decisions* taken from
it. Nothing here restates the specification — it records what was chosen and what was
rejected.

## D1: Framing — implement DIME directly

**Decision**: Write the DIME codec in this repository rather than depend on `python-dime` or
generate one from the Kaitai Struct spec.

**Rationale**: The record layout is small and fully specified — a fixed header of bit flags
plus four length fields with 4-byte padding. Against that, `python-dime` is archived, and a
Kaitai-generated parser adds a code-generation step and a runtime dependency to save perhaps
two hundred lines. Principle IV also requires each emitted byte to be traceable to normative
text at the point of implementation, which is easier to honour in code we write and comment
than in generated code.

**Alternatives considered**: `python-dime` (archived, unmaintained); Kaitai Struct generation
(build-step and runtime dependency, weakens spec traceability). Both remain useful as
cross-checks when debugging a disagreement with a real server.

## D2: Content type — negotiate clear text, and fail loudly if refused

**Decision**: Request `text/xml` with no binary XML and no compression, by setting the OPTIONS
negotiation bits accordingly. Treat a server that declines as a first-class, reported outcome
rather than an error to retry around.

**Rationale**: This removes [MS-BINXML] and XPRESS from the milestone entirely, which is the
single largest scope reduction available. The specification permits it: both are optional and
negotiated. But an overview document asserts the protocols "use binary XML", so the assumption
is not safe — and an assumption this load-bearing must fail visibly. FR-012 exists for exactly
this.

**Alternatives considered**: Implementing binary XML up front (weeks of work that may be
unnecessary); silently falling back to it (hides the very signal the milestone exists to
obtain).

**If refused**: stop, re-estimate, and treat [MS-BINXML] as a new feature. Do not absorb it
into this one.

## D3: Authentication — `pyspnego`, single loop for both mechanisms

**Decision**: Use `pyspnego` to generate security tokens, driving one exchange loop that
serves Kerberos and NTLM without branching on mechanism.

**Rationale**: The specification describes a mechanism-agnostic exchange — send a token,
receive a token, repeat until the security layer reports completion. `pyspnego` presents
exactly that shape and supports both required mechanisms on Linux, so NTLM costs almost
nothing once Kerberos works. Writing SPNEGO by hand would be a second protocol project.

**Alternatives considered**: `python-gssapi` (Kerberos-capable but a heavier build dependency
and no comparable NTLM story); hand-rolled SPNEGO (rejected outright).

**Open**: whether the negotiated context turns on message protection. If it does, every later
message needs wrapping and unwrapping. `pyspnego` supports this; it is extra work, not a
blocker. The spike settles it.

## D4: Instance addressing — pinned port only

**Decision**: Accept host and port. No discovery service, no redirector.

**Rationale**: The redirector's wire format has no public specification (see the brief), so
implementing it would mean reverse engineering — which Principle IV forbids as a starting
point. An operator can pin a named instance to a static port in server configuration, and a
firewall rule is required either way, so pinning costs nothing. This converts an unspecified
protocol into a configuration step.

**Alternatives considered**: Observing the redirector exchange and implementing from capture
(possible later, once there is a fixture to reason about, but not a foundation to build a
milestone on).

## D5: Testability — inject a byte-level seam, not a stub server

**Decision**: The transport takes an injected object exposing send and receive of bytes,
defaulting to a real socket. Tests supply recorded bytes.

**Rationale**: Satisfies Principle III with no live server and no stub process to run,
supervise or keep in sync. Every layer above the socket becomes ordinary unit-testable code.
This is the pattern already proven one layer higher in `ssas-openmetadata-connector`, whose
injectable transport is what makes its parsers testable offline.

**Alternatives considered**: A local stub server (a process to manage, and it would have to
implement the protocol correctly to be useful — testing the implementation against itself);
mocking the socket module (brittle, couples tests to standard-library internals).

## D6: Handshake fixtures — synthesize, never capture

**Decision**: Fixtures covering the authentication exchange use synthetic token bytes.
Captured fixtures are limited to post-authentication message exchanges, and are scrubbed.

**Rationale**: This is Principle I applied to a binary protocol, and it is the finding most
likely to be missed. A security token is not opaque padding: it carries the principal, the
realm, the target service name and often the machine name. Committing a real handshake capture
would be a disclosure that looks like a blob. Synthesizing removes the risk at the source
rather than relying on a scrubber to find structure inside binary data.

**Alternatives considered**: Capturing and scrubbing handshake tokens (a scrubber cannot
reliably parse and redact arbitrary token structures — the safe version of this is not to hold
the bytes at all).

## D7: Dependency surface — one runtime dependency

**Decision**: `pyspnego` only. Sockets, framing and XML come from the standard library.

**Rationale**: The constitution makes a minimal dependency surface a hard requirement, and
that requirement is why this repository exists apart from the connector. A protocol library
that drags in a platform SDK is not reusable by the audience it is for.

**Alternatives considered**: An XML library such as `lxml` (the standard library's parser is
sufficient for rowsets, and this is the connector's existing experience too).
