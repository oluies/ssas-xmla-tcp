# ssas-xmla-tcp

A pure-Python client for the SQL Server Analysis Services **native XMLA/TCP binding**, so
Linux consumers can read SSAS metadata without an IIS/`msmdpump` deployment in front of the
instance. The vendor's clients for this binding are all Windows/COM/.NET; the one other
Linux implementation is hugr-lab/xmla-extention, an independent C++ DuckDB extension on
MIT krb5 that neither uses nor is used by this library.

<!-- SPECKIT START -->
Active plan: [specs/001-ssas-xmla-tcp/plan.md](specs/001-ssas-xmla-tcp/plan.md)
<!-- SPECKIT END -->

## Read these first

- `.specify/memory/constitution.md` — governing principles. Two are NON-NEGOTIABLE.
- `docs/discovery-brief.md` — the protocol research, with normative citations. Claims that
  could not be confirmed are marked **UNVERIFIED**; treat them as open questions, not facts.
- `specs/001-ssas-xmla-tcp/` — spec, plan, research decisions, data model, contract.

## Things that are easy to get wrong here

- **Binary fixtures are not opaque.** A GSS/SPNEGO token carries the principal, realm, target
  service and often the machine name. Handshake fixtures are **synthesized, never captured**.
- **Clear-text encoding is an assumption, not a fact.** The specification says binary XML and
  compression are optional and negotiated; an overview document says they are used. If a real
  server declines clear text, that is a scope change to report, not a fallback to absorb.
- **No port discovery.** The named-instance redirector on TCP 2382 has no public
  specification. Instances are addressed at a pinned port.
- **Dependency surface is one package.** `pyspnego`, plus the standard library. Pulling in a
  platform SDK is what this repository was separated from `ssas-openmetadata-connector` to
  avoid.
- **Read-only by construction.** Mutating operations must not exist in the codebase, not
  merely be unexposed.
- **The docs site restates, it does not upgrade.** `website/` publishes to
  https://oluies.github.io/ssas-xmla-tcp/. What is UNVERIFIED in `docs/discovery-brief.md`
  stays UNVERIFIED there. Internal links must be relative file links — `onBrokenLinks` is
  `throw`, and `docs-build.yml` is the PR gate.

## Related

`ssas-openmetadata-connector` is the first consumer — an OpenMetadata connector reading the
same servers over HTTP/`msmdpump`. This library takes no dependency on it.
