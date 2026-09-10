---
title: Development
sidebar_position: 9
---

# Development

```bash
git clone https://github.com/oluies/ssas-xmla-tcp
cd ssas-xmla-tcp
pip install -e ".[dev]"
```

## The test suite

```bash
pytest                                    # offline suite, sockets disabled
pytest --cov --cov-report=term-missing    # with coverage
./tests/hooks/test_leak_gate.sh           # the commit gate's boundary cases
```

**Sockets are disabled by default**, and the suite must pass on a machine that has never
contacted an Analysis Services instance. That is a governing principle of the project, not a
convenience: it is what makes the byte seam worth having.

Anything needing a live server is marked `integration`, is skipped unless `SSAS_HOST` and
friends are set, and is granted socket access explicitly:

```bash
export SSAS_HOST=... SSAS_PORT=...       # the instance's PINNED port
export SSAS_MECHANISM=ntlm SSAS_PRINCIPAL=...
export SSAS_PASSWORD=...                 # standalone servers only; never on the command line
pytest -m integration
```

Coverage has a floor, and the floor is a **ratchet, not a target**: it exists so a future
change cannot quietly delete coverage. Raise it when the real number rises; never lower it to
make a red build green.

## CI

| Job | What it asserts |
|---|---|
| `ruff` | `ruff check` and `ruff format --check`, at the version pinned in `pyproject.toml` |
| offline suite | the full suite under coverage on Python 3.10, 3.11, 3.12 and 3.13, sockets disabled |
| dependency surface | `[project.dependencies]` is **exactly** `pyspnego` — the declared set, not merely that an install succeeded |
| leak gate | every tracked file scanned for host / IP / SID / connection-string tokens |
| docs build | `website/` builds with broken links treated as errors |

The dependency-surface job checks the *declaration* on purpose. An earlier version installed
whatever was declared and would have gone green after a platform SDK was added.

## Fixtures

Handshake fixtures are **synthesized, never captured**. A GSS/SPNEGO token carries the
principal, the realm, the target service and often the machine name; a committed capture is a
disclosure that merely looks like an opaque blob, and no scrubber can reliably redact
arbitrary token structure.

Captures of *post*-authentication traffic are permitted, and are scrubbed:

```bash
python tools/capture.py --host ... --port ... --out tests/fixtures/
```

Every capture passes the leak gate before it is committed. Regenerating fixtures means
re-running that check.

The gate refuses **binaries** by default, because `grep -I` skips them and would otherwise
report clean on a file it never read. A binary reviewed by eye is recorded in
`.leakgate-allow` as a `sha256  path` pair — the digest is the point, so replacing the file
re-arms the gate.

## The docs site

This site lives in `website/` and is a Docusaurus project.

```bash
cd website
npm ci
npm start          # local dev server with hot reload
npm run build      # what CI builds; broken links fail the build
```

`docs-build.yml` builds it on every pull request that touches `website/`. `pages.yml`
publishes it to GitHub Pages from `main`. The two never run together: `pages.yml` holds the
Pages concurrency group and the `github-pages` environment, so a pull-request run there would
cancel an in-flight deploy.

Pages are ordinary Markdown under `website/docs/`, with the navigation in `website/sidebars.ts`.
Internal links must be **relative file links** (`../reference/errors.md`) — the build resolves
and validates them, and `onBrokenLinks` is `throw`.

One editorial rule carries over from the repository: **what is UNVERIFIED stays UNVERIFIED**.
The site restates the project's claims for a reader who has not cloned it; it does not upgrade
any of them.

## Where the reasoning lives

- `docs/discovery-brief.md` — the protocol research, with normative citations. Claims that
  could not be confirmed are marked **UNVERIFIED**.
- `docs/open-questions.md` — the post-authentication framing investigation, including the
  hypotheses that were refuted.
- `specs/001-ssas-xmla-tcp/` — spec, plan, research decisions, data model, contract.
- `.specify/memory/constitution.md` — the governing principles. Two are non-negotiable.
- `ARCHITECTURE.md` — how the layers fit together.
