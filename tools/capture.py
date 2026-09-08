#!/usr/bin/env python3
"""Record scrubbed fixtures from a live instance.

Deliberately outside src/: this touches a live credentialed server and must not be
importable from the shipped library.

TWO RULES, both non-negotiable (constitution I, research.md D6):

  1. Handshake tokens are NEVER captured. This tool records only post-authentication
     exchanges. A GSS/SPNEGO token carries the principal, realm and target service,
     and no scrubber can reliably redact arbitrary token structure -- so the safe
     version is not to hold the bytes at all. Synthetic handshake material lives in
     tests/fixtures/synth.py.
  2. Everything written passes the scrubber first, and the leak gate must be re-run
     after regenerating fixtures.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ssas_xmla.auth import Credential  # noqa: E402
from ssas_xmla.client import connect  # noqa: E402
from ssas_xmla.redact import make_scrubber  # noqa: E402

REQUESTS = [
    ("DISCOVER_DATASOURCES", "datasources"),
    ("DBSCHEMA_CATALOGS", "catalogs"),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--principal", default=None)
    parser.add_argument("--mechanism", default="kerberos", choices=["kerberos", "ntlm"])
    parser.add_argument("--out", default="tests/fixtures/xmla")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    scrub = make_scrubber(host=args.host, user=args.principal)
    credential = Credential(mechanism=args.mechanism, principal=args.principal)

    with connect(args.host, args.port, credential=credential) as session:
        for request_type, name in REQUESTS:
            try:
                result = session.discover(request_type)
            except Exception as exc:  # keep going; a refused rowset is still a finding
                print(f"  {request_type}: {type(exc).__name__}", file=sys.stderr)
                continue
            # Re-render rather than dumping raw bytes, so nothing unscrubbed escapes.
            lines = ["<rows>"]
            for row in result:
                cells = "".join(f"<{k}>{scrub(v)}</{k}>" for k, v in row.items())
                lines.append(f"  <row>{cells}</row>")
            lines.append("</rows>")
            path = out_dir / f"{name}.xml"
            path.write_text("\n".join(lines), encoding="utf-8")
            print(f"  wrote {path} ({len(result)} rows, scrubbed)")

    print("\nNow re-run the leak gate before committing:  .githooks/pre-commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
