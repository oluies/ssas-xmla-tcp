"""Connection probe: the whole of milestone 1, and a useful diagnostic on its own.

Answers one question for an operator — is this instance readable over the native
binding, with no IIS in front of it? — and names the stage that failed if not.
"""

from __future__ import annotations

import argparse
import os
import sys

from .auth import Credential
from .client import connect
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    NegotiationError,
    ServerError,
    SsasError,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ssas_xmla.probe",
        description="Check whether an Analysis Services instance is readable over TCP.",
    )
    parser.add_argument("--host", required=True)
    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="the instance's pinned TCP port; this client does not use the redirector",
    )
    parser.add_argument("--mechanism", default="kerberos", choices=["kerberos", "ntlm"])
    parser.add_argument("--principal", default=None)
    parser.add_argument("--service", default="MSOLAPSvc.3")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)

    credential = Credential(
        mechanism=args.mechanism, principal=args.principal, service=args.service
    )
    # From the environment, never argv: a password on the command line is visible
    # in the process list to every other user on the machine.
    password = os.environ.get("SSAS_PASSWORD") or None
    try:
        with connect(
            args.host,
            args.port,
            credential=credential,
            timeout=args.timeout,
            password=password,
        ) as session:
            result = session.discover_datasources()
    except NegotiationError as exc:
        print(f"NEGOTIATION FAILED: {exc}", file=sys.stderr)
        print(
            "The server declined clear-text XML. This changes the project's scope "
            "-- see D2 in specs/001-ssas-xmla-tcp/research.md before proceeding.",
            file=sys.stderr,
        )
        return 4
    except ConnectionError as exc:
        print(f"CONNECTION FAILED: {exc}", file=sys.stderr)
        print("Never reached a server. Check host, port and firewall.", file=sys.stderr)
        return 2
    except AuthenticationError as exc:
        print(f"AUTHENTICATION FAILED: {exc}", file=sys.stderr)
        print(
            "Reached the server; identity not established. Check ticket or keytab.", file=sys.stderr
        )
        return 3
    except AuthorizationError as exc:
        print(f"AUTHORIZATION REFUSED: {exc}", file=sys.stderr)
        print("Identity is fine; the account may not read. Check permissions.", file=sys.stderr)
        return 5
    except ServerError as exc:
        print(f"SERVER REJECTED THE REQUEST: {exc}", file=sys.stderr)
        return 6
    except SsasError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print(f"OK - {len(result)} data source(s):")
    for row in result:
        name = row.get("DataSourceName", "?")
        provider = row.get("ProviderName", "")
        print(f"  - {name}  {provider}".rstrip())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
