"""Integration tests need a live instance and are excluded from the default run.

Configure with environment variables; without them every test here skips, so the
offline suite stays hermetic (constitution III):

    SSAS_HOST       hostname or address of the instance
    SSAS_PORT       its PINNED tcp port (this client does not use the redirector)
    SSAS_PRINCIPAL  optional; omit to use the ambient Kerberos identity
    SSAS_MECHANISM  kerberos (default) or ntlm
    SSAS_CATALOG    optional catalog for the query tests
"""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(items):
    """Let integration tests use the network.

    `addopts` disables sockets for the WHOLE run, not just the unit suite, so
    without this every integration test errors with SocketBlockedError the moment
    SSAS_HOST is set -- they were unrunnable as written.
    """
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(pytest.mark.enable_socket)


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is not set; integration tests need a live instance")
    return value


@pytest.fixture(scope="session")
def live_target():
    return _require("SSAS_HOST"), int(_require("SSAS_PORT"))


@pytest.fixture(scope="session")
def live_credential():
    from ssas_xmla import Credential

    return Credential(
        mechanism=os.environ.get("SSAS_MECHANISM", "kerberos"),
        principal=os.environ.get("SSAS_PRINCIPAL") or None,
    )


@pytest.fixture
def live_session(live_target, live_credential):
    from ssas_xmla import connect

    host, port = live_target
    with connect(host, port, credential=live_credential) as session:
        yield session
