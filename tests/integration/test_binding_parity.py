"""T039 / SC-003: the native binding must return what the HTTP binding returns.

Needs both bindings configured for the same account and models. Skips unless
SSAS_HTTP_ENDPOINT is set as well, since the HTTP side is a separate deployment.
"""

import os

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def http_endpoint():
    value = os.environ.get("SSAS_HTTP_ENDPOINT")
    if not value:
        pytest.skip("SSAS_HTTP_ENDPOINT is not set; parity needs both bindings")
    return value


def test_catalog_listing_matches_the_http_binding(live_session, http_endpoint):
    """Compare catalog names field for field across the two bindings."""
    native = sorted(c.name for c in live_session.catalogs())
    # The HTTP side is deliberately fetched with the stdlib rather than by adding a
    # dependency: this test exists to compare, not to become a second client.
    import base64
    import urllib.request

    body = (
        b'<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
        b'<Discover xmlns="urn:schemas-microsoft-com:xml-analysis">'
        b"<RequestType>DBSCHEMA_CATALOGS</RequestType>"
        b"<Restrictions><RestrictionList/></Restrictions>"
        b"<Properties><PropertyList/></Properties>"
        b"</Discover></Body></Envelope>"
    )
    request = urllib.request.Request(
        http_endpoint,
        data=body,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"urn:schemas-microsoft-com:xml-analysis:Discover"',
        },
    )
    user = os.environ.get("SSAS_HTTP_USER")
    password = os.environ.get("SSAS_HTTP_PASSWORD")
    if user and password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode("utf-8", errors="replace")

    from ssas_xmla import rowset

    http = sorted(row["CATALOG_NAME"] for row in rowset.parse(text) if row.get("CATALOG_NAME"))
    assert native == http
