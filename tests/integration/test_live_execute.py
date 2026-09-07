"""T046: read-only query execution against a real instance."""

import os

import pytest

from ssas_xmla import ServerError

pytestmark = pytest.mark.integration


@pytest.fixture
def catalog():
    value = os.environ.get("SSAS_CATALOG")
    if not value:
        pytest.skip("SSAS_CATALOG is not set")
    return value


def test_a_trivial_dax_expression_evaluates(live_session, catalog):
    result = live_session.execute('EVALUATE ROW("one", 1)', catalog=catalog)
    assert len(result) == 1


def test_a_malformed_query_surfaces_the_servers_own_message(live_session, catalog):
    with pytest.raises(ServerError) as excinfo:
        live_session.execute("EVALUATE THIS IS NOT DAX", catalog=catalog)
    assert excinfo.value.detail
