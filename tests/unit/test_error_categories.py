"""SC-005: each of the failure categories, one test apiece."""

import pytest

from ssas_xmla import dime
from ssas_xmla.auth import Credential
from ssas_xmla.client import connect
from ssas_xmla.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    NegotiationError,
    ServerError,
)
from ssas_xmla.transport import BytesChannel
from tests.fixtures import synth
from tests.unit.test_client_session import DoneContext, sealed


def _authed_channel(*payloads):
    ch = BytesChannel()
    ch.queue(synth.dime_message(synth.AUTHENTICATE_RESPONSE.format(token="").encode()))
    for p in payloads:
        ch.queue(synth.dime_message(sealed(p.encode())))
    return ch


def test_connection_error_when_the_stream_ends_early():
    ch = BytesChannel(synth.dime_message(b"partial")[:-8])
    with pytest.raises(ConnectionError):
        connect("h", 2383, channel=ch, context=DoneContext())


def test_authentication_error_when_the_context_fails():
    class Boom:
        protection = False
        complete = False

        def step(self, in_token=None):
            raise RuntimeError("no key")

    with pytest.raises(AuthenticationError):
        connect("h", 2383, channel=BytesChannel(), context=Boom())


def test_authorization_error_for_an_access_denied_fault():
    ch = _authed_channel(synth.SOAP_FAULT)
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        with pytest.raises(AuthorizationError) as excinfo:
            s.discover("DBSCHEMA_CATALOGS")
    # FR-008: the server's own words survive; FR-010: identity does not.
    assert "access" in str(excinfo.value).lower()
    assert "DOMAIN\\reader" not in str(excinfo.value)


def test_server_error_for_a_non_permission_fault():
    fault = (
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><Fault>'
        "<faultcode>XMLAnalysisError.0xC1210003</faultcode>"
        "<faultstring>The syntax for MDX is incorrect.</faultstring>"
        "</Fault></Body></Envelope>"
    )
    ch = _authed_channel(fault)
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        with pytest.raises(ServerError, match="syntax"):
            s.execute("SELECT nonsense")


def test_negotiation_error_when_the_server_picks_binary_xml():
    ch = BytesChannel(synth.dime_message_with_options(b"<Envelope/>", dime.OPT_RESP_SX))
    with pytest.raises(NegotiationError):
        connect("h", 2383, channel=ch, context=DoneContext())


def test_the_five_categories_are_distinct_types():
    types = {
        ConnectionError,
        AuthenticationError,
        AuthorizationError,
        ServerError,
        NegotiationError,
    }
    assert len(types) == 5
    assert AuthorizationError is not AuthenticationError


def test_credential_default_is_kerberos():
    assert Credential().mechanism == "kerberos"
