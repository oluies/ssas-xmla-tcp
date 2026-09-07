"""Session lifecycle and state transitions."""

import pytest

from ssas_xmla import dime
from ssas_xmla.auth import Credential
from ssas_xmla.client import ConnectionTarget, Session, State, connect
from ssas_xmla.errors import AuthenticationError
from ssas_xmla.transport import BytesChannel
from tests.fixtures import synth


class DoneContext:
    """A context that completes on the first step."""

    protection = False

    def __init__(self):
        self._stepped = False

    def step(self, in_token=None):
        self._stepped = True
        return b"tok"

    @property
    def complete(self):
        return self._stepped


def _channel_for(*payloads):
    ch = BytesChannel()
    for p in payloads:
        ch.queue(synth.dime_message(p.encode()))
    return ch


def test_target_rejects_nonsense():
    with pytest.raises(ValueError, match="host"):
        ConnectionTarget(host="", port=2383)
    with pytest.raises(ValueError, match="port"):
        ConnectionTarget(host="h", port=0)
    with pytest.raises(ValueError, match="unbounded"):
        ConnectionTarget(host="h", port=2383, timeout=0)


def test_there_is_no_default_port():
    """A default would invite guessing between a default and a named instance."""
    with pytest.raises(TypeError):
        ConnectionTarget(host="h")  # port is required


def test_state_moves_unconnected_to_authenticated():
    ch = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    assert s.state is State.UNCONNECTED
    s.open(channel=ch, context=DoneContext())
    assert s.state is State.AUTHENTICATED


def test_request_before_authentication_is_refused():
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    with pytest.raises(AuthenticationError, match="not authenticated"):
        s.discover("DISCOVER_DATASOURCES")


def test_a_failed_session_is_terminal():
    class Boom:
        protection = False
        complete = False

        def step(self, in_token=None):
            raise RuntimeError("nope")

    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    with pytest.raises(AuthenticationError):
        s.open(channel=BytesChannel(), context=Boom())
    assert s.state is State.FAILED
    with pytest.raises(AuthenticationError):
        s.discover("DISCOVER_DATASOURCES")


def test_close_is_idempotent_and_works_on_a_failed_session():
    s = Session(target=ConnectionTarget("h", 2383), credential=Credential())
    s.close()
    s.close()
    assert s.state is State.CLOSED


def test_context_manager_closes_on_the_way_out():
    ch = _channel_for(synth.AUTHENTICATE_RESPONSE.format(token=""))
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        assert s.state is State.AUTHENTICATED
    assert s.state is State.CLOSED


def test_discover_datasources_returns_rows():
    ch = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE,
    )
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        result = s.discover_datasources()
    assert len(result) == 1
    assert result.rows[0]["DataSourceName"] == "Analysis Services"


def test_the_request_sent_is_a_valid_dime_message():
    ch = _channel_for(
        synth.AUTHENTICATE_RESPONSE.format(token=""),
        synth.DISCOVER_DATASOURCES_RESPONSE,
    )
    with connect("h", 2383, channel=ch, context=DoneContext()) as s:
        s.discover_datasources()
    payload, content_type = dime.decode_message(bytes(ch.sent))
    assert content_type == dime.TYPE_TEXT_XML
    assert b"Authenticate" in payload
