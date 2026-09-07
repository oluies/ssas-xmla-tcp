import pytest

from ssas_xmla import dime
from ssas_xmla.errors import ConnectionError as SsasConnectionError
from ssas_xmla.errors import NegotiationError
from ssas_xmla.transport import BytesChannel, MessageStream
from tests.fixtures import synth


def test_sends_a_well_formed_dime_message():
    channel = BytesChannel()
    MessageStream(channel).send_message(b"<Envelope/>")
    payload, content_type = dime.decode_message(bytes(channel.sent))
    assert payload == b"<Envelope/>"
    assert content_type == dime.TYPE_TEXT_XML


def test_receives_a_message_from_recorded_bytes():
    response = synth.dime_message(b"<Envelope>ok</Envelope>")
    stream = MessageStream(BytesChannel(response))
    assert stream.receive_message() == b"<Envelope>ok</Envelope>"


def test_reassembles_a_response_split_across_reads():
    """The reader is driven by declared lengths, not by the peer going quiet."""
    response = synth.dime_message(b"y" * 5000)

    class Trickle(BytesChannel):
        def recv(self, size):  # ignore the requested size; hand back 7 bytes at a time
            return super().recv(7)

    stream = MessageStream(Trickle(response))
    assert stream.receive_message() == b"y" * 5000


def test_disconnect_mid_response_raises_connection_error():
    truncated = synth.dime_message(b"payload")[:-6]
    stream = MessageStream(BytesChannel(truncated))
    with pytest.raises(SsasConnectionError, match="closed before"):
        stream.receive_message()


def test_negotiation_is_enforced_on_receive():
    bad = synth.dime_message_with_options(b"<Envelope/>", dime.OPT_RESP_SX)
    stream = MessageStream(BytesChannel(bad))
    with pytest.raises(NegotiationError):
        stream.receive_message()


def test_close_propagates_to_the_channel():
    channel = BytesChannel()
    MessageStream(channel).close()
    assert channel.closed
