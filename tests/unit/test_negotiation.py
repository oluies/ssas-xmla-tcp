"""FR-012: a server that declines clear-text XML must be reported, not worked around."""
import pytest

from ssas_xmla import dime
from ssas_xmla.errors import NegotiationError


def test_client_requests_neither_binary_nor_compressed():
    encoded = dime.encode_message(b"x")
    options = encoded[dime.HEADER_LEN : dime.HEADER_LEN + 4]
    first = options[0]
    assert not first & dime.OPT_REQ_SX
    assert not first & dime.OPT_REQ_XPRESS
    assert not first & dime.OPT_RESP_SX
    assert not first & dime.OPT_RESP_XPRESS
    assert options[1:] == b"\x00\x00\x00"  # reserved bytes MUST be zero


@pytest.mark.parametrize(
    "bit,label",
    [
        (dime.OPT_RESP_SX, "binary XML"),
        (dime.OPT_REQ_SX, "binary XML"),
        (dime.OPT_RESP_XPRESS, "XPRESS compression"),
        (dime.OPT_REQ_XPRESS, "XPRESS compression"),
    ],
)
def test_server_selecting_an_unsupported_encoding_raises(bit, label):
    with pytest.raises(NegotiationError, match=label):
        dime.check_negotiated(bytes([bit, 0, 0, 0]), dime.TYPE_TEXT_XML)


def test_server_replying_with_a_different_content_type_raises():
    with pytest.raises(NegotiationError, match="content type"):
        dime.check_negotiated(dime.OPTIONS_CLEAR_TEXT, dime.TYPE_BINARY_XML)


def test_clear_text_is_accepted():
    dime.check_negotiated(dime.OPTIONS_CLEAR_TEXT, dime.TYPE_TEXT_XML)  # no raise
