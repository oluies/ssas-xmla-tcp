import pytest

from ssas_xmla import dime
from ssas_xmla.errors import ProtocolError


def test_round_trip_single_record():
    payload = b"<Envelope>body</Envelope>"
    encoded = dime.encode_message(payload)
    out, content_type = dime.decode_message(encoded)
    assert out == payload
    assert content_type == dime.TYPE_TEXT_XML


def test_header_matches_the_specified_layout():
    encoded = dime.encode_message(b"abc")
    flags = encoded[0]
    assert flags >> 3 == dime.VERSION  # MS-SSAS: VERSION MUST be 1
    assert flags & 0x04  # MB on the first record
    assert flags & 0x02  # ME on the last record
    assert not flags & 0x01  # CF clear when not chunked
    assert encoded[1] >> 4 == 1  # TYPE_T is 1 for a record starting a message
    assert encoded[1] & 0x0F == 0  # RESERVED MUST be 0


def test_every_field_is_padded_to_a_four_byte_boundary():
    # 3-byte payload and 8-byte type both need padding; total must stay aligned.
    encoded = dime.encode_message(b"abc")
    assert len(encoded) % 4 == 0


@pytest.mark.parametrize("size", [0, 1, 3, 4, 5, 255, 4096])
def test_payload_sizes_round_trip(size):
    payload = b"x" * size
    out, _ = dime.decode_message(dime.encode_message(payload))
    assert out == payload


def test_chunked_sequence_reassembles_within_one_message():
    parts = [b"<Env", b"elope>", b"</Envelope>"]
    encoded = b"".join(
        dime.Record(
            data=p,
            type_=dime.TYPE_TEXT_XML if i == 0 else b"",
            mb=(i == 0),
            me=(i == len(parts) - 1),
            cf=(i != len(parts) - 1),
            type_t=1 if i == 0 else 0,
        ).encode()
        for i, p in enumerate(parts)
    )
    out, _ = dime.decode_message(encoded)
    assert out == b"".join(parts)


def test_rejects_a_version_other_than_one():
    encoded = bytearray(dime.encode_message(b"x"))
    encoded[0] = (2 << 3) | (encoded[0] & 0x07)
    with pytest.raises(ProtocolError, match="unsupported DIME version"):
        dime.decode_message(bytes(encoded))


def test_truncated_header_is_rejected():
    with pytest.raises(ProtocolError, match="truncated"):
        dime.decode_message(b"\x0e\x10")


def test_truncated_body_is_rejected():
    encoded = dime.encode_message(b"payload")
    with pytest.raises(ProtocolError, match="truncated"):
        dime.decode_message(encoded[:-8])


def test_record_missing_its_padding_is_incomplete_not_decoded():
    """Regression: only the declared bytes were checked, not their padding, so a
    31-of-32-byte buffer decoded as complete. The pad byte stayed in the stream and
    was read as the next message's header — a desync surfacing as a bogus
    "unsupported DIME version"."""
    from ssas_xmla.errors import IncompleteMessage

    encoded = dime.encode_message(b"payload")
    assert len(encoded) % 4 == 0
    with pytest.raises(IncompleteMessage):
        dime.decode_message(encoded[:-1])
