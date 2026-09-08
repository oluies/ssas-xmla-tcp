"""The post-authentication frame layout.

Recovered by decompiling AdomdClient; not documented in [MS-SSAS]. These tests
pin the parts that were expensive to discover and are silently fatal if wrong.
"""

import struct

import pytest

from ssas_xmla import sealing
from ssas_xmla.errors import IncompleteMessage, ProtocolError
from tests.fixtures import synth


class FakeContext:
    """Reversible stand-in for a security context: XOR, so wrap/unwrap round-trip
    without needing a KDC or real credentials."""

    TOKEN = b"\x01\x00\x00\x00" + b"\xaa" * 12  # NTLM-shaped: 16 bytes

    def wrap_winrm(self, data):
        return self.TOKEN, bytes(b ^ 0x5A for b in data), 0

    def unwrap_winrm(self, header, data):
        assert header == self.TOKEN
        return bytes(b ^ 0x5A for b in data)


def test_frame_puts_ciphertext_before_the_token():
    """The inverse of GSS ordering. Getting it backwards closes the connection
    with no error and nothing in the server log."""
    ctx = FakeContext()
    frame = sealing.seal_frame(ctx, b"hello")
    data_size, token_size = struct.unpack_from("<HH", frame, 0)
    assert (data_size, token_size) == (5, 16)
    assert frame[4:9] == bytes(b ^ 0x5A for b in b"hello")  # ciphertext first
    assert frame[9:25] == FakeContext.TOKEN  # token second


def test_header_is_two_little_endian_uint16s():
    frame = sealing.seal_frame(FakeContext(), b"x" * 520)
    assert frame[:4] == struct.pack("<HH", 520, 16)
    assert len(frame) == 4 + 520 + 16


def test_bom_is_sealed_as_its_own_frame():
    """The reference client writes the encoding preamble through a StreamWriter,
    so it lands as a separate frame, and we match it. Whether the server REQUIRES
    it is untested: the working exchange fixed two faults at once (byte order, and
    the missing header plus BOM frame), so the BOM was never varied on its own."""
    message = sealing.seal_message(FakeContext(), b"<Envelope/>")
    first_data, first_token = struct.unpack_from("<HH", message, 0)
    assert first_data == len(sealing.BOM) == 3
    assert first_token == 16
    # the captured real-client frame was exactly this size
    assert 4 + first_data + first_token == 23


def test_a_real_captured_frame_size_is_reproduced():
    """A captured first message was 563 bytes: a 23-byte BOM frame plus a
    540-byte body frame (dataSize 520, tokenSize 16)."""
    body = b"y" * 520
    message = sealing.seal_message(FakeContext(), body)
    assert len(message) == 23 + (4 + 520 + 16) == 563


def test_round_trip():
    ctx = FakeContext()
    payload = b"<Envelope>body</Envelope>"
    assert sealing.unseal_message(ctx, sealing.seal_message(ctx, payload)) == payload


def test_large_payloads_are_chunked_like_the_reference_client():
    ctx = FakeContext()
    payload = b"z" * (sealing.MAX_CHUNK * 2 + 100)
    message = sealing.seal_message(ctx, payload)
    frames, offset = 0, 0
    while offset + 4 <= len(message):
        ds, ts = struct.unpack_from("<HH", message, offset)
        offset += 4 + ds + ts
        frames += 1
    assert frames == 4  # BOM + three body chunks
    assert sealing.unseal_message(ctx, message) == payload


def test_a_truncated_frame_is_incomplete_not_malformed():
    """The transport discriminates on this type, and conflating the two broke
    chunked messages once: a rowset larger than one read arrives split, which is
    "read more", not "malformed"."""
    ctx = FakeContext()
    message = sealing.seal_message(ctx, b"payload")
    with pytest.raises(IncompleteMessage, match="past the end"):
        sealing.unseal_message(ctx, message[:-4])


@pytest.mark.parametrize("cut", [1, 2, 3])
def test_a_partial_trailing_header_is_not_silently_discarded(cut):
    """A 1-3 byte remainder used to fall out of the loop condition, so the caller
    got SHORT PLAINTEXT with no error at all -- the worst shape of failure, since
    an empty or truncated rowset is indistinguishable from a real answer."""
    ctx = FakeContext()
    message = sealing.seal_message(ctx, b"payload") + b"\x00" * cut
    with pytest.raises(IncompleteMessage, match="frame header"):
        sealing.unseal_message(ctx, message)


def test_a_padding_mechanism_is_refused_rather_than_corrupting_the_body():
    """The frame carries dataSize and tokenSize and nothing else, so padding sits
    inside dataSize with no way for the peer to strip it. NTLM pads by zero, which
    is why the NTLM path works; Kerberos does not, and would send the server XML
    with trailing rubbish that fails as a parse error far from its cause."""

    class Padding(FakeContext):
        def wrap_winrm(self, data):
            return self.TOKEN, bytes(b ^ 0x5A for b in data) + b"\x00" * 5, 5

    with pytest.raises(ProtocolError, match="padded the plaintext by 5"):
        sealing.seal_frame(Padding(), b"x")


def test_dataSize_is_a_uint16_and_oversize_is_refused():
    class Oversize(FakeContext):
        def wrap_winrm(self, data):
            return self.TOKEN, b"\x00" * 0x10000, 0

    with pytest.raises(ProtocolError, match="uint16"):
        sealing.seal_frame(Oversize(), b"x")


def _frame_count(message: bytes) -> int:
    """How many sealed frames a message carries, walked by the declared sizes."""
    count, offset = 0, 0
    while offset + 4 <= len(message):
        ds, ts = struct.unpack_from("<HH", message, offset)
        offset += 4 + ds + ts
        count += 1
    return count


def test_all_three_split_layers_compose():
    """Sealed chunks inside DIME chunks arriving in TCP fragments.

    Three independent splits stack on one message and each is handled at a
    different layer, so this asserts they compose rather than merely work alone:

      1. the payload exceeds MAX_CHUNK, so sealing emits several frames
      2. the sealed bytes exceed one DIME record, so framing sets CF and chunks
      3. the socket hands the reader a few bytes at a time

    Observed against a live instance: DBSCHEMA_COLUMNS returned 1366 rows, sealed
    into many frames and read over many socket reads. Whether the server also split
    it across DIME records was not recorded -- DIME's DATA_LENGTH is a uint32, so
    there is no row count at which layer 2 must engage. This test is what pins the
    composition; the live run only shows the sizes are realistic.

    Uses the LOCAL FakeContext, whose unwrap_winrm asserts the token it was handed:
    a context that ignores the header would still pass if token and ciphertext were
    swapped in a way that preserved their lengths.
    """
    from ssas_xmla.transport import MessageStream

    ctx = FakeContext()
    payload = b"<Envelope>" + b"x" * 7000 + b"</Envelope>"
    assert len(payload) > sealing.MAX_CHUNK  # (1) the plaintext is what drives it

    sealed_bytes = sealing.seal_message(ctx, payload)
    assert _frame_count(sealed_bytes) > 2  # BOM + more than one body frame

    parts = [sealed_bytes[i : i + 2000] for i in range(0, len(sealed_bytes), 2000)]
    assert len(parts) > 1  # (2) several DIME records
    wire = synth.chunked_dime_message(parts)

    reassembled = MessageStream(synth.trickling(wire)).receive_message()  # (3)
    assert reassembled == sealed_bytes
    assert sealing.unseal_message(ctx, reassembled) == payload


@pytest.mark.parametrize("short_by", [1, 2, 3])
def test_a_short_sealed_body_inside_a_complete_dime_message_is_not_silent(short_by):
    """The failure this stacking introduces is silent, and only at the top layer.

    Layers 2 and 3 do their job: the DIME message reassembles perfectly, ME and all.
    It is the sealed content INSIDE it that is short, and that used to return
    truncated plaintext with no error -- which `rowset.parse` then degraded to an
    empty Rowset, and empty is a meaningful answer in this API. The DIME layer
    cannot catch this: it has no idea what its payload means.
    """
    from ssas_xmla.errors import IncompleteMessage
    from ssas_xmla.transport import MessageStream

    ctx = FakeContext()
    sealed_bytes = sealing.seal_message(ctx, b"<Envelope>" + b"x" * 4000 + b"</Envelope>")
    truncated = sealed_bytes[:-short_by]
    wire = synth.chunked_dime_message(
        [truncated[i : i + 2000] for i in range(0, len(truncated), 2000)]
    )
    reassembled = MessageStream(synth.trickling(wire)).receive_message()
    assert reassembled == truncated  # layers 2 and 3 delivered exactly what was sent
    with pytest.raises(IncompleteMessage):
        sealing.unseal_message(ctx, reassembled)
