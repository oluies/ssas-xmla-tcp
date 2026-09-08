"""The post-authentication frame layout.

Recovered by decompiling AdomdClient; not documented in [MS-SSAS]. These tests
pin the parts that were expensive to discover and are silently fatal if wrong.
"""

import struct

import pytest

from ssas_xmla import sealing
from ssas_xmla.errors import ProtocolError


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
    so it lands as a separate frame. A server that never sees it rejects the
    exchange."""
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


def test_a_truncated_frame_is_rejected():
    ctx = FakeContext()
    message = sealing.seal_message(ctx, b"payload")
    with pytest.raises(ProtocolError, match="past the end"):
        sealing.unseal_message(ctx, message[:-4])


def test_dataSize_is_a_uint16_and_oversize_is_refused():
    class Oversize(FakeContext):
        def wrap_winrm(self, data):
            return self.TOKEN, b"\x00" * 0x10000, 0

    with pytest.raises(ProtocolError, match="uint16"):
        sealing.seal_frame(Oversize(), b"x")


def test_all_three_split_layers_compose():
    """Sealed chunks inside DIME chunks arriving in TCP fragments.

    Three independent splits stack on one message and each is handled at a
    different layer, so this asserts they compose rather than merely work alone:

      1. the payload exceeds MAX_CHUNK, so sealing emits several frames
      2. the sealed bytes exceed one DIME record, so framing sets CF and chunks
      3. the socket hands the reader a few bytes at a time

    Verified against a live instance too: DBSCHEMA_COLUMNS returns 1366 rows, well
    past all three thresholds.
    """
    from ssas_xmla import dime
    from ssas_xmla.transport import BytesChannel, MessageStream
    from tests.unit.test_client_session import DoneContext

    ctx = DoneContext()
    payload = b"<Envelope>" + b"x" * 7000 + b"</Envelope>"

    sealed_bytes = sealing.seal_message(ctx, payload)
    assert len(sealed_bytes) > sealing.MAX_CHUNK  # (1) several sealed frames

    parts = [sealed_bytes[i : i + 2000] for i in range(0, len(sealed_bytes), 2000)]
    assert len(parts) > 1  # (2) several DIME records
    wire = b"".join(
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

    class Trickle(BytesChannel):
        def recv(self, size):  # (3) seven bytes per read
            return super().recv(7)

    reassembled = MessageStream(Trickle(wire)).receive_message()
    assert reassembled == sealed_bytes
    assert sealing.unseal_message(ctx, reassembled) == payload
