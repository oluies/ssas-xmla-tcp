"""DIME record framing for the Analysis Services TCP binding.

Every field below is specified in [MS-SSAS] "TCP":
https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssas/f172a52f-f69e-4051-8b3a-627433e978fb

  "When using TCP as the transport, the client and server MUST compose messages by
   using Direct Internet Message Encapsulation [DIME]."

Record header, 12 bytes:

    byte 0   VERSION (5 bits, MUST be 1) | MB (1) | ME (1) | CF (1)
    byte 1   TYPE_T (4 bits) | RESERVED (4 bits, MUST be 0)
    bytes 2-3    OPTIONS_LENGTH (16)
    bytes 4-5    ID_LENGTH (16)
    bytes 6-7    TYPE_LENGTH (16)
    bytes 8-11   DATA_LENGTH (32)

then OPTIONS, ID, TYPE and DATA in that order, each padded to a 4-byte boundary.
The length fields exclude their own padding, which is why every read and write
here rounds separately.

Content-type negotiation is the reason this library can stay small: binary XML
[MS-BINXML] and XPRESS compression are OPTIONAL and negotiated, so we ask for
clear-text XML and never implement either (research.md, D2).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import NegotiationError, ProtocolError

VERSION = 1
HEADER_LEN = 12

# TYPE values from the [MS-SSAS] TCP content-type table. TYPE_LENGTH in the header
# is simply the byte length of these strings (8, 14, 22, 21 respectively).
TYPE_TEXT_XML = b"text/xml"
TYPE_BINARY_XML = b"application/sx"
TYPE_COMPRESSED_XML = b"application/xml+xpress"
TYPE_COMPRESSED_BINARY_XML = b"application/sx+xpress"

# OPTIONS: 4 bytes, only the first is used; the remaining three are reserved and
# MUST be zero. Bits run from least significant upward.
OPT_NEGO = 0x01
OPT_REQ_SX = 0x02
OPT_REQ_XPRESS = 0x04
OPT_RESP_SX = 0x08
OPT_RESP_XPRESS = 0x10

# What this client asks for: negotiation in progress, nothing binary, nothing
# compressed. NEGO is left clear on our side; the server sets it when settled.
OPTIONS_CLEAR_TEXT = bytes([0x00, 0x00, 0x00, 0x00])


def _pad(n: int) -> int:
    """Bytes of padding needed to reach the next 4-byte boundary."""
    return (-n) % 4


@dataclass(frozen=True)
class Record:
    """One DIME record."""

    data: bytes
    type_: bytes = TYPE_TEXT_XML
    options: bytes = OPTIONS_CLEAR_TEXT
    id_: bytes = b""
    mb: bool = True
    me: bool = True
    cf: bool = False
    type_t: int = 1

    def encode(self) -> bytes:
        if len(self.options) % 4:
            raise ProtocolError("OPTIONS must be a whole number of 4-byte words")
        flags = (VERSION << 3) | (int(self.mb) << 2) | (int(self.me) << 1) | int(self.cf)
        header = struct.pack(
            ">BBHHHI",
            flags,
            (self.type_t & 0x0F) << 4,
            len(self.options),
            len(self.id_),
            len(self.type_),
            len(self.data),
        )
        out = [header]
        for field in (self.options, self.id_, self.type_, self.data):
            out.append(field)
            out.append(b"\x00" * _pad(len(field)))
        return b"".join(out)


def decode_record(buf: bytes, offset: int = 0) -> tuple[Record, int]:
    """Decode one record starting at `offset`; return it and the next offset."""
    if len(buf) - offset < HEADER_LEN:
        raise ProtocolError("truncated DIME header")
    flags, type_byte, opt_len, id_len, type_len, data_len = struct.unpack_from(
        ">BBHHHI", buf, offset
    )
    version = flags >> 3
    if version != VERSION:
        # MS-SSAS: "This value MUST be set to 1."
        raise ProtocolError(f"unsupported DIME version {version}, expected {VERSION}")
    pos = offset + HEADER_LEN
    fields = []
    for length in (opt_len, id_len, type_len, data_len):
        end = pos + length
        if end > len(buf):
            raise ProtocolError("truncated DIME record body")
        fields.append(buf[pos:end])
        pos = end + _pad(length)
    options, id_, type_, data = fields
    record = Record(
        data=data,
        type_=type_,
        options=options,
        id_=id_,
        mb=bool(flags & 0x04),
        me=bool(flags & 0x02),
        cf=bool(flags & 0x01),
        type_t=type_byte >> 4,
    )
    return record, pos


def encode_message(payload: bytes, type_: bytes = TYPE_TEXT_XML) -> bytes:
    """Encode a whole message as a single DIME record (MB and ME both set)."""
    return Record(data=payload, type_=type_).encode()


def decode_message_at(buf: bytes, offset: int = 0) -> tuple[bytes, bytes, bytes, int]:
    """Reassemble one DIME message starting at `offset`.

    Returns (payload, content type, first record's OPTIONS, next offset). The next
    offset matters: a peer may pack several messages into one TCP segment, so the
    caller must keep the remainder rather than discarding the read buffer.

    A chunked sequence "is required to be encapsulated entirely within one DIME
    message and cannot span across multiple DIME messages", so reassembly stops at
    the record whose ME bit is set.
    """
    chunks: list[bytes] = []
    content_type = b""
    options = b""
    first = True
    while True:
        record, offset = decode_record(buf, offset)
        if first:
            if not record.mb:
                raise ProtocolError("first DIME record does not set MB")
            content_type = record.type_
            options = record.options
            first = False
        chunks.append(record.data)
        if record.me:
            break
        if offset >= len(buf):
            raise ProtocolError("DIME message ended without a record setting ME")
    return b"".join(chunks), content_type, options, offset


def decode_message(buf: bytes) -> tuple[bytes, bytes]:
    """Decode the first message in `buf`; return (payload, content type)."""
    payload, content_type, _options, _next = decode_message_at(buf, 0)
    return payload, content_type


def check_negotiated(record_options: bytes, record_type: bytes) -> None:
    """Fail loudly if the server selected an encoding we deliberately do not implement.

    This is FR-012. Binary XML and compression are permitted by the specification
    but excluded from this milestone; a server that insists on them is a scope
    change to report, not a fallback to absorb.
    """
    first = record_options[0] if record_options else 0
    if first & (OPT_REQ_SX | OPT_RESP_SX):
        raise NegotiationError(
            "server selected binary XML (application/sx); this client negotiates "
            "clear-text text/xml only"
        )
    if first & (OPT_REQ_XPRESS | OPT_RESP_XPRESS):
        raise NegotiationError(
            "server selected XPRESS compression; this client negotiates "
            "uncompressed text/xml only"
        )
    if record_type and record_type != TYPE_TEXT_XML:
        raise NegotiationError(
            f"server replied with content type {record_type!r}, expected "
            f"{TYPE_TEXT_XML!r}"
        )
