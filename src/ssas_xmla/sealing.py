"""The post-authentication frame: how a sealed message is laid out on the wire.

Every message after the handshake is sealed with the negotiated security context
and wrapped in a 4-byte header. The layout was recovered by decompiling
``Microsoft.AnalysisServices.AdomdClient`` (``TcpSecureStream.WriteHeader`` /
``WriteInBlockMode``), because it is not in [MS-SSAS]:

    uint16  dataSize    little-endian, the ciphertext length
    uint16  tokenSize   little-endian, the security token length (16 for NTLM)
    bytes   ciphertext  dataSize bytes
    bytes   token       tokenSize bytes

**Ciphertext first, token second.** That is the inverse of the GSS-API ordering
`pyspnego` produces, and getting it backwards is silently fatal: the server closes
the connection with no error and logs nothing.

Two details that are easy to miss and cost a lot to rediscover:

- The UTF-8 BOM is sealed as its OWN frame before the body. The reference client
  writes it through a StreamWriter, whose preamble is a separate write, so it
  becomes a separate frame. A server that never sees it rejects the exchange.
- Frames are chunked at 2888 bytes for NTLM (the reference client reuses
  ``cbMaxToken`` as the data chunk size). The hard ceiling is 65535, since
  ``dataSize`` is a uint16.
"""

from __future__ import annotations

import struct
from typing import Protocol

from .errors import ProtocolError

BOM = b"\xef\xbb\xbf"
HEADER = struct.Struct("<HH")
# The reference client's chunk size for NTLM. Not a protocol limit -- the limit is
# 65535 -- but matching it keeps our frames the same shape as a real client's.
MAX_CHUNK = 2888


class SecurityContext(Protocol):
    def wrap_winrm(self, data: bytes) -> tuple[bytes, bytes, int]: ...

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes: ...


def seal_frame(context: SecurityContext, payload: bytes) -> bytes:
    """Wrap one payload as a single sealed frame."""
    token, ciphertext, _padding = context.wrap_winrm(payload)
    if len(ciphertext) > 0xFFFF or len(token) > 0xFFFF:
        raise ProtocolError("frame exceeds the uint16 size fields")
    return HEADER.pack(len(ciphertext), len(token)) + ciphertext + token


def seal_message(context: SecurityContext, payload: bytes) -> bytes:
    """Seal a whole message: the BOM as its own frame, then the body, chunked."""
    out = [seal_frame(context, BOM)]
    for start in range(0, len(payload), MAX_CHUNK):
        out.append(seal_frame(context, payload[start : start + MAX_CHUNK]))
    return b"".join(out)


def unseal_message(context: SecurityContext, blob: bytes) -> bytes:
    """Decrypt every frame in a sealed response and concatenate the plaintext."""
    out: list[bytes] = []
    offset = 0
    while offset + HEADER.size <= len(blob):
        data_size, token_size = HEADER.unpack_from(blob, offset)
        offset += HEADER.size
        end_data = offset + data_size
        end_token = end_data + token_size
        if end_token > len(blob):
            raise ProtocolError("sealed frame runs past the end of the message")
        ciphertext = blob[offset:end_data]
        token = blob[end_data:end_token]
        out.append(context.unwrap_winrm(token, ciphertext))
        offset = end_token
    plain = b"".join(out)
    return plain[len(BOM) :] if plain.startswith(BOM) else plain
