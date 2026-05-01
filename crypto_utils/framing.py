"""Length-prefixed JSON messages over TCP (simple record layer for the project)."""

from __future__ import annotations

import json
import socket
import struct
from typing import Any, Dict


class ProtocolError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise ProtocolError("connection closed while receiving")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def send_msg(sock: socket.socket, obj: Dict[str, Any]) -> None:
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_msg(sock: socket.socket, max_len: int = 1_000_000) -> Dict[str, Any]:
    header = _recv_exact(sock, 4)
    (n,) = struct.unpack("!I", header)
    if n <= 0 or n > max_len:
        raise ProtocolError(f"invalid message length: {n}")
    payload = _recv_exact(sock, n)
    try:
        obj = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ProtocolError(f"invalid json: {e}") from e
    if not isinstance(obj, dict):
        raise ProtocolError("message must be a JSON object")
    return obj

