from __future__ import annotations

import os
import secrets
import socket
from typing import Any, Dict

from crypto_utils.framing import ProtocolError, recv_msg, send_msg


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "4444"))


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    try:
        msg = recv_msg(conn)
        if msg.get("type") != "client_hello":
            raise ProtocolError("expected client_hello")

        server_nonce = secrets.token_hex(16)
        reply: Dict[str, Any] = {"type": "server_hello", "server_nonce": server_nonce}
        send_msg(conn, reply)
    except ProtocolError as e:
        send_msg(conn, {"type": "error", "error": str(e)})
    finally:
        conn.close()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[server] listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print(f"[server] connection from {addr[0]}:{addr[1]}")
            handle_client(conn, addr)


if __name__ == "__main__":
    main()

