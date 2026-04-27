from __future__ import annotations

import os
import secrets
import socket

from crypto_utils.framing import recv_msg, send_msg


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "4444"))


def main() -> None:
    client_nonce = secrets.token_hex(16)
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        send_msg(sock, {"type": "client_hello", "client_nonce": client_nonce})
        resp = recv_msg(sock)
        print("[client] received:", resp)


if __name__ == "__main__":
    main()

