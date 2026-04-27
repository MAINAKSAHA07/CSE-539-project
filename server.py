from __future__ import annotations

import os
import secrets
import socket
from pathlib import Path
from typing import Any, Dict

from crypto_utils.certs import load_cert
from crypto_utils.framing import ProtocolError, recv_msg, send_msg
from crypto_utils.hkdf import hkdf_extract_and_expand
from crypto_utils.pake import (
    client_proof,
    compute_shared_secret,
    server_pake_start,
    server_proof,
    transcript_hash,
)
from crypto_utils.aead import aesgcm_decrypt, aesgcm_encrypt
from crypto_utils.utils import b64d
from crypto_utils.signatures import decode_private_key, sign_ed25519
from crypto_utils.utils import b64e, canonical_json


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "4444"))

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
SERVER_SK_PATH = CERTS_DIR / "server_sk.bin"
SERVER_CERT_PATH = CERTS_DIR / "server_cert.json"
USERS_PATH = BASE_DIR / "data" / "users.json"


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    try:
        msg = recv_msg(conn)
        if msg.get("type") != "client_hello":
            raise ProtocolError("expected client_hello")

        username = str(msg.get("username", ""))
        if not username:
            raise ProtocolError("client_hello must include username")

        server_nonce = secrets.token_hex(16)
        server_hello: Dict[str, Any] = {"type": "server_hello", "server_nonce": server_nonce}

        # Load long-term materials.
        if not SERVER_SK_PATH.exists() or not SERVER_CERT_PATH.exists():
            raise ProtocolError("missing certs; run `python3 ca_setup.py` first")

        server_sk = decode_private_key(SERVER_SK_PATH.read_bytes())
        cert = load_cert(str(SERVER_CERT_PATH))

        # Sign a simple transcript = canonical_json([client_hello, server_hello, cert_dict]).
        transcript_obj = [msg, server_hello, {"type": "certificate", "cert": cert.to_dict()}]
        transcript = canonical_json(transcript_obj)
        sig = sign_ed25519(server_sk, transcript)

        send_msg(conn, server_hello)
        send_msg(conn, {"type": "certificate", "cert": cert.to_dict()})
        send_msg(conn, {"type": "handshake_signature", "sig": b64e(sig)})

        # --- PAKE-style password authentication + key exchange (replaces DH) ---
        # Setup record required before handshake:
        if not USERS_PATH.exists():
            raise ProtocolError("no users registered; run `python3 register_user.py` first")

        import json as _json

        users = _json.loads(USERS_PATH.read_text(encoding="utf-8"))
        if username not in users:
            raise ProtocolError("unknown user")

        salt = b64d(users[username]["salt"])
        pw_key = b64d(users[username]["pw_key"])

        # Server sends its ephemeral key + the user's salt.
        server_state, server_eph_pk_raw = server_pake_start()
        send_msg(
            conn,
            {
                "type": "pake_server_1",
                "server_eph": b64e(server_eph_pk_raw),
                "salt": b64e(salt),
                "hint": "send username + client_eph + client_proof",
            },
        )

        client_pake = recv_msg(conn)
        if client_pake.get("type") != "pake_client_1":
            raise ProtocolError("expected pake_client_1")

        if str(client_pake.get("username", "")) != username:
            raise ProtocolError("username mismatch")

        client_eph_raw = b64d(str(client_pake.get("client_eph", "")))
        client_proof_b = b64d(str(client_pake.get("client_proof", "")))

        # Build transcript hash binding PAKE to the signed handshake.
        th = transcript_hash(transcript)

        expected_client_proof = client_proof(pw_key, th, client_eph_raw, server_eph_pk_raw)
        if not secrets.compare_digest(expected_client_proof, client_proof_b):
            raise ProtocolError("bad password proof")

        srv_proof = server_proof(pw_key, th, client_eph_raw, server_eph_pk_raw)
        send_msg(conn, {"type": "pake_server_2", "salt": b64e(salt), "server_proof": b64e(srv_proof)})

        # Shared secret from X25519 + bind password key.
        dh = compute_shared_secret(server_state.server_eph_sk, client_eph_raw)
        ikm = dh + pw_key
        master = hkdf_extract_and_expand(ikm, salt=th, info=b"cse539 master", length=32)

        client_key = hkdf_extract_and_expand(master, salt=b"app", info=b"client_key", length=32)
        server_key = hkdf_extract_and_expand(master, salt=b"app", info=b"server_key", length=32)
        client_nonce = hkdf_extract_and_expand(master, salt=b"app", info=b"client_nonce", length=12)
        server_nonce = hkdf_extract_and_expand(master, salt=b"app", info=b"server_nonce", length=12)

        # AEAD-protected post-handshake exchange.
        enc = recv_msg(conn)
        if enc.get("type") != "app_data":
            raise ProtocolError("expected app_data")

        aad = transcript  # bind record layer to handshake transcript
        ct = b64d(str(enc.get("ciphertext", "")))
        try:
            pt = aesgcm_decrypt(client_key, client_nonce, ct, aad)
        except Exception as e:
            raise ProtocolError(f"app decrypt failed: {e}") from e

        reply_pt = b"server_received:" + pt
        reply_ct = aesgcm_encrypt(server_key, server_nonce, reply_pt, aad)
        send_msg(conn, {"type": "app_data", "ciphertext": b64e(reply_ct)})
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

