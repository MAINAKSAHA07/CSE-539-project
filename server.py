"""
TLS-like server: certificate + signed transcript, then OPRF + PAKE + HKDF + AEAD.

Phases (see PDF): PKI-backed server auth, password-based client auth via OPRF/PAKE,
traffic secrets via HKDF, application data via AES-GCM.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
from pathlib import Path
from typing import Any, Dict

from crypto_utils.aead import aesgcm_decrypt, aesgcm_encrypt
from crypto_utils.certs import load_cert
from crypto_utils.framing import ProtocolError, recv_msg, send_msg
from crypto_utils.hkdf import (
    derive_aead_material_from_application_traffic_secret,
    derive_application_traffic_secret,
    derive_handshake_traffic_secret,
)
from crypto_utils.oprf import oprf_evaluate_safe
from crypto_utils.pake import (
    client_proof,
    compute_shared_secret,
    server_pake_start,
    server_proof,
    transcript_hash,
)
from crypto_utils.signatures import decode_private_key, sign_ed25519
from crypto_utils.utils import b64d, b64e, canonical_json


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "4444"))

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
SERVER_SK_PATH = CERTS_DIR / "server_sk.bin"
SERVER_CERT_PATH = CERTS_DIR / "server_cert.json"
USERS_PATH = BASE_DIR / "data" / "users.json"


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    try:
        # --- Phase 1: ClientHello ---
        msg = recv_msg(conn)
        if msg.get("type") != "client_hello":
            raise ProtocolError("expected client_hello")

        username = str(msg.get("username", ""))
        if not username:
            raise ProtocolError("client_hello must include username")

        server_nonce = secrets.token_hex(16)
        server_hello: Dict[str, Any] = {"type": "server_hello", "server_nonce": server_nonce}

        # --- Phase 2: Server certificate + transcript signature (TLS-ish server auth) ---
        if not SERVER_SK_PATH.exists() or not SERVER_CERT_PATH.exists():
            raise ProtocolError("missing certs; run `python3 ca_setup.py` first")

        server_sk = decode_private_key(SERVER_SK_PATH.read_bytes())
        cert = load_cert(str(SERVER_CERT_PATH))

        transcript_obj = [msg, server_hello, {"type": "certificate", "cert": cert.to_dict()}]
        transcript = canonical_json(transcript_obj)
        sig = sign_ed25519(server_sk, transcript)

        send_msg(conn, server_hello)
        send_msg(conn, {"type": "certificate", "cert": cert.to_dict()})
        send_msg(conn, {"type": "handshake_signature", "sig": b64e(sig)})

        # --- Phase 3: OPRF (OPAQUE-style password hardening; server does not see password) ---
        if not USERS_PATH.exists():
            raise ProtocolError("no users registered; run `python3 register_user.py` first")

        users = json.loads(USERS_PATH.read_text(encoding="utf-8"))
        if username not in users:
            raise ProtocolError("unknown user")

        record = users[username]
        if "oprf_sk" not in record or "pw_key" not in record:
            raise ProtocolError("user record missing OPRF fields; re-run register_user.py")

        oprf_sk = b64d(record["oprf_sk"])
        pw_key = b64d(record["pw_key"])

        oprf_blind_msg = recv_msg(conn)
        if oprf_blind_msg.get("type") != "oprf_blind":
            raise ProtocolError("expected oprf_blind")
        blind = b64d(str(oprf_blind_msg.get("blind", "")))
        try:
            evaluated = oprf_evaluate_safe(oprf_sk, blind)
        except ValueError as e:
            raise ProtocolError(str(e)) from e
        send_msg(conn, {"type": "oprf_eval", "evaluated": b64e(evaluated)})

        # --- Phase 4: PAKE (X25519 + mutual HMAC proofs) ---
        server_state, server_eph_pk_raw = server_pake_start()
        send_msg(
            conn,
            {
                "type": "pake_server_1",
                "server_eph": b64e(server_eph_pk_raw),
            },
        )

        client_pake = recv_msg(conn)
        if client_pake.get("type") != "pake_client_1":
            raise ProtocolError("expected pake_client_1")

        if str(client_pake.get("username", "")) != username:
            raise ProtocolError("username mismatch")

        client_eph_raw = b64d(str(client_pake.get("client_eph", "")))
        client_proof_b = b64d(str(client_pake.get("client_proof", "")))

        th = transcript_hash(transcript)

        expected_client_proof = client_proof(pw_key, th, client_eph_raw, server_eph_pk_raw)
        if not secrets.compare_digest(expected_client_proof, client_proof_b):
            raise ProtocolError("bad password proof")

        srv_proof = server_proof(pw_key, th, client_eph_raw, server_eph_pk_raw)
        send_msg(conn, {"type": "pake_server_2", "server_proof": b64e(srv_proof)})

        # --- Phase 5: TLS 1.3–style HKDF: handshake traffic secret → application traffic secret ---
        dh = compute_shared_secret(server_state.server_eph_sk, client_eph_raw)
        ikm = dh + pw_key
        handshake_traffic_secret = derive_handshake_traffic_secret(ikm, th)
        application_traffic_secret = derive_application_traffic_secret(handshake_traffic_secret, th)
        client_key, server_key, client_nonce, server_nonce = derive_aead_material_from_application_traffic_secret(
            application_traffic_secret
        )

        # --- Phase 6: AEAD application messages (post-handshake only) ---
        # Demo scope: one AES-GCM record per direction; fixed derived nonce — do not reuse for
        # multiple messages without a per-record nonce or counter (see report).
        enc = recv_msg(conn)
        if enc.get("type") != "app_data":
            raise ProtocolError("expected app_data")

        aad = transcript
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
