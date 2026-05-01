"""
TLS-like client: verify server cert + transcript signature, complete OPRF + PAKE,
derive HKDF traffic secrets, exchange AEAD application data.
"""

from __future__ import annotations

import os
import secrets
import socket
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from crypto_utils.aead import aesgcm_decrypt, aesgcm_encrypt
from crypto_utils.certs import Certificate, verify_certificate
from crypto_utils.framing import recv_msg, send_msg
from crypto_utils.hkdf import (
    derive_aead_material_from_application_traffic_secret,
    derive_application_traffic_secret,
    derive_handshake_traffic_secret,
)
from crypto_utils.oprf import oprf_blind, oprf_finalize, pw_key_from_oprf_output
from crypto_utils.pake import (
    client_pake_start,
    client_proof,
    compute_shared_secret,
    server_proof,
    transcript_hash,
)
from crypto_utils.signatures import decode_public_key, verify_ed25519
from crypto_utils.utils import b64d, b64e, canonical_json


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "4444"))

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
CA_PK_PATH = CERTS_DIR / "ca_pk.bin"


def main() -> None:
    client_nonce = secrets.token_hex(16)
    username = os.environ.get("USERNAME", "alice")
    password = os.environ.get("PASSWORD", "correct horse battery staple")

    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        if not CA_PK_PATH.exists():
            raise SystemExit("missing CA public key; run `python3 ca_setup.py` first")

        ca_pk = decode_public_key(CA_PK_PATH.read_bytes())

        # --- Phase 1: ClientHello ---
        client_hello = {"type": "client_hello", "client_nonce": client_nonce, "username": username}
        send_msg(sock, client_hello)

        # --- Phase 2: ServerHello + certificate + transcript signature ---
        server_hello = recv_msg(sock)
        cert_msg = recv_msg(sock)
        sig_msg = recv_msg(sock)

        if server_hello.get("type") != "server_hello":
            raise SystemExit(f"expected server_hello, got {server_hello.get('type')}")
        if cert_msg.get("type") != "certificate":
            raise SystemExit(f"expected certificate, got {cert_msg.get('type')}")
        if sig_msg.get("type") != "handshake_signature":
            raise SystemExit(f"expected handshake_signature, got {sig_msg.get('type')}")

        cert = Certificate.from_dict(cert_msg["cert"])
        server_pk = verify_certificate(ca_pk, cert)

        transcript_obj = [client_hello, server_hello, cert_msg]
        transcript = canonical_json(transcript_obj)
        sig = b64d(sig_msg["sig"])
        try:
            verify_ed25519(server_pk, sig, transcript)
        except InvalidSignature as e:
            raise SystemExit("handshake transcript signature invalid") from e

        # --- Phase 3: OPRF (online); derive pw_key without sending password ---
        blinded, oprf_st = oprf_blind(password)
        send_msg(sock, {"type": "oprf_blind", "blind": b64e(blinded)})

        oprf_eval_msg = recv_msg(sock)
        if oprf_eval_msg.get("type") != "oprf_eval":
            raise SystemExit(f"expected oprf_eval, got {oprf_eval_msg.get('type')}")
        evaluated = b64d(str(oprf_eval_msg.get("evaluated", "")))
        oprf_out = oprf_finalize(oprf_st, evaluated)
        pw_key = pw_key_from_oprf_output(oprf_out)

        # --- Phase 4: PAKE (X25519 + proofs) ---
        pake_s1 = recv_msg(sock)
        if pake_s1.get("type") != "pake_server_1":
            raise SystemExit(f"expected pake_server_1, got {pake_s1.get('type')}")

        server_eph_raw = b64d(str(pake_s1.get("server_eph", "")))

        client_state, client_eph_raw = client_pake_start()
        th = transcript_hash(transcript)
        cp = client_proof(pw_key, th, client_eph_raw, server_eph_raw)
        send_msg(
            sock,
            {
                "type": "pake_client_1",
                "username": username,
                "client_eph": b64e(client_eph_raw),
                "client_proof": b64e(cp),
            },
        )

        pake_s2 = recv_msg(sock)
        if pake_s2.get("type") != "pake_server_2":
            raise SystemExit(f"expected pake_server_2, got {pake_s2.get('type')}")

        sp = b64d(str(pake_s2.get("server_proof", "")))
        expected_sp = server_proof(pw_key, th, client_eph_raw, server_eph_raw)
        if not secrets.compare_digest(sp, expected_sp):
            raise SystemExit("server password proof invalid")

        # --- Phase 5: HKDF key schedule (handshake → application traffic secrets) ---
        dh = compute_shared_secret(client_state.client_eph_sk, server_eph_raw)
        ikm = dh + pw_key
        handshake_traffic_secret = derive_handshake_traffic_secret(ikm, th)
        application_traffic_secret = derive_application_traffic_secret(handshake_traffic_secret, th)
        client_key, server_key, client_nonce_aead, server_nonce_aead = (
            derive_aead_material_from_application_traffic_secret(application_traffic_secret)
        )

        # --- Phase 6: AEAD application data ---
        aad = transcript
        pt = b"hello secure server"
        ct = aesgcm_encrypt(client_key, client_nonce_aead, pt, aad)
        send_msg(sock, {"type": "app_data", "ciphertext": b64e(ct)})

        enc_reply = recv_msg(sock)
        if enc_reply.get("type") != "app_data":
            raise SystemExit(f"expected app_data reply, got {enc_reply.get('type')}")

        reply_ct = b64d(str(enc_reply.get("ciphertext", "")))
        reply_pt = aesgcm_decrypt(server_key, server_nonce_aead, reply_ct, aad)

        print("[client] verified certificate + handshake signature")
        print("[client] OPRF + PAKE OK; HKDF handshake→application traffic secrets derived")
        print("[client] decrypted reply:", reply_pt.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
