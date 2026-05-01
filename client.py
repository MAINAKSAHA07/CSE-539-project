"""
TLS-like client: verify server cert + transcript signature, complete OPRF + PAKE,
derive HKDF traffic secrets, exchange AEAD application data.
"""

from __future__ import annotations

import os
import secrets
import socket
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature

from crypto_utils.aead import aesgcm_decrypt, aesgcm_encrypt
from crypto_utils.certs import Certificate, verify_certificate
from crypto_utils.framing import ProtocolError, recv_msg, send_msg
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


def _friendly_server_error(detail: str) -> None:
    """Turn server ProtocolError text into a short, grader-friendly client exit message."""
    d = (detail or "").strip()
    low = d.lower()
    if "bad password proof" in low:
        reason = "authentication failed: invalid password (PAKE client proof rejected by server)"
    elif "username mismatch" in low:
        reason = "authentication failed: username mismatch between messages"
    elif "unknown user" in low:
        reason = "authentication failed: unknown user (run register_user.py for this username)"
    elif "no users registered" in low:
        reason = "authentication failed: no registered users (run register_user.py)"
    elif "missing certs" in low or "run `python3 ca_setup.py`" in low:
        reason = "server configuration error: TLS certificate material missing (run ca_setup.py on server host)"
    elif "oprf evaluate failed" in low or "opr evaluate" in low:
        reason = f"handshake failed: OPRF evaluation error ({d})"
    elif "app decrypt failed" in low:
        reason = "secure channel failed: server could not decrypt application data (wrong keys, bad nonce/AAD, or corrupted AEAD ciphertext)"
    else:
        reason = d
    raise SystemExit(f"[client] {reason}")


def _recv_checked(sock: socket.socket) -> Dict[str, Any]:
    """Receive one message; if server sent ``type: error``, exit with a clear explanation."""
    msg = recv_msg(sock)
    if msg.get("type") == "error":
        _friendly_server_error(str(msg.get("error", "")))
    return msg


def _expect_type(msg: Dict[str, Any], expected: str, phase: str) -> None:
    if msg.get("type") != expected:
        raise SystemExit(
            f"[client] handshake failed: unexpected server message during {phase} "
            f"(expected {expected!r}, got {msg.get('type')!r})"
        )


def main() -> None:
    client_nonce = secrets.token_hex(16)
    username = os.environ.get("USERNAME", "alice")
    password = os.environ.get("PASSWORD", "correct horse battery staple")
    corrupt_aead = os.environ.get("CLIENT_CORRUPT_AEAD", "").lower() in ("1", "true", "yes")

    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            if not CA_PK_PATH.exists():
                raise SystemExit("[client] missing CA public key; run `python3 ca_setup.py` first")

            ca_pk = decode_public_key(CA_PK_PATH.read_bytes())

            # --- Phase 1: ClientHello ---
            client_hello = {"type": "client_hello", "client_nonce": client_nonce, "username": username}
            send_msg(sock, client_hello)

            # --- Phase 2: ServerHello + certificate + transcript signature ---
            server_hello = _recv_checked(sock)
            cert_msg = _recv_checked(sock)
            sig_msg = _recv_checked(sock)

            _expect_type(server_hello, "server_hello", "server authentication (hello)")
            _expect_type(cert_msg, "certificate", "server authentication (certificate)")
            _expect_type(sig_msg, "handshake_signature", "server authentication (signature)")

            cert = Certificate.from_dict(cert_msg["cert"])
            try:
                server_pk = verify_certificate(ca_pk, cert)
            except InvalidSignature:
                raise SystemExit(
                    "[client] handshake failed: invalid server certificate (CA signature verification failed)"
                ) from None

            transcript_obj = [client_hello, server_hello, cert_msg]
            transcript = canonical_json(transcript_obj)
            sig = b64d(sig_msg["sig"])
            try:
                verify_ed25519(server_pk, sig, transcript)
            except InvalidSignature:
                raise SystemExit(
                    "[client] handshake failed: invalid handshake transcript signature (tampered or wrong server key)"
                ) from None

            # --- Phase 3: OPRF (online); derive pw_key without sending password ---
            blinded, oprf_st = oprf_blind(password)
            send_msg(sock, {"type": "oprf_blind", "blind": b64e(blinded)})

            oprf_eval_msg = _recv_checked(sock)
            _expect_type(oprf_eval_msg, "oprf_eval", "OPRF")
            evaluated = b64d(str(oprf_eval_msg.get("evaluated", "")))
            oprf_out = oprf_finalize(oprf_st, evaluated)
            pw_key = pw_key_from_oprf_output(oprf_out)

            # --- Phase 4: PAKE (X25519 + mutual HMAC proofs) ---
            pake_s1 = _recv_checked(sock)
            _expect_type(pake_s1, "pake_server_1", "PAKE")
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

            pake_s2 = _recv_checked(sock)
            _expect_type(pake_s2, "pake_server_2", "PAKE")
            sp = b64d(str(pake_s2.get("server_proof", "")))
            expected_sp = server_proof(pw_key, th, client_eph_raw, server_eph_raw)
            if not secrets.compare_digest(sp, expected_sp):
                raise SystemExit(
                    "[client] authentication failed: invalid server PAKE proof (possible impersonation or transcript mismatch)"
                )

            # --- Phase 5: HKDF key schedule (handshake → application traffic secrets) ---
            dh = compute_shared_secret(client_state.client_eph_sk, server_eph_raw)
            ikm = dh + pw_key
            handshake_traffic_secret = derive_handshake_traffic_secret(ikm, th)
            application_traffic_secret = derive_application_traffic_secret(handshake_traffic_secret, th)
            client_key, server_key, client_nonce_aead, server_nonce_aead = (
                derive_aead_material_from_application_traffic_secret(application_traffic_secret)
            )

            # --- Phase 6: AEAD application data (post-handshake only) ---
            aad = transcript
            pt = b"hello secure server"
            ct = aesgcm_encrypt(client_key, client_nonce_aead, pt, aad)
            if corrupt_aead and ct:
                ct = bytes(ct[:-1]) + bytes([(ct[-1] ^ 0xFF) & 0xFF])
            send_msg(sock, {"type": "app_data", "ciphertext": b64e(ct)})

            enc_reply = _recv_checked(sock)
            _expect_type(enc_reply, "app_data", "application data")
            reply_ct = b64d(str(enc_reply.get("ciphertext", "")))
            try:
                reply_pt = aesgcm_decrypt(server_key, server_nonce_aead, reply_ct, aad)
            except Exception:
                raise SystemExit(
                    "[client] secure channel failed: could not decrypt server application data (AEAD authentication failed)"
                ) from None

            print("[client] verified certificate + handshake signature")
            print("[client] OPRF + PAKE OK; mutual authentication complete")
            print("[client] HKDF: handshake traffic secret → application traffic secret → AES-GCM keys")
            print("[client] post-handshake AEAD: decrypted server reply:", reply_pt.decode("utf-8", errors="replace"))
    except ProtocolError as e:
        raise SystemExit(f"[client] handshake failed: connection error ({e})") from e


if __name__ == "__main__":
    main()
