"""
Password-authenticated key exchange (PAKE) helpers: X25519 ephemeral DH plus
HMAC-SHA256 mutual proofs keyed by material derived from the OPRF output.

This replaces a raw TLS 1.3 (EC)DH in the handshake while keeping a clear
separation: ``oprf.py`` hardens the password; this module binds the transcript
and derives the shared DH secret.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def _h(msg: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(msg)
    return d.finalize()


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, digestmod="sha256").digest()


@dataclass(frozen=True)
class ServerPakeState:
    server_eph_sk: X25519PrivateKey
    server_eph_pk: X25519PublicKey


@dataclass(frozen=True)
class ClientPakeState:
    client_eph_sk: X25519PrivateKey
    client_eph_pk: X25519PublicKey


def server_pake_start() -> tuple[ServerPakeState, bytes]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return ServerPakeState(server_eph_sk=sk, server_eph_pk=pk), pk.public_bytes_raw()


def client_pake_start() -> tuple[ClientPakeState, bytes]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return ClientPakeState(client_eph_sk=sk, client_eph_pk=pk), pk.public_bytes_raw()


def compute_shared_secret(own_sk: X25519PrivateKey, peer_pk_raw: bytes) -> bytes:
    peer = X25519PublicKey.from_public_bytes(peer_pk_raw)
    return own_sk.exchange(peer)


def client_proof(pw_key: bytes, transcript_hash: bytes, client_eph_pk_raw: bytes, server_eph_pk_raw: bytes) -> bytes:
    return _hmac(pw_key, b"client_proof|" + transcript_hash + client_eph_pk_raw + server_eph_pk_raw)


def server_proof(pw_key: bytes, transcript_hash: bytes, client_eph_pk_raw: bytes, server_eph_pk_raw: bytes) -> bytes:
    return _hmac(pw_key, b"server_proof|" + transcript_hash + client_eph_pk_raw + server_eph_pk_raw)


def transcript_hash(transcript: bytes) -> bytes:
    return _h(b"transcript|" + transcript)
