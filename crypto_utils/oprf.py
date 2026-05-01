"""
Oblivious PRF (OPRF) layer in the style of OPAQUE’s password hardening step.

Uses a 2-message blind evaluation on Curve25519 in “Ed25519 point” form via
libsodium/PyNaCl: the server holds a per-user scalar k; the client blinds the
password-derived point P with r and learns F_k(P) = [k]P without revealing P.

This is a course-sized subset of full OPAQUE (no envelope / AKE from the RFC);
the subsequent X25519 + HMAC proofs in ``pake.py`` complete password-authenticated
key exchange.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import nacl.bindings as nacl_b
import nacl.exceptions

from crypto_utils.hkdf import hkdf_extract_and_expand


def _password_scalar(password: str) -> bytes:
    """Map password to a valid Ed25519 scalar (reduced)."""
    h = hashlib.sha512(b"cse539|opaque|oprf|pw|" + password.encode("utf-8")).digest()
    return nacl_b.crypto_core_ed25519_scalar_reduce(h)


def random_server_oprf_scalar() -> bytes:
    """Server OPRF secret k as a reduced 32-byte scalar."""
    return nacl_b.crypto_core_ed25519_scalar_reduce(secrets.token_bytes(64))


@dataclass(frozen=True)
class OprfClientState:
    """Client-side blinding factor r (32-byte reduced scalar)."""

    r: bytes


def oprf_blind(password: str) -> tuple[bytes, OprfClientState]:
    """
    Client: compute P = [pw_scalar]B, blind with r, return blinded point T = [r]P.
    """
    pw_scalar = _password_scalar(password)
    p = nacl_b.crypto_scalarmult_ed25519_base_noclamp(pw_scalar)
    r_raw = secrets.token_bytes(64)
    r = nacl_b.crypto_core_ed25519_scalar_reduce(r_raw)
    blinded = nacl_b.crypto_scalarmult_ed25519_noclamp(r, p)
    return blinded, OprfClientState(r=r)


def oprf_evaluate(server_k: bytes, blinded_point: bytes) -> bytes:
    """
    Server: return U = [k]T. ``server_k`` must be a 32-byte reduced scalar.
    """
    return nacl_b.crypto_scalarmult_ed25519_noclamp(server_k, blinded_point)


def oprf_finalize(state: OprfClientState, evaluated: bytes) -> bytes:
    """
    Client: unblind to W = [k]P, then hash to a fixed-length OPRF output.
    """
    r_inv = nacl_b.crypto_core_ed25519_scalar_invert(state.r)
    w = nacl_b.crypto_scalarmult_ed25519_noclamp(r_inv, evaluated)
    return hashlib.sha256(b"cse539|oprf|out|" + w).digest()


def pw_key_from_oprf_output(oprf_output: bytes) -> bytes:
    """Derive the symmetric PAKE keying material from the OPRF output (HKDF)."""
    return hkdf_extract_and_expand(oprf_output, salt=b"", info=b"opaque|pake|pw_key", length=32)


def oprf_evaluate_safe(server_k: bytes, blinded_point: bytes) -> bytes:
    """
    Like ``oprf_evaluate`` but maps invalid points to a clear error (libsodium may raise).
    """
    try:
        return oprf_evaluate(server_k, blinded_point)
    except (nacl.exceptions.CryptoError, ValueError) as e:
        raise ValueError(f"OPRF evaluate failed: {e}") from e
