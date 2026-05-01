"""
HKDF (SHA-256) helpers with TLS 1.3–style *naming* for this project.

TLS 1.3 derives a **handshake traffic secret** then an **application traffic secret**
from the key schedule. We mirror that *structure* here (labels + extract/expand),
without implementing the full TLS 1.3 state machine.

Typical flow in this codebase::

    ikm = dh_secret || pw_key
    hts = derive_handshake_traffic_secret(ikm, transcript_hash)
    ats = derive_application_traffic_secret(hts, transcript_hash)
    keys = derive_aead_material_from_application_traffic_secret(ats)
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


def hkdf_extract_and_expand(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def hkdf_expand(prk: bytes, *, info: bytes, length: int) -> bytes:
    exp = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return exp.derive(prk)


def derive_handshake_traffic_secret(ikm: bytes, transcript_hash: bytes) -> bytes:
    """
    PDF: “handshake traffic secrets” — first HKDF stage after shared IKM
    (here: X25519 shared secret concatenated with password-derived material).
    """
    return hkdf_extract_and_expand(
        ikm,
        salt=transcript_hash,
        info=b"tls13 handshake traffic secret",
        length=32,
    )


def derive_application_traffic_secret(handshake_traffic_secret: bytes, transcript_hash: bytes) -> bytes:
    """
    PDF: “application traffic secrets” — second stage derived from the handshake secret.
    """
    return hkdf_expand(
        handshake_traffic_secret,
        info=b"tls13 application traffic secret|" + transcript_hash,
        length=32,
    )


def derive_aead_material_from_application_traffic_secret(application_traffic_secret: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Expand application traffic secret into AEAD keys/nonces (client vs server write keys).
    """
    client_key = hkdf_expand(application_traffic_secret, info=b"tls13 client application write key", length=32)
    server_key = hkdf_expand(application_traffic_secret, info=b"tls13 server application write key", length=32)
    client_nonce = hkdf_expand(application_traffic_secret, info=b"tls13 client application write iv", length=12)
    server_nonce = hkdf_expand(application_traffic_secret, info=b"tls13 server application write iv", length=12)
    return client_key, server_key, client_nonce, server_nonce
