"""AES-GCM authenticated encryption for post-handshake application data."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aesgcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

