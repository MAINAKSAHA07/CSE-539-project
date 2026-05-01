"""Ed25519 sign/verify and raw key encode/decode helpers."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def sign_ed25519(sk: Ed25519PrivateKey, msg: bytes) -> bytes:
    return sk.sign(msg)


def verify_ed25519(pk: Ed25519PublicKey, sig: bytes, msg: bytes) -> None:
    pk.verify(sig, msg)  # raises InvalidSignature


def encode_public_key(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def decode_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def encode_private_key(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def decode_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)

