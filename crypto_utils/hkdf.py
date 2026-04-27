from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


def hkdf_extract_and_expand(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def hkdf_expand(prk: bytes, *, info: bytes, length: int) -> bytes:
    exp = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return exp.derive(prk)

