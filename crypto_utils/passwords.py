from __future__ import annotations

import hashlib
import secrets


def new_salt(n: int = 16) -> bytes:
    return secrets.token_bytes(n)


def derive_password_key(password: str, salt: bytes, out_len: int = 32) -> bytes:
    """
    Derive a stable password key for registration + online proofs.

    Uses scrypt (available in stdlib via hashlib) to slow guessing.
    """
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=out_len,
    )

