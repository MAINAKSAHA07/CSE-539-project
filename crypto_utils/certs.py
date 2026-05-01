"""Minimal JSON certificates signed by a local CA (Ed25519)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature

from crypto_utils.signatures import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    decode_public_key,
    encode_public_key,
    sign_ed25519,
    verify_ed25519,
)
from crypto_utils.utils import b64d, b64e, canonical_json


@dataclass(frozen=True)
class Certificate:
    """
    Minimal JSON "certificate" for the class project:
    {
      "subject": "server",
      "public_key": "<base64 raw ed25519 pk>",
      "issuer": "local_ca",
      "signature": "<base64 sig over tbs>"
    }
    """

    subject: str
    issuer: str
    public_key_b64: str
    signature_b64: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "public_key": self.public_key_b64,
            "signature": self.signature_b64,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Certificate":
        return Certificate(
            subject=str(d["subject"]),
            issuer=str(d["issuer"]),
            public_key_b64=str(d["public_key"]),
            signature_b64=str(d["signature"]),
        )


def _tbs(cert_fields: Dict[str, Any]) -> bytes:
    return canonical_json(cert_fields)


def issue_certificate(ca_sk: Ed25519PrivateKey, *, subject: str, subject_pk: Ed25519PublicKey, issuer: str) -> Certificate:
    tbs_fields = {"subject": subject, "issuer": issuer, "public_key": b64e(encode_public_key(subject_pk))}
    sig = sign_ed25519(ca_sk, _tbs(tbs_fields))
    return Certificate(
        subject=subject,
        issuer=issuer,
        public_key_b64=tbs_fields["public_key"],
        signature_b64=b64e(sig),
    )


def verify_certificate(ca_pk: Ed25519PublicKey, cert: Certificate) -> Ed25519PublicKey:
    tbs_fields = {"subject": cert.subject, "issuer": cert.issuer, "public_key": cert.public_key_b64}
    sig = b64d(cert.signature_b64)
    try:
        verify_ed25519(ca_pk, sig, _tbs(tbs_fields))
    except InvalidSignature as e:
        raise InvalidSignature("certificate signature invalid") from e
    return decode_public_key(b64d(cert.public_key_b64))


def save_cert(path: str, cert: Certificate) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cert.to_dict(), f, sort_keys=True, indent=2)


def load_cert(path: str) -> Certificate:
    with open(path, "r", encoding="utf-8") as f:
        return Certificate.from_dict(json.load(f))

