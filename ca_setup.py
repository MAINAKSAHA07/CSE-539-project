from __future__ import annotations

import os
from pathlib import Path

from crypto_utils.certs import issue_certificate, save_cert
from crypto_utils.signatures import (
    encode_private_key,
    encode_public_key,
    generate_ed25519_keypair,
)


BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    issuer = os.environ.get("CA_NAME", "local_ca")

    ca_sk, ca_pk = generate_ed25519_keypair()
    server_sk, server_pk = generate_ed25519_keypair()

    # Store raw Ed25519 keys (simple + deterministic).
    write_bytes(CERTS_DIR / "ca_sk.bin", encode_private_key(ca_sk))
    write_bytes(CERTS_DIR / "ca_pk.bin", encode_public_key(ca_pk))
    write_bytes(CERTS_DIR / "server_sk.bin", encode_private_key(server_sk))
    write_bytes(CERTS_DIR / "server_pk.bin", encode_public_key(server_pk))

    cert = issue_certificate(ca_sk, subject="server", subject_pk=server_pk, issuer=issuer)
    save_cert(str(CERTS_DIR / "server_cert.json"), cert)

    print("[ca_setup] wrote CA keys, server keys, and server_cert.json to certs/")


if __name__ == "__main__":
    main()

