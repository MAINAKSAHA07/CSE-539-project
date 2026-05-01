"""
Setup-phase user registration (before any handshake).

Runs the OPRF steps locally (client + server roles in one process) to produce:
- ``oprf_sk``: server-held OPRF key (per user)
- ``pw_key``: symmetric key material derived from the OPRF output (used in PAKE proofs)

The raw password is not stored.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from crypto_utils.oprf import (
    oprf_blind,
    oprf_evaluate,
    oprf_finalize,
    pw_key_from_oprf_output,
    random_server_oprf_scalar,
)
from crypto_utils.utils import b64e


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_PATH = DATA_DIR / "users.json"


def main() -> None:
    username = os.environ.get("USERNAME", "alice")
    password = os.environ.get("PASSWORD", "correct horse battery staple")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    users = {}
    if USERS_PATH.exists():
        users = json.loads(USERS_PATH.read_text(encoding="utf-8"))

    oprf_sk = random_server_oprf_scalar()
    blinded, st = oprf_blind(password)
    evaluated = oprf_evaluate(oprf_sk, blinded)
    oprf_out = oprf_finalize(st, evaluated)
    pw_key = pw_key_from_oprf_output(oprf_out)

    users[username] = {"oprf_sk": b64e(oprf_sk), "pw_key": b64e(pw_key)}
    USERS_PATH.write_text(json.dumps(users, sort_keys=True, indent=2), encoding="utf-8")
    print(f"[register_user] registered {username} (OPRF + pw_key) in data/users.json")


if __name__ == "__main__":
    main()
