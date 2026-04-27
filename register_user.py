from __future__ import annotations

import json
import os
from pathlib import Path

from crypto_utils.passwords import derive_password_key, new_salt
from crypto_utils.utils import b64e


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_PATH = DATA_DIR / "users.json"


def main() -> None:
    """
    Setup-phase registration (before handshake), as required by the PDF.

    Stores a per-user salt and a password-derived key (no raw password stored).
    """
    username = os.environ.get("USERNAME", "alice")
    password = os.environ.get("PASSWORD", "correct horse battery staple")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    users = {}
    if USERS_PATH.exists():
        users = json.loads(USERS_PATH.read_text(encoding="utf-8"))

    salt = new_salt()
    pw_key = derive_password_key(password, salt)

    users[username] = {"salt": b64e(salt), "pw_key": b64e(pw_key)}
    USERS_PATH.write_text(json.dumps(users, sort_keys=True, indent=2), encoding="utf-8")
    print(f"[register_user] registered {username} in data/users.json")


if __name__ == "__main__":
    main()

