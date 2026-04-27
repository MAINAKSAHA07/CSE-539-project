from __future__ import annotations

import base64
import json
from typing import Any


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canonical_json(obj: Any) -> bytes:
    """
    Canonical JSON bytes for signing/verification.
    - stable key order
    - no extra whitespace
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

