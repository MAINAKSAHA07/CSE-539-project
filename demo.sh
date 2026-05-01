#!/usr/bin/env bash
# Reproducible demo: PKI → register user → server + client (success + wrong password).
set -euo pipefail
cd "$(dirname "$0")"

export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-4444}"

if pids="$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null)"; then
  echo "demo.sh: freeing port $PORT (PIDs: $pids)"
  kill $pids 2>/dev/null || true
  sleep 0.5
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install -q -r requirements.txt

echo "=== ca_setup ==="
python ca_setup.py

echo "=== register_user (USERNAME=${USERNAME:-alice}) ==="
python register_user.py

echo "=== start server ==="
python server.py &
srv_pid=$!
cleanup() { kill "$srv_pid" 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

echo "=== client (correct password) ==="
python client.py

echo "=== client (wrong password; expect failure) ==="
set +e
PASSWORD=wrong python client.py
wrong_rc=$?
set -e
if [[ "$wrong_rc" -eq 0 ]]; then
  echo "demo.sh: expected wrong-password client to fail" >&2
  exit 1
fi

echo "=== demo OK ==="
