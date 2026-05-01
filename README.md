# CSE 539 Project — TLS Handshake with PAKE (Working)

This repo implements a runnable protocol for the course project:

- Two processes (`client.py`, `server.py`) communicating over `127.0.0.1` sockets.
- A simple CA and server certificate stored as files.
- Server handshake messages are signed; client verifies certificate and handshake transcript signature.
- **OPRF** (oblivious PRF, OPAQUE-flavored password hardening) + **PAKE** (X25519 + mutual HMAC proofs).
- **HKDF** with explicit **handshake traffic secret** and **application traffic secret** stages (TLS 1.3–style naming).
- Post-handshake application data is protected with **AEAD (AES-GCM)**.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Generate CA + server certificate

```bash
python3 ca_setup.py
```

This writes keys/certs under `certs/`. Private signing keys are **not** committed (see `.gitignore`).

## Register a user (setup phase)

Password registration happens **before** the handshake. Registration runs the OPRF locally and stores the server’s OPRF key plus derived `pw_key` in `data/users.json` (gitignored).

```bash
python3 register_user.py
```

Override defaults:

```bash
USERNAME=alice PASSWORD="mypassword" python3 register_user.py
```

## Handshake message order (high level)

1. `client_hello` (includes `username`)
2. `server_hello`, `certificate`, `handshake_signature`
3. `oprf_blind` → `oprf_eval`
4. `pake_server_1` → `pake_client_1` → `pake_server_2`
5. `app_data` (AES-GCM) ↔ `app_data`

## Run the full handshake + secure channel

Terminal 1:

```bash
python3 server.py
```

Terminal 2:

```bash
python3 client.py
```

## One-shot demo script

Runs PKI setup, registration, successful client, then a **wrong-password** attempt (must fail):

```bash
chmod +x demo.sh
./demo.sh
```

## Failure cases (for report / TA)

- Wrong password (expect a clear client exit, non-zero status):

```bash
USERNAME=alice PASSWORD="wrong" python3 client.py
```

- No user registered: delete `data/users.json` and connect with `client.py`.

- **AEAD / integrity (optional):** after a successful handshake, corrupt the client’s ciphertext to show the server rejects bad application data:

```bash
CLIENT_CORRUPT_AEAD=1 python3 client.py
```

- **Invalid certificate / signature:** use a mismatched `certs/ca_pk.bin` (e.g. from another `ca_setup.py` run) while the server still presents `server_cert.json` from a different CA — the client should fail CA verification or transcript signature with an explicit message.

## Pre-submission checklist (PDF + Canvas)

- [ ] Clean checkout: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- [ ] `python3 ca_setup.py` then `python3 register_user.py` then run `server.py` + `client.py` (or `./demo.sh`)
- [ ] `requirements.txt` lists all dependencies (including PyNaCl)
- [ ] Add **report** under `report/` (architecture, security intuition, implementation) and include **`project.pdf`** if your instructor expects it
- [ ] Zip **one folder** with code + report for Canvas

## Project structure

```text
.
├── client.py
├── server.py
├── ca_setup.py
├── register_user.py
├── demo.sh
├── crypto_utils/
│   ├── framing.py
│   ├── utils.py
│   ├── signatures.py
│   ├── certs.py
│   ├── oprf.py
│   ├── pake.py
│   ├── hkdf.py
│   └── aead.py
├── certs/
├── data/
└── report/
```
