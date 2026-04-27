# CSE 539 Project — TLS Handshake with PAKE (Working)

This repo implements a runnable protocol for the course project:

- Two processes (`client.py`, `server.py`) communicating over `127.0.0.1` sockets.
- A simple CA and server certificate stored as files.
- Server handshake messages are signed; client verifies certificate and handshake transcript signature.
- Client authenticates to the server using a password-based PAKE-style exchange (setup registration + online proofs).
- Session keys are derived using HKDF (TLS 1.3-style “traffic secrets” concept).
- Post-handshake application data is protected with AEAD (AES-GCM).

## Setup

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Generate CA + server certificate

```bash
python3 ca_setup.py
```

This writes keys/certs under `certs/`.

Note: private keys are generated locally and are **ignored by git** (see `.gitignore`).

## Register a user (setup phase)
Note: `data/users.json` is a **local artifact** and is **ignored by git** (see `.gitignore`).

This is required by the PDF: password registration happens **before** the handshake.

```bash
python3 register_user.py
```

Defaults are `USERNAME=alice` and `PASSWORD="correct horse battery staple"`. You can override:

```bash
USERNAME=alice PASSWORD="mypassword" python3 register_user.py
```

## Run the full handshake + secure channel

Terminal 1:

```bash
python3 server.py
```

Terminal 2:

```bash
python3 client.py
```

Expected behavior:

- Client verifies **server certificate** (CA-signed) and **server handshake signature**.
- Client and server run a **password-authenticated key exchange** and mutually verify password proofs.
- Both derive the same session keys via **HKDF**.
- Client sends one **AES-GCM encrypted** message; server decrypts and replies encrypted; client decrypts.

## Failure cases to demo (for report)

- Wrong password:

```bash
USERNAME=alice PASSWORD="wrong" python3 client.py
```

- No user registered:
  - Delete `data/users.json` and rerun `python3 server.py` then `python3 client.py` to see failure.

## Project structure

```text
.
├── client.py
├── server.py
├── ca_setup.py
├── register_user.py
├── crypto_utils/
│   ├── utils.py
│   ├── framing.py
│   ├── signatures.py
│   └── certs.py
├── certs/
├── data/
└── report/
```

