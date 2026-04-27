# CSE 539 Project — TLS-like Handshake with PAKE (Baseline)

This repo implements a minimal, runnable baseline for the course project:

- Two processes (`client.py`, `server.py`) communicating over `127.0.0.1` sockets.
- A simple CA and server certificate stored as files.
- Server handshake messages are signed; client verifies certificate and handshake transcript signature.

PAKE + HKDF + AEAD are scaffolded as modules and will be layered next.

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

## Run the handshake baseline

Terminal 1:

```bash
python3 server.py
```

Terminal 2:

```bash
python3 client.py
```

Expected behavior:

- Client connects, sends `client_hello`.
- Server responds with `server_hello`, its certificate, and a signature over the handshake transcript.
- Client verifies (1) CA signature on certificate, then (2) server signature on the handshake transcript.

## Project structure

```text
.
├── client.py
├── server.py
├── ca_setup.py
├── register_user.py            # (PAKE setup phase placeholder for now)
├── crypto_utils/
│   ├── utils.py
│   ├── framing.py
│   ├── signatures.py
│   └── certs.py
├── certs/
├── data/
└── report/
```

