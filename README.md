# Hybrid Cryptographic Local Messenger

Design and evaluation of a multi-stage hybrid cryptographic framework for secure **local** messaging and file transfer. The chat UI is the demonstration platform. The research artefact is the pipeline around X25519, ML-KEM, HKDF, AES-GCM, ChaCha20-Poly1305, SHA-3/HMAC, Ed25519, ML-DSA, and Argon2id.

## Architecture

- **Hub PC** runs the coordinator, SQLite database, and FTP server. Encrypted messages and files are stored as FTP blobs.
- **Each workstation** holds private keys. The peer PC never hosts the database.

X25519 and ML-KEM run **in parallel**. Custom stages bind, mix, and separate keys:

1. **CT1** — context-bound HKDF extract on the X25519 secret  
2. **CT2** — KDF hybrid mixer of classical + ML-KEM secrets  
3. **CT3** — labeled key diversification (message / file / MAC, A→B / B→A)  
4. **CT4** — ciphertext bound in AEAD AAD (session, seq, peers, profile)  
5. **CT5** — HMAC-SHA3 over the canonical header plus replay window  

The **baseline** is concatenate-then-HKDF with a single shared key and no AAD/replay binding.

## Two PCs on a local network (no Internet)

The **hub PC** (sender side) stores the database and runs FTP. The **peer PC** (receiver) keeps its own private-key vault and pulls/pushes **ciphertext only** over FTP.

| What | Where |
|---|---|
| SQLite DB | Hub: `data/coordinator/cns.sqlite` |
| Encrypted blobs | Hub: `data/ftp/*.bin` (served over FTP port 2121) |
| Private keys | Each PC: `data/workstations/<name>/vault.bin` |

**Hub PC**

```bash
python -m cns host
```

Open http://127.0.0.1:8101 and register (e.g. `alice`). Note the LAN IP printed in the terminal (example `192.168.1.10`). Allow TCP **8000**, **2121**, and **50100–50120** in Windows Firewall (Private).

**Receiver PC** (same project copied, do not copy `data/workstations` from the other person)

```bash
python -m cns peer --hub 192.168.1.10
```

Open http://127.0.0.1:8102, register `bob`, then open a session with Alice. Chat and file send use FTP for the encrypted payload.

You can also type the hub IP in the UI (**Connect to hub**) instead of `--hub`.

Both PCs must be on the same LAN (Ethernet, Wi‑Fi, or a cable with static IPs). No Internet is required.

## Single-PC demo

Then:

1. Open Alice at http://127.0.0.1:8101 — register `alice`
2. Open Bob at http://127.0.0.1:8102 — register `bob`
3. Open a session, chat, and send a file (ciphertext goes over FTP even on one PC)

```bash
python -m cns eval
```

## Tests

```bash
pytest -q
```

## Threat model (local demo)

Plaintext and private keys never leave the workstation process. The coordinator and FTP operator are assumed able to read stored ciphertext and metadata. Session material is dropped when a session is expired.
