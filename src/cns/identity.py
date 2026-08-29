from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cns.crypto import (
    IdentityKeySet,
    argon2id_key,
    generate_identity,
    load_ed25519_sk,
    load_x25519_sk,
    serialize_ed25519_sk,
    serialize_x25519_sk,
)


def vault_path(root: Path) -> Path:
    return root / "vault.bin"


def save_vault(root: Path, keys: IdentityKeySet, password: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "ed25519_sk": serialize_ed25519_sk(keys.ed25519_sk).hex(),
        "x25519_sk": serialize_x25519_sk(keys.x25519_sk).hex(),
        "mlkem_ek": keys.mlkem_ek.hex(),
        "mlkem_dk": keys.mlkem_dk.hex(),
        "mldsa_pk": keys.mldsa_pk.hex(),
        "mldsa_sk": keys.mldsa_sk.hex(),
        "ed25519_pk": keys.ed25519_pk.hex(),
        "x25519_pk": keys.x25519_pk.hex(),
    }
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = argon2id_key(password, salt)
    blob = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), b"cns-vault")
    vault_path(root).write_bytes(b"CNS1" + salt + nonce + blob)


def load_vault(root: Path, password: str) -> IdentityKeySet:
    raw = vault_path(root).read_bytes()
    if not raw.startswith(b"CNS1"):
        raise ValueError("invalid vault")
    salt, nonce, blob = raw[4:20], raw[20:32], raw[32:]
    key = argon2id_key(password, salt)
    data = json.loads(AESGCM(key).decrypt(nonce, blob, b"cns-vault"))
    ed_sk = load_ed25519_sk(bytes.fromhex(data["ed25519_sk"]))
    x_sk = load_x25519_sk(bytes.fromhex(data["x25519_sk"]))
    return IdentityKeySet(
        ed25519_sk=ed_sk,
        ed25519_pk=bytes.fromhex(data["ed25519_pk"]),
        x25519_sk=x_sk,
        x25519_pk=bytes.fromhex(data["x25519_pk"]),
        mlkem_ek=bytes.fromhex(data["mlkem_ek"]),
        mlkem_dk=bytes.fromhex(data["mlkem_dk"]),
        mldsa_pk=bytes.fromhex(data["mldsa_pk"]),
        mldsa_sk=bytes.fromhex(data["mldsa_sk"]),
    )


def create_identity_vault(root: Path, password: str) -> IdentityKeySet:
    keys = generate_identity()
    save_vault(root, keys, password)
    return keys
