from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

MLKEM = ML_KEM_768
MLDSA = ML_DSA_65


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_sha256(ikm: bytes, *, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def hmac_sha3(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA3_256())
    h.update(data)
    return h.finalize()


def argon2id_key(password: str, salt: bytes, length: int = 32) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=length,
        type=Type.ID,
    )


def lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def encode_fields(*parts: bytes) -> bytes:
    return b"".join(lp(p) for p in parts)


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, blob, aad)


def chacha_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def chacha_decrypt(key: bytes, nonce: bytes, blob: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, blob, aad)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


@dataclass(frozen=True)
class IdentityKeySet:
    ed25519_sk: ed25519.Ed25519PrivateKey
    ed25519_pk: bytes
    x25519_sk: x25519.X25519PrivateKey
    x25519_pk: bytes
    mlkem_ek: bytes
    mlkem_dk: bytes
    mldsa_pk: bytes
    mldsa_sk: bytes

    def public_bundle(self) -> dict[str, str]:
        return {
            "ed25519_pk": self.ed25519_pk.hex(),
            "x25519_pk": self.x25519_pk.hex(),
            "mlkem_ek": self.mlkem_ek.hex(),
            "mldsa_pk": self.mldsa_pk.hex(),
        }


def generate_identity() -> IdentityKeySet:
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    x_sk = x25519.X25519PrivateKey.generate()
    ek, dk = MLKEM.keygen()
    mldsa_pk, mldsa_sk = MLDSA.keygen()
    return IdentityKeySet(
        ed25519_sk=ed_sk,
        ed25519_pk=ed_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        x25519_sk=x_sk,
        x25519_pk=x_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        mlkem_ek=ek,
        mlkem_dk=dk,
        mldsa_pk=mldsa_pk,
        mldsa_sk=mldsa_sk,
    )


def x25519_shared(sk: x25519.X25519PrivateKey, peer_pk: bytes) -> bytes:
    pub = x25519.X25519PublicKey.from_public_bytes(peer_pk)
    return sk.exchange(pub)


def generate_x25519() -> tuple[x25519.X25519PrivateKey, bytes]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pk


def mlkem_encaps(ek: bytes) -> tuple[bytes, bytes]:
    key, ct = MLKEM.encaps(ek)
    return key, ct


def mlkem_decaps(dk: bytes, ct: bytes) -> bytes:
    return MLKEM.decaps(dk, ct)


def ed25519_sign(sk: ed25519.Ed25519PrivateKey, msg: bytes) -> bytes:
    return sk.sign(msg)


def ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except Exception:
        return False


def mldsa_sign(sk: bytes, msg: bytes) -> bytes:
    return MLDSA.sign(sk, msg)


def mldsa_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(MLDSA.verify(pk, msg, sig))
    except Exception:
        return False


def serialize_ed25519_sk(sk: ed25519.Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_x25519_sk(sk: x25519.X25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_ed25519_sk(raw: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def load_x25519_sk(raw: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(raw)
