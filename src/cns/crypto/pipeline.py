from __future__ import annotations

from dataclasses import dataclass

from cns import PROTOCOL_VERSION
from cns.config import AES_PROFILE, CHACHA_PROFILE, CONSTRUCTION_BASELINE, CONSTRUCTION_PROPOSED
from cns.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    chacha_decrypt,
    chacha_encrypt,
    encode_fields,
    hkdf_sha256,
    hmac_sha3,
    sha3_256,
)


def session_context(
    *,
    session_id: str,
    initiator_id: str,
    responder_id: str,
    eph_x25519_pk: bytes,
    mlkem_ct: bytes,
    construction: str,
) -> bytes:
    return encode_fields(
        PROTOCOL_VERSION.encode(),
        construction.encode(),
        session_id.encode(),
        initiator_id.encode(),
        responder_id.encode(),
        eph_x25519_pk,
        sha3_256(mlkem_ct),
    )


def ct1_context_bind(ss_x: bytes, context: bytes) -> bytes:
    """Bind the classical shared secret to session/protocol context."""
    salt = sha3_256(b"CNS-CT1-v1" + context)
    return hkdf_sha256(ss_x, salt=salt, info=b"ct1-context-bound", length=32)


def ct2_hybrid_mixer(ss_x_bound: bytes, ss_k: bytes, context: bytes) -> bytes:
    """KDF combiner of classical and ML-KEM secrets (not XOR/concat alone)."""
    salt = sha3_256(b"CNS-CT2-v1" + context)
    ikm = encode_fields(ss_x_bound, ss_k)
    return hkdf_sha256(ikm, salt=salt, info=b"ct2-hybrid-mixer", length=32)


def ct2_nested_mixer(ss_x_bound: bytes, ss_k: bytes, context: bytes) -> bytes:
    inner = hkdf_sha256(ss_k, salt=sha3_256(b"CNS-CT2-nested-pq" + context), info=b"pq", length=32)
    return hkdf_sha256(ss_x_bound, salt=inner, info=b"ct2-nested-classical", length=32)


def baseline_mix(ss_x: bytes, ss_k: bytes) -> bytes:
    return hkdf_sha256(ss_x + ss_k, salt=None, info=b"baseline-concat-hkdf", length=32)


@dataclass(frozen=True)
class DirectionKeys:
    msg: bytes
    file: bytes
    mac: bytes
    nonce_seed: bytes


@dataclass(frozen=True)
class SessionKeys:
    a2b: DirectionKeys
    b2a: DirectionKeys
    hybrid_secret: bytes


def ct3_diversify(prk: bytes, session_id: str) -> SessionKeys:
    """Purpose- and direction-separated keys via labeled HKDF-Expand."""

    def expand(label: str) -> bytes:
        return hkdf_sha256(
            prk,
            salt=session_id.encode(),
            info=b"ct3|" + label.encode(),
            length=32,
        )

    def direction(prefix: str) -> DirectionKeys:
        return DirectionKeys(
            msg=expand(f"{prefix}|msg"),
            file=expand(f"{prefix}|file"),
            mac=expand(f"{prefix}|mac"),
            nonce_seed=expand(f"{prefix}|nonce"),
        )

    return SessionKeys(a2b=direction("a2b"), b2a=direction("b2a"), hybrid_secret=prk)


def derive_session_keys(
    *,
    ss_x: bytes,
    ss_k: bytes,
    context: bytes,
    session_id: str,
    construction: str,
) -> SessionKeys:
    if construction == CONSTRUCTION_BASELINE:
        prk = baseline_mix(ss_x, ss_k)
        # Baseline uses one key family copied across purposes (intentionally weak isolation).
        shared = hkdf_sha256(prk, salt=None, info=b"baseline-single-key", length=32)
        one = DirectionKeys(msg=shared, file=shared, mac=shared, nonce_seed=shared)
        return SessionKeys(a2b=one, b2a=one, hybrid_secret=prk)

    if construction != CONSTRUCTION_PROPOSED:
        raise ValueError(f"unknown construction {construction}")
    bound = ct1_context_bind(ss_x, context)
    hybrid = ct2_hybrid_mixer(bound, ss_k, context)
    return ct3_diversify(hybrid, session_id)


def nonce_from_seq(nonce_seed: bytes, seq: int) -> bytes:
    return hkdf_sha256(nonce_seed, salt=seq.to_bytes(8, "big"), info=b"nonce12", length=12)


def ct4_aad(
    *,
    session_id: str,
    seq: int,
    sender_id: str,
    receiver_id: str,
    kind: str,
    profile: str,
    nonce: bytes,
    construction: str,
) -> bytes:
    return encode_fields(
        b"CNS-CT4-v1",
        PROTOCOL_VERSION.encode(),
        construction.encode(),
        session_id.encode(),
        seq.to_bytes(8, "big"),
        sender_id.encode(),
        receiver_id.encode(),
        kind.encode(),
        profile.encode(),
        nonce,
    )


def encrypt_payload(
    *,
    keys: DirectionKeys,
    plaintext: bytes,
    session_id: str,
    seq: int,
    sender_id: str,
    receiver_id: str,
    kind: str,
    construction: str,
) -> dict:
    profile = CHACHA_PROFILE if kind == "file" else AES_PROFILE
    nonce = nonce_from_seq(keys.nonce_seed, seq)
    aad = ct4_aad(
        session_id=session_id,
        seq=seq,
        sender_id=sender_id,
        receiver_id=receiver_id,
        kind=kind,
        profile=profile,
        nonce=nonce,
        construction=construction,
    )
    if construction == CONSTRUCTION_BASELINE:
        aad = b""
        nonce = nonce_from_seq(keys.nonce_seed, seq)
    if profile == AES_PROFILE:
        blob = aes_gcm_encrypt(keys.msg if kind == "msg" else keys.file, nonce, plaintext, aad)
    else:
        blob = chacha_encrypt(keys.file, nonce, plaintext, aad)

    header = encode_fields(
        session_id.encode(),
        seq.to_bytes(8, "big"),
        sender_id.encode(),
        receiver_id.encode(),
        kind.encode(),
        profile.encode(),
        nonce,
        blob,
    )
    mac = hmac_sha3(keys.mac, b"CNS-CT5-v1" + header) if construction == CONSTRUCTION_PROPOSED else hmac_sha3(keys.mac, blob)
    return {
        "v": PROTOCOL_VERSION,
        "construction": construction,
        "session_id": session_id,
        "seq": seq,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "kind": kind,
        "profile": profile,
        "nonce": nonce.hex(),
        "ciphertext": blob.hex(),
        "mac": mac.hex(),
    }


def verify_mac(keys: DirectionKeys, payload: dict) -> bool:
    blob = bytes.fromhex(payload["ciphertext"])
    nonce = bytes.fromhex(payload["nonce"])
    construction = payload["construction"]
    header = encode_fields(
        payload["session_id"].encode(),
        int(payload["seq"]).to_bytes(8, "big"),
        payload["sender_id"].encode(),
        payload["receiver_id"].encode(),
        payload["kind"].encode(),
        payload["profile"].encode(),
        nonce,
        blob,
    )
    expected = hmac_sha3(keys.mac, b"CNS-CT5-v1" + header) if construction == CONSTRUCTION_PROPOSED else hmac_sha3(keys.mac, blob)
    return expected == bytes.fromhex(payload["mac"])


def decrypt_payload(keys: DirectionKeys, payload: dict) -> bytes:
    construction = payload["construction"]
    kind = payload["kind"]
    profile = payload["profile"]
    nonce = bytes.fromhex(payload["nonce"])
    blob = bytes.fromhex(payload["ciphertext"])
    aad = b""
    if construction == CONSTRUCTION_PROPOSED:
        aad = ct4_aad(
            session_id=payload["session_id"],
            seq=int(payload["seq"]),
            sender_id=payload["sender_id"],
            receiver_id=payload["receiver_id"],
            kind=kind,
            profile=profile,
            nonce=nonce,
            construction=construction,
        )
    key = keys.file if kind == "file" else keys.msg
    if profile == AES_PROFILE:
        return aes_gcm_decrypt(key, nonce, blob, aad)
    return chacha_decrypt(key, nonce, blob, aad)
