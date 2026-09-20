"""Live CT1–CT5 pipeline simulation for the UI demo panel."""

from __future__ import annotations

from cns.config import CONSTRUCTION_PROPOSED
from cns.crypto import random_bytes, sha3_256
from cns.crypto.pipeline import (
    ct1_context_bind,
    ct2_hybrid_mixer,
    ct3_diversify,
    ct4_aad,
    encrypt_payload,
    session_context,
)


STAGES = [
    {
        "id": "x25519",
        "title": "X25519 (classical KEM)",
        "detail": "Ephemeral Diffie–Hellman produces ss_x. Used as a toolbox primitive — not our novel contribution.",
    },
    {
        "id": "ct1",
        "title": "CT1 · Context-Bound Secret",
        "detail": "HKDF-binds ss_x to session context (protocol, peers, ephemeral keys). Stops identity misbinding / cross-session reuse.",
    },
    {
        "id": "mlkem",
        "title": "ML-KEM (post-quantum KEM)",
        "detail": "Independent PQ encapsulation produces ss_k. Parallel to X25519 — not chained after it.",
    },
    {
        "id": "ct2",
        "title": "CT2 · Hybrid Secret Mixer",
        "detail": "KDF-combines CT1 output with ss_k (not raw concat). Partial-compromise binding if either side fails.",
    },
    {
        "id": "hkdf",
        "title": "HKDF / SHA-3 family",
        "detail": "Standard extract/expand used inside our stages as a cryptographic toolbox component.",
    },
    {
        "id": "ct3",
        "title": "CT3 · Key Diversification",
        "detail": "Labeled HKDF-Expand → separate msg / file / mac / nonce keys and A→B vs B→A directions.",
    },
    {
        "id": "aead",
        "title": "AES-GCM / ChaCha20-Poly1305",
        "detail": "Symmetric AEAD encrypts the payload. Established algorithm — selected, not reinvented.",
    },
    {
        "id": "ct4",
        "title": "CT4 · Ciphertext Context Binding",
        "detail": "Dense AAD (session, seq, peers, kind, profile) locks ciphertext to its metadata.",
    },
    {
        "id": "ct5",
        "title": "CT5 · Integrity & Replay",
        "detail": "HMAC-SHA3 over canonical header + ciphertext, plus monotonic sequence / replay window.",
    },
]


def simulate_pipeline(plaintext: str = "Hello Bob") -> dict:
    """Run a self-contained CT1–CT5 demo and return stage outputs for the UI."""
    ss_x = random_bytes(32)
    ss_k = random_bytes(32)
    eph = random_bytes(32)
    mlct = random_bytes(64)
    session_id = "demo-" + sha3_256(eph)[:4].hex()
    ctx = session_context(
        session_id=session_id,
        initiator_id="alice",
        responder_id="bob",
        eph_x25519_pk=eph,
        mlkem_ct=mlct,
        construction=CONSTRUCTION_PROPOSED,
    )
    bound = ct1_context_bind(ss_x, ctx)
    hybrid = ct2_hybrid_mixer(bound, ss_k, ctx)
    keys = ct3_diversify(hybrid, session_id)
    pt = plaintext.encode("utf-8")
    payload = encrypt_payload(
        keys=keys.a2b,
        plaintext=pt,
        session_id=session_id,
        seq=1,
        sender_id="alice",
        receiver_id="bob",
        kind="msg",
        construction=CONSTRUCTION_PROPOSED,
    )
    aad = ct4_aad(
        session_id=session_id,
        seq=1,
        sender_id="alice",
        receiver_id="bob",
        kind="msg",
        profile=payload["profile"],
        nonce=bytes.fromhex(payload["nonce"]),
        construction=CONSTRUCTION_PROPOSED,
    )
    stages = [
        {**STAGES[0], "status": "done", "output": f"ss_x = {ss_x[:8].hex()}… ({len(ss_x)} bytes)"},
        {**STAGES[1], "status": "done", "output": f"bound = {bound[:8].hex()}…  context={len(ctx)}B"},
        {**STAGES[2], "status": "done", "output": f"ss_k = {ss_k[:8].hex()}… ({len(ss_k)} bytes)"},
        {**STAGES[3], "status": "done", "output": f"hybrid = {hybrid[:8].hex()}…"},
        {**STAGES[4], "status": "done", "output": "HKDF-SHA256 used inside CT1–CT3"},
        {
            **STAGES[5],
            "status": "done",
            "output": (
                f"msg={keys.a2b.msg[:6].hex()}… file={keys.a2b.file[:6].hex()}… "
                f"mac={keys.a2b.mac[:6].hex()}… (isolated)"
            ),
        },
        {
            **STAGES[6],
            "status": "done",
            "output": f"ciphertext = {payload['ciphertext'][:16]}…  profile={payload['profile']}",
        },
        {**STAGES[7], "status": "done", "output": f"AAD = {aad[:12].hex()}… ({len(aad)} bytes)"},
        {
            **STAGES[8],
            "status": "done",
            "output": f"HMAC = {payload['mac'][:16]}…  seq={payload['seq']}  replay window armed",
        },
    ]
    return {
        "session_id": session_id,
        "plaintext": plaintext,
        "construction": CONSTRUCTION_PROPOSED,
        "stages": stages,
        "summary": (
            "We do not invent X25519 / ML-KEM / AES / HKDF. "
            "Our contribution is the CT1–CT5 multi-stage construction around them."
        ),
    }


def stage_catalog() -> list[dict]:
    return list(STAGES)
