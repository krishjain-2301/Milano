from __future__ import annotations

import math
from collections import Counter
from typing import Callable

from cns.config import CONSTRUCTION_BASELINE, CONSTRUCTION_PROPOSED
from cns.crypto import generate_identity, random_bytes
from cns.crypto.pipeline import (
    ct1_context_bind,
    ct2_hybrid_mixer,
    decrypt_payload,
    derive_session_keys,
    encrypt_payload,
    session_context,
    verify_mac,
)
from cns.crypto.replay import ReplayWindow
from cns.session import accept_session, open_session


def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=True))


def avalanche_ratio(f: Callable[[bytes], bytes], blob: bytes, trials: int = 64) -> float:
    ratios = []
    out0 = f(blob)
    bits = len(out0) * 8
    for i in range(trials):
        flipped = bytearray(blob)
        bit = i % bits if bits else 0
        # flip a bit in the input, wrapping if input shorter
        idx = (i // 8) % len(flipped)
        flipped[idx] ^= 1 << (i % 8)
        out1 = f(bytes(flipped))
        n = min(len(out0), len(out1))
        ratios.append(hamming(out0[:n], out1[:n]) / (n * 8))
    return sum(ratios) / len(ratios)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def correlation(a: bytes, b: bytes) -> float:
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    xa = [a[i] for i in range(n)]
    xb = [b[i] for i in range(n)]
    ma, mb = sum(xa) / n, sum(xb) / n
    num = sum((xa[i] - ma) * (xb[i] - mb) for i in range(n))
    da = math.sqrt(sum((x - ma) ** 2 for x in xa))
    db = math.sqrt(sum((x - mb) ** 2 for x in xb))
    if da == 0 or db == 0:
        return 0.0
    return num / (da * db)


def _fresh_pair():
    alice = generate_identity()
    bob = generate_identity()
    return alice, bob


def evaluate() -> dict:
    alice, bob = _fresh_pair()
    offer_p, keys_p, _ = open_session(
        alice, my_id="A", peer_id="B", peer_x25519_pk=bob.x25519_pk, peer_mlkem_ek=bob.mlkem_ek, construction=CONSTRUCTION_PROPOSED
    )
    keys_p_b = accept_session(bob, offer_p)
    offer_b, keys_b, _ = open_session(
        alice, my_id="A", peer_id="B", peer_x25519_pk=bob.x25519_pk, peer_mlkem_ek=bob.mlkem_ek, construction=CONSTRUCTION_BASELINE
    )
    keys_b_b = accept_session(bob, offer_b)

    assert keys_p.a2b.msg == keys_p_b.a2b.msg
    assert keys_b.a2b.msg == keys_b_b.a2b.msg

    ss_x = random_bytes(32)
    ss_k = random_bytes(32)
    ctx = session_context(
        session_id="sid-eval",
        initiator_id="A",
        responder_id="B",
        eph_x25519_pk=random_bytes(32),
        mlkem_ct=random_bytes(64),
        construction=CONSTRUCTION_PROPOSED,
    )

    av_ct1 = avalanche_ratio(lambda x: ct1_context_bind(x, ctx), ss_x)
    av_ct2 = avalanche_ratio(lambda x: ct2_hybrid_mixer(ss_x, x, ctx), ss_k)
    av_base = avalanche_ratio(lambda x: derive_session_keys(ss_x=x, ss_k=ss_k, context=ctx, session_id="s", construction=CONSTRUCTION_BASELINE).hybrid_secret, ss_x)

    def key_sens(construction: str) -> float:
        k0 = derive_session_keys(ss_x=ss_x, ss_k=ss_k, context=ctx, session_id="s", construction=construction)
        ss_x2 = bytearray(ss_x)
        ss_x2[0] ^= 1
        k1 = derive_session_keys(ss_x=bytes(ss_x2), ss_k=ss_k, context=ctx, session_id="s", construction=construction)
        return hamming(k0.hybrid_secret, k1.hybrid_secret) / 256

    pt = b"Hello Bob" * 8
    enc_p = encrypt_payload(
        keys=keys_p.a2b, plaintext=pt, session_id=offer_p.session_id, seq=1, sender_id="A", receiver_id="B", kind="msg", construction=CONSTRUCTION_PROPOSED
    )
    enc_b = encrypt_payload(
        keys=keys_b.a2b, plaintext=pt, session_id=offer_b.session_id, seq=1, sender_id="A", receiver_id="B", kind="msg", construction=CONSTRUCTION_BASELINE
    )
    ct_p = bytes.fromhex(enc_p["ciphertext"])
    ct_b = bytes.fromhex(enc_b["ciphertext"])

    # Key isolation: proposed keys differ; baseline keys are identical.
    isol_p = keys_p.a2b.msg != keys_p.a2b.file and keys_p.a2b.msg != keys_p.a2b.mac
    isol_b = keys_b.a2b.msg != keys_b.a2b.file  # False in baseline by design

    # Cross-purpose decrypt: try file key on message ciphertext (proposed should fail)
    def cross_purpose(keys, payload, construction):
        from cns.crypto.pipeline import DirectionKeys

        swapped = DirectionKeys(msg=keys.file, file=keys.msg, mac=keys.mac, nonce_seed=keys.nonce_seed)
        try:
            decrypt_payload(swapped, payload)
            return False
        except Exception:
            return True

    # Session isolation: keys from another session cannot decrypt
    offer2, keys2, _ = open_session(
        alice, my_id="A", peer_id="B", peer_x25519_pk=bob.x25519_pk, peer_mlkem_ek=bob.mlkem_ek, construction=CONSTRUCTION_PROPOSED
    )
    sess_iso = True
    try:
        decrypt_payload(keys2.a2b, enc_p)
        sess_iso = False
    except Exception:
        sess_iso = True

    # Tamper
    tampered = dict(enc_p)
    raw = bytearray(bytes.fromhex(tampered["ciphertext"]))
    raw[0] ^= 0xFF
    tampered["ciphertext"] = bytes(raw).hex()
    tamper_mac = not verify_mac(keys_p.a2b, tampered)
    tamper_dec = False
    try:
        decrypt_payload(keys_p.a2b, tampered)
    except Exception:
        tamper_dec = True

    # Replay
    window = ReplayWindow()
    replay_first = window.accept(1)
    replay_dup = not window.accept(1)

    # Partial compromise: mixer with leaked classical secret still changes if PQ secret differs
    leaked_x = ss_x
    k_ok = ct2_hybrid_mixer(ct1_context_bind(leaked_x, ctx), ss_k, ctx)
    other_k = ct2_hybrid_mixer(ct1_context_bind(leaked_x, ctx), random_bytes(32), ctx)
    pq_still_binds = k_ok != other_k

    leaked_k = ss_k
    k_ok2 = ct2_hybrid_mixer(ct1_context_bind(ss_x, ctx), leaked_k, ctx)
    other_x = ct2_hybrid_mixer(ct1_context_bind(random_bytes(32), ctx), leaked_k, ctx)
    x_still_binds = k_ok2 != other_x

    baseline_partial = derive_session_keys(ss_x=ss_x, ss_k=ss_k, context=ctx, session_id="s", construction=CONSTRUCTION_BASELINE)
    baseline_xleak = derive_session_keys(ss_x=ss_x, ss_k=random_bytes(32), context=ctx, session_id="s", construction=CONSTRUCTION_BASELINE)

    return {
        "handshake_agreement_proposed": keys_p.hybrid_secret == keys_p_b.hybrid_secret,
        "handshake_agreement_baseline": keys_b.hybrid_secret == keys_b_b.hybrid_secret,
        "avalanche_ct1": round(av_ct1, 4),
        "avalanche_ct2": round(av_ct2, 4),
        "avalanche_baseline_mix": round(av_base, 4),
        "key_sensitivity_proposed": round(key_sens(CONSTRUCTION_PROPOSED), 4),
        "key_sensitivity_baseline": round(key_sens(CONSTRUCTION_BASELINE), 4),
        "entropy_hybrid_proposed": round(shannon_entropy(keys_p.hybrid_secret), 4),
        "entropy_hybrid_baseline": round(shannon_entropy(keys_b.hybrid_secret), 4),
        "entropy_ciphertext_proposed": round(shannon_entropy(ct_p), 4),
        "entropy_ciphertext_baseline": round(shannon_entropy(ct_b), 4),
        "plaintext_ciphertext_correlation_proposed": round(correlation(pt, ct_p[: len(pt)]), 4),
        "plaintext_ciphertext_correlation_baseline": round(correlation(pt, ct_b[: len(pt)]), 4),
        "key_isolation_proposed": isol_p,
        "key_isolation_baseline": isol_b,
        "cross_purpose_decrypt_blocked_proposed": cross_purpose(keys_p.a2b, enc_p, CONSTRUCTION_PROPOSED),
        "cross_purpose_decrypt_blocked_baseline": cross_purpose(keys_b.a2b, enc_b, CONSTRUCTION_BASELINE),
        "session_isolation_proposed": sess_iso,
        "tamper_mac_rejected": tamper_mac,
        "tamper_aead_rejected": tamper_dec,
        "replay_accept_first": replay_first,
        "replay_reject_duplicate": replay_dup,
        "partial_compromise_pq_still_binds": pq_still_binds,
        "partial_compromise_x25519_still_binds": x_still_binds,
        "baseline_mix_changes_if_pq_changes": baseline_partial.hybrid_secret != baseline_xleak.hybrid_secret,
        "msg_roundtrip": decrypt_payload(keys_p_b.a2b, enc_p) == pt,
    }


def comparison_table(results: dict) -> list[dict]:
    return [
        {"property": "Handshake agreement", "baseline": results["handshake_agreement_baseline"], "proposed": results["handshake_agreement_proposed"]},
        {"property": "Avalanche (mix)", "baseline": results["avalanche_baseline_mix"], "proposed": results["avalanche_ct2"]},
        {"property": "Key sensitivity", "baseline": results["key_sensitivity_baseline"], "proposed": results["key_sensitivity_proposed"]},
        {"property": "Hybrid entropy (bits/byte)", "baseline": results["entropy_hybrid_baseline"], "proposed": results["entropy_hybrid_proposed"]},
        {"property": "Ciphertext entropy", "baseline": results["entropy_ciphertext_baseline"], "proposed": results["entropy_ciphertext_proposed"]},
        {"property": "P/C correlation", "baseline": results["plaintext_ciphertext_correlation_baseline"], "proposed": results["plaintext_ciphertext_correlation_proposed"]},
        {"property": "Key isolation (msg ≠ file ≠ mac)", "baseline": results["key_isolation_baseline"], "proposed": results["key_isolation_proposed"]},
        {"property": "Cross-purpose decrypt blocked", "baseline": results["cross_purpose_decrypt_blocked_baseline"], "proposed": results["cross_purpose_decrypt_blocked_proposed"]},
        {"property": "Session isolation", "baseline": True, "proposed": results["session_isolation_proposed"]},
        {"property": "Tamper detection", "baseline": True, "proposed": results["tamper_mac_rejected"] and results["tamper_aead_rejected"]},
        {"property": "Replay detection", "baseline": False, "proposed": results["replay_reject_duplicate"]},
        {"property": "Partial-compromise binding", "baseline": results["baseline_mix_changes_if_pq_changes"], "proposed": results["partial_compromise_pq_still_binds"] and results["partial_compromise_x25519_still_binds"]},
    ]


def main() -> None:
    import json
    from pathlib import Path

    from cns.config import ROOT

    results = evaluate()
    table = comparison_table(results)
    out = {"results": results, "table": table}
    path = ROOT / "eval_results.json"
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"Wrote {path}")
