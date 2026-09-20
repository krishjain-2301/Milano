from cns.config import CONSTRUCTION_BASELINE, CONSTRUCTION_PROPOSED
from cns.crypto import generate_identity, serialize_x25519_sk
from cns.crypto.pipeline import decrypt_payload, encrypt_payload
from cns.crypto.replay import ReplayWindow
from cns.eval.run import comparison_table, evaluate
from cns.identity import create_identity_vault, load_vault
from cns.session import accept_session, open_session


def _open(alice, bob, construction):
    return open_session(
        alice,
        my_id="A",
        peer_id="B",
        peer_x25519_pk=bob.x25519_pk,
        peer_mlkem_ek=bob.mlkem_ek,
        peer_prekey_id="test_id",
        construction=construction,
    )


def test_proposed_roundtrip(tmp_path):
    alice, bob = generate_identity(), generate_identity()
    offer, keys_a, _ = _open(alice, bob, CONSTRUCTION_PROPOSED)
    keys_b = accept_session(bob, offer, serialize_x25519_sk(bob.x25519_sk), bob.mlkem_dk)
    payload = encrypt_payload(
        keys=keys_a.a2b,
        plaintext=b"Hello Bob",
        session_id=offer.session_id,
        seq=1,
        sender_id="A",
        receiver_id="B",
        kind="msg",
        construction=CONSTRUCTION_PROPOSED,
    )
    assert decrypt_payload(keys_b.a2b, payload) == b"Hello Bob"


def test_key_isolation_proposed():
    alice, bob = generate_identity(), generate_identity()
    _, keys, _ = _open(alice, bob, CONSTRUCTION_PROPOSED)
    assert keys.a2b.msg != keys.a2b.file
    assert keys.a2b.msg != keys.a2b.mac
    assert keys.a2b.msg != keys.b2a.msg


def test_baseline_shares_keys():
    alice, bob = generate_identity(), generate_identity()
    _, keys, _ = _open(alice, bob, CONSTRUCTION_BASELINE)
    assert keys.a2b.msg == keys.a2b.file == keys.a2b.mac


def test_replay_window():
    w = ReplayWindow(size=8)
    assert w.accept(0)
    assert not w.accept(0)
    assert w.accept(1)


def test_vault(tmp_path):
    keys = create_identity_vault(tmp_path, "pw")
    loaded = load_vault(tmp_path, "pw")
    assert loaded.ed25519_pk == keys.ed25519_pk
    assert loaded.mlkem_ek == keys.mlkem_ek


def test_evaluate_core_properties():
    r = evaluate()
    assert r["handshake_agreement_proposed"] is True
    assert r["msg_roundtrip"] is True
    assert r["key_isolation_proposed"] is True
    assert r["key_isolation_baseline"] is False
    assert r["tamper_mac_rejected"] is True
    assert r["replay_reject_duplicate"] is True
    assert r["partial_compromise_proposed"] is True
    table = comparison_table(r)
    overall = next(row for row in table if row["property"] == "Overall security score")
    assert float(overall["proposed"]) > float(overall["baseline"])
    for row in table:
        if row["property"] == "Handshake agreement":
            continue
        b, p = row["baseline"], row["proposed"]
        if isinstance(b, bool) and isinstance(p, bool):
            if p is False:
                assert b is False
        elif isinstance(b, (int, float)) and isinstance(p, (int, float)):
            assert float(p) >= float(b)
