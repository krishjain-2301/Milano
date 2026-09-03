from __future__ import annotations

import uuid
from dataclasses import dataclass

from cns.config import CONSTRUCTION_PROPOSED
from cns.crypto import IdentityKeySet, generate_x25519, mlkem_decaps, mlkem_encaps, x25519_shared
from cns.crypto.pipeline import SessionKeys, derive_session_keys, session_context


@dataclass
class SessionOffer:
    session_id: str
    initiator_id: str
    responder_id: str
    construction: str
    eph_x25519_pk: bytes
    mlkem_ct: bytes
    prekey_id: str



def open_session(
    me: IdentityKeySet,
    *,
    my_id: str,
    peer_id: str,
    peer_x25519_pk: bytes,
    peer_mlkem_ek: bytes,
    peer_prekey_id: str,
    construction: str = CONSTRUCTION_PROPOSED,
) -> tuple[SessionOffer, SessionKeys, bytes]:
    eph_sk, eph_pk = generate_x25519()
    ss_x = x25519_shared(eph_sk, peer_x25519_pk)
    ss_k, mlkem_ct = mlkem_encaps(peer_mlkem_ek)
    session_id = str(uuid.uuid4())
    ctx = session_context(
        session_id=session_id,
        initiator_id=my_id,
        responder_id=peer_id,
        eph_x25519_pk=eph_pk,
        mlkem_ct=mlkem_ct,
        construction=construction,
    )
    keys = derive_session_keys(
        ss_x=ss_x,
        ss_k=ss_k,
        context=ctx,
        session_id=session_id,
        construction=construction,
    )
    offer = SessionOffer(
        session_id=session_id,
        initiator_id=my_id,
        responder_id=peer_id,
        construction=construction,
        eph_x25519_pk=eph_pk,
        mlkem_ct=mlkem_ct,
        prekey_id=peer_prekey_id,
    )
    return offer, keys, serialize_eph(eph_sk)


def accept_session(
    me: IdentityKeySet,
    offer: SessionOffer,
    responder_x25519_sk: bytes,
    responder_mlkem_dk: bytes,
) -> SessionKeys:
    from cryptography.hazmat.primitives.asymmetric import x25519
    sk = x25519.X25519PrivateKey.from_private_bytes(responder_x25519_sk)
    ss_x = x25519_shared(sk, offer.eph_x25519_pk)
    ss_k = mlkem_decaps(responder_mlkem_dk, offer.mlkem_ct)
    ctx = session_context(
        session_id=offer.session_id,
        initiator_id=offer.initiator_id,
        responder_id=offer.responder_id,
        eph_x25519_pk=offer.eph_x25519_pk,
        mlkem_ct=offer.mlkem_ct,
        construction=offer.construction,
    )
    return derive_session_keys(
        ss_x=ss_x,
        ss_k=ss_k,
        context=ctx,
        session_id=offer.session_id,
        construction=offer.construction,
    )


def serialize_eph(sk) -> bytes:
    from cns.crypto import serialize_x25519_sk

    return serialize_x25519_sk(sk)
