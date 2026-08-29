from __future__ import annotations

import json
import os
import uuid

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from cns.config import DATA_DIR, FTP_PORT, detect_lan_ip, ftp_client_host
from cns.crypto import ed25519_verify
from cns.db import CoordinatorDB

db = CoordinatorDB(DATA_DIR / "coordinator" / "cns.sqlite")
app = FastAPI(title="CNS Coordinator", version="1.0.0")


class RegisterBody(BaseModel):
    username: str
    ed25519_pk: str
    x25519_pk: str
    mlkem_ek: str
    mldsa_pk: str


class ChallengeBody(BaseModel):
    username: str


class VerifyBody(BaseModel):
    username: str
    signature: str


class SessionBody(BaseModel):
    initiator_id: str
    responder_id: str
    construction: str
    eph_x25519_pk: str
    mlkem_ct: str
    session_id: str
    signature: str


class MessageBody(BaseModel):
    payload: dict
    file_id: str | None = None
    filename: str | None = None
    size: int | None = None


class ExpireBody(BaseModel):
    actor_id: str = Field(...)


@app.get("/health")
def health():
    return {
        "ok": True,
        "lan_ip": detect_lan_ip(),
        "ftp": f"{ftp_client_host()}:{FTP_PORT}",
        "database": str(DATA_DIR / "coordinator" / "cns.sqlite"),
    }


@app.post("/register")
async def register(request: Request):
    payload = RegisterBody.model_validate(await request.json())
    if db.get_user_by_name(payload.username):
        raise HTTPException(409, "username taken")
    user_id = str(uuid.uuid4())
    db.register_user(
        {
            "user_id": user_id,
            "username": payload.username,
            "ed25519_pk": payload.ed25519_pk,
            "x25519_pk": payload.x25519_pk,
            "mlkem_ek": payload.mlkem_ek,
            "mldsa_pk": payload.mldsa_pk,
        }
    )
    return {"user_id": user_id, "username": payload.username}


@app.post("/auth/challenge")
async def challenge(request: Request):
    payload = ChallengeBody.model_validate(await request.json())
    user = db.get_user_by_name(payload.username)
    if not user:
        raise HTTPException(404, "unknown user")
    nonce = os.urandom(32).hex()
    db.put_challenge(user["user_id"], nonce)
    return {"user_id": user["user_id"], "nonce": nonce}


@app.post("/auth/verify")
async def verify(request: Request):
    payload = VerifyBody.model_validate(await request.json())
    user = db.get_user_by_name(payload.username)
    if not user:
        raise HTTPException(404, "unknown user")
    nonce = db.pop_challenge(user["user_id"])
    if not nonce:
        raise HTTPException(400, "no challenge")
    ok = ed25519_verify(bytes.fromhex(user["ed25519_pk"]), bytes.fromhex(nonce), bytes.fromhex(payload.signature))
    if not ok:
        raise HTTPException(401, "bad signature")
    token = os.urandom(16).hex()
    return {"ok": True, "user": user, "token": token}


@app.get("/users")
def users():
    return db.list_users()


@app.get("/users/{user_id}")
def user(user_id: str):
    u = db.get_user(user_id)
    if not u:
        raise HTTPException(404, "not found")
    return u


@app.post("/sessions")
async def create_session(request: Request):
    payload = SessionBody.model_validate(await request.json())
    initiator = db.get_user(payload.initiator_id)
    if not initiator:
        raise HTTPException(404, "initiator missing")
    transcript = (
        payload.session_id
        + payload.initiator_id
        + payload.responder_id
        + payload.construction
        + payload.eph_x25519_pk
        + payload.mlkem_ct
    ).encode()
    if not ed25519_verify(bytes.fromhex(initiator["ed25519_pk"]), transcript, bytes.fromhex(payload.signature)):
        raise HTTPException(401, "invalid session signature")
    db.create_session(
        {
            "session_id": payload.session_id,
            "initiator_id": payload.initiator_id,
            "responder_id": payload.responder_id,
            "construction": payload.construction,
            "eph_x25519_pk": payload.eph_x25519_pk,
            "mlkem_ct": payload.mlkem_ct,
            "status": "pending",
        }
    )
    return {"ok": True, "session_id": payload.session_id}


@app.post("/sessions/{session_id}/accept")
def accept(session_id: str):
    sess = db.get_session(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    db.set_status(session_id, "active")
    return {"ok": True}


@app.post("/sessions/{session_id}/expire")
async def expire(session_id: str, request: Request):
    payload = ExpireBody.model_validate(await request.json())
    sess = db.get_session(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    if payload.actor_id not in (sess["initiator_id"], sess["responder_id"]):
        raise HTTPException(403, "not a participant")
    db.set_status(session_id, "expired")
    return {"ok": True}


@app.get("/sessions")
def list_sessions(user_id: str):
    return db.sessions_for(user_id)


@app.get("/sessions/{session_id}")
def get_session(session_id: str):
    sess = db.get_session(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    return sess


@app.post("/sessions/{session_id}/messages")
async def post_message(session_id: str, request: Request):
    envelope = MessageBody.model_validate(await request.json())
    sess = db.get_session(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    if sess["status"] != "active":
        raise HTTPException(409, "session not active")
    payload = envelope.payload
    file_id = envelope.file_id
    if payload.get("kind") == "file":
        if not file_id:
            file_id = str(uuid.uuid4())
        db.add_file(
            {
                "file_id": file_id,
                "session_id": session_id,
                "filename": envelope.filename or "file.bin",
                "size": envelope.size or 0,
                "sender_id": payload["sender_id"],
            }
        )
    db.add_message(
        {
            "session_id": session_id,
            "seq": int(payload["seq"]),
            "sender_id": payload["sender_id"],
            "receiver_id": payload["receiver_id"],
            "kind": payload["kind"],
            "payload_json": json.dumps(payload),
            "file_id": file_id,
        }
    )
    return {"ok": True, "file_id": file_id}


@app.get("/sessions/{session_id}/messages")
def get_messages(session_id: str):
    return db.messages(session_id)
