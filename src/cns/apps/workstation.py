from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from cns.config import (
    CONSTRUCTION_BASELINE,
    CONSTRUCTION_PROPOSED,
    COORDINATOR_PORT,
    DATA_DIR,
    FTP_PORT,
    apply_hub,
    coordinator_url,
    ftp_client_host,
    hub_ip,
)
from cns.crypto import IdentityKeySet, ed25519_sign
from cns.crypto.pipeline import DirectionKeys, SessionKeys, decrypt_payload, encrypt_payload, verify_mac
from cns.crypto.replay import ReplayWindow
from cns.ftp_store import download_bytes, upload_bytes
from cns.identity import create_identity_vault, load_vault, vault_path
from cns.session import SessionOffer, accept_session, open_session

STATIC = Path(__file__).resolve().parent.parent / "web" / "static"


class AuthBody(BaseModel):
    username: str
    password: str


class SessionStart(BaseModel):
    peer_id: str
    construction: str = CONSTRUCTION_PROPOSED


class MsgBody(BaseModel):
    text: str


@dataclass
class LiveSession:
    meta: dict
    keys: SessionKeys
    send_seq: int = 0
    recv: ReplayWindow = field(default_factory=ReplayWindow)
    seen_payloads: dict[int, dict] = field(default_factory=dict)
    sent_plain: dict[int, str] = field(default_factory=dict)


class Workstation:
    def __init__(self, name: str, port: int) -> None:
        self.name = name
        self.port = port
        self.root = DATA_DIR / "workstations" / name
        self.root.mkdir(parents=True, exist_ok=True)
        self.keys: IdentityKeySet | None = None
        self.user_id: str | None = None
        self.username: str | None = None
        self.sessions: dict[str, LiveSession] = {}
        saved = self._lan_file()
        if saved.exists() and not os.environ.get("CNS_HUB"):
            apply_hub(json.loads(saved.read_text())["hub"])
        self.client = httpx.Client(base_url=coordinator_url(), timeout=30.0)

    def _lan_file(self) -> Path:
        return self.root / "lan.json"

    def _reconnect(self) -> None:
        self.client.close()
        self.client = httpx.Client(base_url=coordinator_url(), timeout=30.0)

    def set_hub(self, ip: str) -> dict:
        apply_hub(ip)
        self._lan_file().write_text(json.dumps({"hub": hub_ip()}))
        self._reconnect()
        return self.network_state()

    def network_state(self) -> dict:
        return {
            "hub": hub_ip(),
            "coordinator": coordinator_url(),
            "ftp_host": ftp_client_host(),
            "ftp_port": FTP_PORT,
            "coordinator_port": COORDINATOR_PORT,
        }

    def locked(self) -> bool:
        return self.keys is None

    def upload_prekeys(self) -> None:
        from cns.crypto import generate_x25519, serialize_x25519_sk
        from kyber_py.ml_kem import ML_KEM_768
        import uuid
        prekeys = []
        p = self.root / "prekeys.json"
        privs = json.loads(p.read_text()) if p.exists() else {}
        for _ in range(10):
            pid = str(uuid.uuid4())
            x_sk, x_pk = generate_x25519()
            ek, dk = ML_KEM_768.keygen()
            prekeys.append({"id": pid, "x25519_pk": x_pk.hex(), "mlkem_ek": ek.hex()})
            privs[pid] = {"x25519_sk": serialize_x25519_sk(x_sk).hex(), "mlkem_dk": dk.hex()}
        p.write_text(json.dumps(privs))
        self.client.post("/prekeys", json={"prekeys": prekeys})

    def register(self, username: str, password: str) -> dict:
        from cns.identity import vault_path
        if vault_path(self.root).exists():
            raise HTTPException(400, "A vault already exists on this PC. Please click Unlock instead.")
        keys = create_identity_vault(self.root, password)
        pub = keys.public_bundle()
        r = self.client.post("/register", json={"username": username, **pub})
        if r.status_code >= 400:
            raise HTTPException(r.status_code, r.text)
        return self.login(username, password)

    def login(self, username: str, password: str) -> dict:
        try:
            keys = load_vault(self.root, password)
        except Exception as exc:
            raise HTTPException(401, f"vault unlock failed: {exc}") from exc
        chal = self.client.post("/auth/challenge", json={"username": username})
        if chal.status_code >= 400:
            raise HTTPException(chal.status_code, chal.text)
        nonce = bytes.fromhex(chal.json()["nonce"])
        sig = ed25519_sign(keys.ed25519_sk, nonce)
        from cns.crypto import mldsa_sign
        mldsa_sig = mldsa_sign(keys.mldsa_sk, nonce)
        ver = self.client.post("/auth/verify", json={"username": username, "signature": sig.hex(), "mldsa_signature": mldsa_sig.hex()})
        if ver.status_code >= 400:
            raise HTTPException(ver.status_code, ver.text)
        data = ver.json()
        user = data["user"]
        self.keys = keys
        self.user_id = user["user_id"]
        self.username = username
        self.client.headers["Authorization"] = f"Bearer {data['token']}"
        (self.root / "profile.json").write_text(json.dumps({"user_id": self.user_id, "username": username}))
        self.upload_prekeys()
        return user

    def wipe(self) -> None:
        self.keys = None
        self.user_id = None
        self.username = None
        self.sessions.clear()
        import shutil
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True, exist_ok=True)

    def _need(self) -> IdentityKeySet:
        if not self.keys or not self.user_id:
            raise HTTPException(401, "unlock this workstation first")
        return self.keys

    def peers(self) -> list[dict]:
        self._need()
        users = self.client.get("/users").json()
        return [u for u in users if u["user_id"] != self.user_id]

    def start_session(self, peer_id: str, construction: str) -> dict:
        me = self._need()
        peer = self.client.get(f"/users/{peer_id}").json()
        prekey_r = self.client.get(f"/prekeys/{peer_id}")
        if prekey_r.status_code >= 400:
            raise HTTPException(404, "peer has no prekeys available")
        prekey = prekey_r.json()
        
        offer, keys, _eph = open_session(
            me,
            my_id=self.user_id or "",
            peer_id=peer_id,
            peer_x25519_pk=bytes.fromhex(prekey["x25519_pk"]),
            peer_mlkem_ek=bytes.fromhex(prekey["mlkem_ek"]),
            peer_prekey_id=prekey["id"],
            construction=construction,
        )
        transcript = (
            offer.session_id
            + offer.initiator_id
            + offer.responder_id
            + offer.construction
            + offer.eph_x25519_pk.hex()
            + offer.mlkem_ct.hex()
            + offer.prekey_id
        ).encode()
        sig = ed25519_sign(me.ed25519_sk, transcript)
        from cns.crypto import mldsa_sign
        mldsa_sig = mldsa_sign(me.mldsa_sk, transcript)
        r = self.client.post(
            "/sessions",
            json={
                "session_id": offer.session_id,
                "initiator_id": offer.initiator_id,
                "responder_id": offer.responder_id,
                "construction": offer.construction,
                "eph_x25519_pk": offer.eph_x25519_pk.hex(),
                "mlkem_ct": offer.mlkem_ct.hex(),
                "signature": sig.hex(),
                "mldsa_signature": mldsa_sig.hex(),
                "prekey_id": offer.prekey_id,
            },
        )
        if r.status_code >= 400:
            raise HTTPException(r.status_code, r.text)
        live = LiveSession(
            meta={
                "session_id": offer.session_id,
                "initiator_id": offer.initiator_id,
                "responder_id": offer.responder_id,
                "construction": construction,
                "peer_id": peer_id,
                "peer_name": peer["username"],
                "role": "initiator",
            },
            keys=keys,
        )
        self._load_session(live)
        self.sessions[offer.session_id] = live
        return live.meta

    def ingest_remote_sessions(self) -> list[dict]:
        me = self._need()
        remote = self.client.get("/sessions", params={"user_id": self.user_id}).json()
        for sess in remote:
            sid = sess["session_id"]
            if sid in self.sessions:
                self.sessions[sid].meta["status"] = sess["status"]
                continue
            if sess["responder_id"] == self.user_id and sess["status"] in ("pending", "active"):
                offer = SessionOffer(
                    session_id=sid,
                    initiator_id=sess["initiator_id"],
                    responder_id=sess["responder_id"],
                    construction=sess["construction"],
                    eph_x25519_pk=bytes.fromhex(sess["eph_x25519_pk"]),
                    mlkem_ct=bytes.fromhex(sess["mlkem_ct"]),
                    prekey_id=sess["prekey_id"],
                )
                initiator = self.client.get(f"/users/{sess['initiator_id']}").json()
                transcript = (
                    offer.session_id
                    + offer.initiator_id
                    + offer.responder_id
                    + offer.construction
                    + offer.eph_x25519_pk.hex()
                    + offer.mlkem_ct.hex()
                    + offer.prekey_id
                ).encode()
                from cns.crypto import ed25519_verify, mldsa_verify
                if not ed25519_verify(bytes.fromhex(initiator["ed25519_pk"]), transcript, bytes.fromhex(sess["signature"])):
                    continue
                if not mldsa_verify(bytes.fromhex(initiator["mldsa_pk"]), transcript, bytes.fromhex(sess["mldsa_signature"])):
                    continue
                
                p = self.root / "prekeys.json"
                privs = json.loads(p.read_text()) if p.exists() else {}
                my_prekey = privs.get(offer.prekey_id)
                if not my_prekey:
                    continue
                
                keys = accept_session(me, offer, bytes.fromhex(my_prekey["x25519_sk"]), bytes.fromhex(my_prekey["mlkem_dk"]))
                if sess["status"] == "pending":
                    self.client.post(f"/sessions/{sid}/accept")
                    sess["status"] = "active"
                live = LiveSession(
                    meta={
                        "session_id": sid,
                        "initiator_id": sess["initiator_id"],
                        "responder_id": sess["responder_id"],
                        "construction": sess["construction"],
                        "peer_id": sess["initiator_id"],
                        "peer_name": initiator["username"],
                        "role": "responder",
                    },
                    keys=keys,
                )
                self._load_session(live)
                self.sessions[sid] = live
        listed = []
        for sess in remote:
            sid = sess["session_id"]
            local = self.sessions.get(sid)
            listed.append(
                {
                    **sess,
                    "peer_name": local.meta.get("peer_name") if local else "peer",
                    "role": local.meta.get("role") if local else "remote",
                    "ready": sid in self.sessions and sess["status"] == "active",
                }
            )
        return listed

    def _dir_keys(self, live: LiveSession, sending: bool) -> DirectionKeys:
        i_am_initiator = live.meta["initiator_id"] == self.user_id
        if sending:
            return live.keys.a2b if i_am_initiator else live.keys.b2a
        return live.keys.b2a if i_am_initiator else live.keys.a2b

    def send_text(self, session_id: str, text: str) -> dict:
        live = self._live(session_id)
        peer = live.meta["responder_id"] if live.meta["initiator_id"] == self.user_id else live.meta["initiator_id"]
        live.send_seq += 1
        payload = encrypt_payload(
            keys=self._dir_keys(live, True),
            plaintext=text.encode(),
            session_id=session_id,
            seq=live.send_seq,
            sender_id=self.user_id or "",
            receiver_id=peer,
            kind="msg",
            construction=live.meta["construction"],
        )
        blob_id = str(uuid.uuid4())
        try:
            upload_bytes(blob_id, json.dumps(payload).encode("utf-8"))
        except Exception as exc:
            live.send_seq -= 1
            raise HTTPException(502, f"FTP upload failed: {exc}") from exc
        meta = {**payload, "ciphertext": "", "ftp_blob_id": blob_id}
        r = self.client.post(
            f"/sessions/{session_id}/messages",
            json={"payload": meta, "file_id": blob_id},
        )
        if r.status_code >= 400:
            live.send_seq -= 1
            raise HTTPException(r.status_code, r.text)
        live.sent_plain[live.send_seq] = text
        self._save_session(live)
        return {"ftp_blob_id": blob_id, "seq": live.send_seq}

    def send_file(self, session_id: str, filename: str, data: bytes) -> dict:
        live = self._live(session_id)
        peer = live.meta["responder_id"] if live.meta["initiator_id"] == self.user_id else live.meta["initiator_id"]
        live.send_seq += 1
        payload = encrypt_payload(
            keys=self._dir_keys(live, True),
            plaintext=data,
            session_id=session_id,
            seq=live.send_seq,
            sender_id=self.user_id or "",
            receiver_id=peer,
            kind="file",
            construction=live.meta["construction"],
        )
        file_id = str(uuid.uuid4())
        try:
            upload_bytes(file_id, bytes.fromhex(payload["ciphertext"]))
        except Exception as exc:
            live.send_seq -= 1
            raise HTTPException(502, f"FTP upload failed: {exc}") from exc
        payload_meta = {**payload, "ciphertext": "", "ftp_file_id": file_id, "ftp_blob_id": file_id, "filename": filename}
        r = self.client.post(
            f"/sessions/{session_id}/messages",
            json={"payload": payload_meta, "file_id": file_id, "filename": filename, "size": len(data)},
        )
        if r.status_code >= 400:
            live.send_seq -= 1
            raise HTTPException(r.status_code, r.text)
        self._save_session(live)
        return {"file_id": file_id, "seq": live.send_seq, "filename": filename}

    def inbox(self, session_id: str) -> list[dict]:
        live = self._live(session_id)
        rows = self.client.get(f"/sessions/{session_id}/messages").json()
        out = []
        for row in rows:
            payload = row["payload"]
            mine = payload["sender_id"] == self.user_id
            item = {
                "seq": payload["seq"],
                "kind": payload["kind"],
                "from_me": mine,
                "sender_id": payload["sender_id"],
                "status": "sent" if mine else "received",
                "filename": payload.get("filename"),
                "file_id": row.get("file_id") or payload.get("ftp_file_id") or payload.get("ftp_blob_id"),
            }
            if mine:
                item["text"] = live.sent_plain.get(int(payload["seq"]), payload.get("filename") or "sent")
                out.append(item)
                continue
            keys = self._dir_keys(live, False)
            fid = item["file_id"]
            try:
                if payload["kind"] == "file":
                    if fid:
                        payload = {**payload, "ciphertext": download_bytes(fid).hex()}
                else:
                    if fid:
                        payload = json.loads(download_bytes(fid).decode("utf-8"))
            except Exception as exc:
                item["status"] = "ftp_error"
                item["text"] = f"[FTP download failed: {exc}]"
                out.append(item)
                continue
            if not verify_mac(keys, payload):
                item["status"] = "rejected_mac"
                item["text"] = "[integrity failure]"
                out.append(item)
                continue
            seq = int(payload["seq"])
            proposed = live.meta["construction"] != CONSTRUCTION_BASELINE
            
            if proposed and seq not in live.seen_payloads:
                if not live.recv.accept(seq):
                    item["status"] = "replay"
                    item["text"] = "[replay/window rejected]"
                    out.append(item)
                    continue

            try:
                pt = decrypt_payload(keys, payload)
            except Exception:
                item["status"] = "rejected_decrypt"
                item["text"] = "[decrypt failed — context/key mismatch]"
                out.append(item)
                continue
            live.seen_payloads[seq] = payload
            if payload["kind"] == "file":
                item["text"] = payload.get("filename") or "encrypted file"
                dest = self.root / "downloads"
                dest.mkdir(exist_ok=True)
                name = payload.get("filename") or f"{seq}.bin"
                (dest / name).write_bytes(pt)
                item["saved_as"] = str(dest / name)
            else:
                item["text"] = pt.decode("utf-8", errors="replace")
            out.append(item)
        self._save_session(live)
        return out

    def _save_session(self, live: LiveSession) -> None:
        p = self.root / "sessions" / f"{live.meta['session_id']}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "send_seq": live.send_seq,
            "recv_highest": live.recv.highest,
            "recv_seen": list(live.recv.seen),
        }
        p.write_text(json.dumps(data))

    def _load_session(self, live: LiveSession) -> None:
        p = self.root / "sessions" / f"{live.meta['session_id']}.json"
        if p.exists():
            data = json.loads(p.read_text())
            live.send_seq = data.get("send_seq", 0)
            live.recv.highest = data.get("recv_highest", -1)
            live.recv.seen = set(data.get("recv_seen", []))

    def expire(self, session_id: str) -> None:
        self._need()
        r = self.client.post(f"/sessions/{session_id}/expire", json={"actor_id": self.user_id})
        if r.status_code >= 400:
            raise HTTPException(r.status_code, r.text)
        self.sessions.pop(session_id, None)

    def _live(self, session_id: str) -> LiveSession:
        self._need()
        live = self.sessions.get(session_id)
        if not live:
            self.ingest_remote_sessions()
            live = self.sessions.get(session_id)
        if not live:
            raise HTTPException(404, "session keys not on this workstation")
        return live


def create_app(name: str, port: int) -> FastAPI:
    ws = Workstation(name, port)
    app = FastAPI(title=f"CNS Workstation ({name})")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.post("/api/wipe")
    def api_wipe():
        ws.wipe()
        return {"ok": True}

    @app.get("/api/state")
    def state():
        profile = {}
        p = ws.root / "profile.json"
        if p.exists():
            profile = json.loads(p.read_text())
        return {
            "workstation": name,
            "port": port,
            "unlocked": not ws.locked(),
            "user_id": ws.user_id,
            "username": ws.username or profile.get("username"),
            "has_vault": vault_path(ws.root).exists(),
            "construction_default": CONSTRUCTION_PROPOSED,
            **ws.network_state(),
        }

    @app.post("/api/hub")
    async def api_hub(request: Request):
        data = await request.json()
        ip = (data.get("hub") or "").strip()
        if not ip:
            raise HTTPException(400, "hub IP required")
        return ws.set_hub(ip)

    @app.post("/api/register")
    async def api_register(request: Request):
        data = await request.json()
        return ws.register(data["username"], data["password"])

    @app.post("/api/login")
    async def api_login(request: Request):
        data = await request.json()
        return ws.login(data["username"], data["password"])

    @app.get("/api/peers")
    def api_peers():
        return ws.peers()

    @app.post("/api/sessions")
    async def api_start(request: Request):
        data = await request.json()
        return ws.start_session(data["peer_id"], data.get("construction", CONSTRUCTION_PROPOSED))

    @app.get("/api/sessions")
    def api_sessions():
        return ws.ingest_remote_sessions()

    @app.post("/api/sessions/{sid}/messages")
    async def api_send(sid: str, request: Request):
        data = await request.json()
        return ws.send_text(sid, data["text"])

    @app.get("/api/sessions/{sid}/messages")
    def api_inbox(sid: str):
        return ws.inbox(sid)

    @app.post("/api/sessions/{sid}/files")
    async def api_file(sid: str, file: UploadFile = File(...)):
        data = await file.read()
        return ws.send_file(sid, file.filename or "upload.bin", data)

    @app.post("/api/sessions/{sid}/expire")
    def api_expire(sid: str):
        ws.expire(sid)
        return {"ok": True}

    @app.post("/api/eval")
    def api_eval():
        from cns.eval.run import comparison_table, evaluate

        results = evaluate()
        return {"results": results, "table": comparison_table(results)}

    @app.get("/api/sessions/{sid}/download/{file_id}")
    def api_dl(sid: str, file_id: str):
        live = ws._live(sid)
        rows = ws.client.get(f"/sessions/{sid}/messages").json()
        for row in rows:
            if (row.get("file_id") or row["payload"].get("ftp_file_id")) == file_id:
                payload = dict(row["payload"])
                payload["ciphertext"] = download_bytes(file_id).hex()
                sending = payload["sender_id"] == ws.user_id
                keys = ws._dir_keys(live, sending)
                pt = decrypt_payload(keys, payload)
                name = payload.get("filename") or "file.bin"
                return Response(
                    content=pt,
                    media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'},
                )
        raise HTTPException(404, "file not found")

    return app
