from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  ed25519_pk TEXT NOT NULL,
  x25519_pk TEXT NOT NULL,
  mlkem_ek TEXT NOT NULL,
  mldsa_pk TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS challenges (
  user_id TEXT PRIMARY KEY,
  nonce TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  initiator_id TEXT NOT NULL,
  responder_id TEXT NOT NULL,
  construction TEXT NOT NULL,
  eph_x25519_pk TEXT NOT NULL,
  mlkem_ct TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  sender_id TEXT NOT NULL,
  receiver_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  file_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS files (
  file_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  sender_id TEXT NOT NULL
);
"""


class CoordinatorDB:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.executescript(_SCHEMA)

    def register_user(self, user: dict) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO users (user_id, username, ed25519_pk, x25519_pk, mlkem_ek, mldsa_pk)
                   VALUES (:user_id, :username, :ed25519_pk, :x25519_pk, :mlkem_ek, :mldsa_pk)""",
                user,
            )

    def get_user_by_name(self, username: str) -> dict | None:
        cur = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_user(self, user_id: str) -> dict | None:
        cur = self.conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT user_id, username, ed25519_pk, x25519_pk, mlkem_ek, mldsa_pk FROM users")]

    def put_challenge(self, user_id: str, nonce: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO challenges (user_id, nonce) VALUES (?, ?)",
                (user_id, nonce),
            )

    def pop_challenge(self, user_id: str) -> str | None:
        with self._lock:
            cur = self.conn.execute("SELECT nonce FROM challenges WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
            if not row:
                return None
            with self.conn:
                self.conn.execute("DELETE FROM challenges WHERE user_id = ?", (user_id,))
            return row["nonce"]

    def create_session(self, sess: dict) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO sessions (session_id, initiator_id, responder_id, construction, eph_x25519_pk, mlkem_ct, status)
                   VALUES (:session_id, :initiator_id, :responder_id, :construction, :eph_x25519_pk, :mlkem_ct, :status)""",
                sess,
            )

    def get_session(self, session_id: str) -> dict | None:
        cur = self.conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def set_status(self, session_id: str, status: str) -> None:
        with self._lock, self.conn:
            self.conn.execute("UPDATE sessions SET status = ? WHERE session_id = ?", (status, session_id))

    def sessions_for(self, user_id: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM sessions WHERE initiator_id = ? OR responder_id = ? ORDER BY created_at DESC",
            (user_id, user_id),
        )
        return [dict(r) for r in cur.fetchall()]

    def add_message(self, msg: dict) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO messages (session_id, seq, sender_id, receiver_id, kind, payload_json, file_id)
                   VALUES (:session_id, :seq, :sender_id, :receiver_id, :kind, :payload_json, :file_id)""",
                msg,
            )

    def messages(self, session_id: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM messages WHERE session_id = ? ORDER BY seq ASC, id ASC",
            (session_id,),
        )
        rows = []
        for r in cur.fetchall():
            item = dict(r)
            item["payload"] = json.loads(item["payload_json"])
            rows.append(item)
        return rows

    def add_file(self, rec: dict) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO files (file_id, session_id, filename, size, sender_id)
                   VALUES (:file_id, :session_id, :filename, :size, :sender_id)""",
                rec,
            )
