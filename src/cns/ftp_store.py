from __future__ import annotations

import threading
from io import BytesIO
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from cns.config import (
    DATA_DIR,
    FTP_PASV_END,
    FTP_PASV_START,
    FTP_PASSWORD,
    FTP_PORT,
    FTP_USER,
    bind_host,
    detect_lan_ip,
    ftp_client_host,
)


def ftp_root() -> Path:
    path = DATA_DIR / "ftp"
    path.mkdir(parents=True, exist_ok=True)
    return path


def blob_name(blob_id: str) -> str:
    return f"{blob_id}.bin"


def start_ftp_server() -> FTPServer:
    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USER, FTP_PASSWORD, str(ftp_root()), perm="elradfmwMT")
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "CNS encrypted blob FTP"
    lan = detect_lan_ip()
    if bind_host() == "0.0.0.0" and lan != "127.0.0.1":
        handler.masquerade_address = lan
    handler.passive_ports = range(FTP_PASV_START, FTP_PASV_END + 1)
    server = FTPServer((bind_host(), FTP_PORT), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _ftp() :
    from ftplib import FTP

    client = FTP()
    client.connect(ftp_client_host(), FTP_PORT, timeout=15)
    client.login(FTP_USER, FTP_PASSWORD)
    client.set_pasv(True)
    return client


def upload_bytes(blob_id: str, data: bytes) -> None:
    bio = BytesIO(data)
    ftp = _ftp()
    try:
        ftp.storbinary(f"STOR {blob_name(blob_id)}", bio)
    finally:
        ftp.quit()


def download_bytes(blob_id: str) -> bytes:
    bio = BytesIO()
    ftp = _ftp()
    try:
        ftp.retrbinary(f"RETR {blob_name(blob_id)}", bio.write)
    finally:
        ftp.quit()
    return bio.getvalue()
