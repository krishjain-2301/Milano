from __future__ import annotations

import os
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("CNS_DATA_DIR", ROOT / "data"))

COORDINATOR_PORT = int(os.environ.get("CNS_COORDINATOR_PORT", "8000"))
FTP_PORT = int(os.environ.get("CNS_FTP_PORT", "2121"))
FTP_USER = os.environ.get("CNS_FTP_USER", "cnsftp")
FTP_PASSWORD = os.environ.get("CNS_FTP_PASSWORD", "cns-local-ftp")
FTP_PASV_START = 50100
FTP_PASV_END = 50120
ALICE_PORT = int(os.environ.get("CNS_ALICE_PORT", "8101"))
BOB_PORT = int(os.environ.get("CNS_BOB_PORT", "8102"))

PROTOCOL_VERSION = "cns-hybrid-1"
CONSTRUCTION_PROPOSED = "proposed"
CONSTRUCTION_BASELINE = "baseline"

AES_PROFILE = "aes-256-gcm"
CHACHA_PROFILE = "chacha20-poly1305"


def detect_lan_ip() -> str:
    env = os.environ.get("CNS_HOST_IP")
    if env:
        return env
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("10.255.255.255", 1))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                return ip
    except OSError:
        pass
    return "127.0.0.1"


def hub_ip() -> str:
    return os.environ.get("CNS_HUB") or os.environ.get("CNS_FTP_HOST") or "127.0.0.1"


def bind_host() -> str:
    return os.environ.get("CNS_BIND", "127.0.0.1")


def coordinator_url() -> str:
    if os.environ.get("CNS_COORDINATOR_URL"):
        return os.environ["CNS_COORDINATOR_URL"].rstrip("/")
    return f"http://{hub_ip()}:{COORDINATOR_PORT}"


def ftp_client_host() -> str:
    return os.environ.get("CNS_FTP_HOST") or hub_ip()


def apply_hub(ip: str) -> None:
    ip = ip.strip()
    os.environ["CNS_HUB"] = ip
    os.environ["CNS_FTP_HOST"] = ip
    os.environ["CNS_COORDINATOR_URL"] = f"http://{ip}:{COORDINATOR_PORT}"
