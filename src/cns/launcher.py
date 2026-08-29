from __future__ import annotations

import argparse
import os
import threading
import time

import uvicorn

from cns.config import (
    ALICE_PORT,
    BOB_PORT,
    COORDINATOR_PORT,
    DATA_DIR,
    FTP_PASV_END,
    FTP_PASV_START,
    FTP_PORT,
    apply_hub,
    bind_host,
    coordinator_url,
    detect_lan_ip,
    ftp_client_host,
)
from cns.ftp_store import start_ftp_server


def serve(app, host: str, port: int) -> None:
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    uvicorn.Server(config).run()


def _print_lan_help(role: str, workstation_port: int | None = None) -> None:
    lan = detect_lan_ip()
    print()
    if role == "host":
        print("This PC is the hub (coordinator + FTP + this workstation).")
        print(f"  LAN IP         {lan}")
        print(f"  Coordinator    http://{lan}:{COORDINATOR_PORT}/health")
        print(f"  FTP            {lan}:{FTP_PORT}  (encrypted messages and files)")
        print(f"  Passive FTP    {FTP_PASV_START}-{FTP_PASV_END}")
        if workstation_port:
            print(f"  This UI        http://127.0.0.1:{workstation_port}")
        print()
        print("On the other PC, copy this project, then run:")
        print(f"  python -m cns peer --hub {lan}")
        print("Allow Windows Firewall for TCP 8000, 2121, and 50100-50120 on Private networks.")
    else:
        print("This PC is a peer workstation.")
        print(f"  Coordinator    {coordinator_url()}")
        print(f"  FTP            {ftp_client_host()}:{FTP_PORT}")
        if workstation_port:
            print(f"  This UI        http://127.0.0.1:{workstation_port}")
        print("Enter the hub LAN IP in the UI if you did not pass --hub.")
    print()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="CNS hybrid messaging launcher")
    parser.add_argument(
        "role",
        nargs="?",
        default="all",
        choices=["all", "coordinator", "ftp", "alice", "bob", "host", "peer", "eval"],
    )
    parser.add_argument("--name", help="workstation name (alice/bob or any label)")
    parser.add_argument("--hub", help="LAN IP of the PC running coordinator + FTP")
    parser.add_argument("--port", type=int, help="workstation HTTP port")
    args = parser.parse_args(argv)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.hub:
        apply_hub(args.hub)

    if args.role == "eval":
        from cns.eval.run import main as eval_main

        eval_main()
        return

    if args.role == "ftp":
        os.environ.setdefault("CNS_BIND", "0.0.0.0")
        start_ftp_server()
        print(f"FTP listening on {bind_host()}:{FTP_PORT}  (clients use {ftp_client_host()}:{FTP_PORT})")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return

    if args.role == "coordinator":
        os.environ.setdefault("CNS_BIND", "0.0.0.0")
        from cns.apps.coordinator import app

        serve(app, bind_host() if bind_host() != "127.0.0.1" else "0.0.0.0", COORDINATOR_PORT)
        return

    if args.role == "host":
        os.environ["CNS_BIND"] = "0.0.0.0"
        os.environ["CNS_HOST_IP"] = detect_lan_ip()
        # This PC talks to its own services on localhost; the other PC uses the LAN IP.
        os.environ["CNS_HUB"] = "127.0.0.1"
        os.environ["CNS_FTP_HOST"] = "127.0.0.1"
        os.environ["CNS_COORDINATOR_URL"] = f"http://127.0.0.1:{COORDINATOR_PORT}"
        start_ftp_server()
        from cns.apps.coordinator import app as coordinator_app
        from cns.apps.workstation import create_app

        name = args.name or "alice"
        port = args.port or ALICE_PORT
        ws = create_app(name, port)
        threads = [
            threading.Thread(target=serve, args=(coordinator_app, "0.0.0.0", COORDINATOR_PORT), daemon=True),
            threading.Thread(target=serve, args=(ws, "0.0.0.0", port), daemon=True),
        ]
        for t in threads:
            t.start()
        _print_lan_help("host", port)
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopping.")
        return

    if args.role == "peer":
        os.environ.setdefault("CNS_BIND", "0.0.0.0")
        from cns.apps.workstation import create_app

        name = args.name or "bob"
        port = args.port or BOB_PORT
        if args.hub:
            apply_hub(args.hub)
        _print_lan_help("peer", port)
        serve(create_app(name, port), "0.0.0.0", port)
        return

    if args.role in ("alice", "bob"):
        from cns.apps.workstation import create_app

        name = args.role
        port = args.port or (ALICE_PORT if name == "alice" else BOB_PORT)
        serve(create_app(name, port), bind_host(), port)
        return

    # Single-PC demo
    start_ftp_server()
    from cns.apps.coordinator import app as coordinator_app
    from cns.apps.workstation import create_app

    alice = create_app("alice", ALICE_PORT)
    bob = create_app("bob", BOB_PORT)
    listen = bind_host()
    threads = [
        threading.Thread(target=serve, args=(coordinator_app, listen, COORDINATOR_PORT), daemon=True),
        threading.Thread(target=serve, args=(alice, listen, ALICE_PORT), daemon=True),
        threading.Thread(target=serve, args=(bob, listen, BOB_PORT), daemon=True),
    ]
    for t in threads:
        t.start()
    print()
    print("CNS hybrid messaging is running on this PC:")
    print(f"  Coordinator  {coordinator_url()}/health")
    print(f"  FTP          {ftp_client_host()}:{FTP_PORT}")
    print(f"  Alice        http://127.0.0.1:{ALICE_PORT}")
    print(f"  Bob          http://127.0.0.1:{BOB_PORT}")
    print("Two-PC mode: python -m cns host   on the sender,   python -m cns peer --hub <LAN-IP>  on the receiver.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping.")


if __name__ == "__main__":
    main()
