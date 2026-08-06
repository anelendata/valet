"""Configured host daemon.

``valet serve`` always starts the local Unix-domain socket. When
``[host].lan = true`` it also starts the Level 1 WebSocket RPC listener using
the same broker instance.
"""
from __future__ import annotations

import threading

from .broker import Broker
from .config import BrokerConfig
from .server_uds import close_server as close_uds_server
from .server_uds import make_server as make_uds_server
from .server_ws import make_server as make_ws_server


def serve(cfg: BrokerConfig) -> None:
    broker = Broker(cfg, audit_to_console=cfg.audit.console)
    ws_server = make_ws_server(cfg, broker=broker) if cfg.host.lan else None
    try:
        uds_server = make_uds_server(cfg, broker=broker)
    except Exception:
        if ws_server is not None:
            ws_server.server_close()
        raise

    ws_thread: threading.Thread | None = None
    sock_path = uds_server.socket_path  # type: ignore[attr-defined]
    print(f"valet: listening on {sock_path} (0600).")
    if ws_server is not None:
        host, port = ws_server.server_address[:2]
        print(
            f"valet: listening on ws://{host}:{port}/rpc "
            "(trusted LAN only)."
        )

        ws_thread = threading.Thread(target=ws_server.serve_forever, daemon=True)
        ws_thread.start()
    print("valet: Ctrl-C to stop.")

    try:
        uds_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if ws_server is not None:
            ws_server.shutdown()
            ws_server.server_close()
