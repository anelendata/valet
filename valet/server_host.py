"""Configured host daemon.

``valet serve`` always starts the local Unix-domain socket. When
``[host].lan = true`` it also starts the Level 1 WebSocket RPC listener using
the same broker instance.
"""
from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .broker import Broker
from .config import BrokerConfig, load_config
from .server_uds import close_server as close_uds_server
from .server_uds import make_server as make_uds_server
from .server_ws import make_server as make_ws_server


@dataclass
class _ConfigWatchState:
    stamp: tuple[int, int] | None


def serve(
    cfg: BrokerConfig,
    *,
    config_path: Path | None = None,
    reload_interval: float = 1.0,
) -> None:
    broker = Broker(cfg, audit_to_console=cfg.audit.console)
    ws_server = make_ws_server(cfg, broker=broker) if cfg.host.lan else None
    try:
        uds_server = make_uds_server(cfg, broker=broker)
    except Exception:
        if ws_server is not None:
            ws_server.server_close()
        raise

    ws_thread: threading.Thread | None = None
    stop_reload = threading.Event()
    reload_thread = _start_config_reloader(
        config_path,
        broker,
        ws_server,
        stop_reload,
        interval=reload_interval,
    )
    sock_path = uds_server.socket_path  # type: ignore[attr-defined]
    print(f"valet: listening on {sock_path} (0600).")
    if ws_server is not None:
        host, port = ws_server.server_address[:2]
        print(f"valet: listening on ws://{host}:{port}/rpc (trusted LAN only).")

        ws_thread = threading.Thread(target=ws_server.serve_forever, daemon=True)
        ws_thread.start()
    print("valet: Ctrl-C to stop.")

    try:
        uds_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_reload.set()
        if ws_server is not None:
            ws_server.shutdown()
            ws_server.server_close()
        close_uds_server(uds_server)
        if reload_thread is not None:
            reload_thread.join(timeout=2)
        if ws_thread is not None:
            ws_thread.join(timeout=2)


def _start_config_reloader(
    config_path: Path | None,
    broker: Broker,
    ws_server,
    stop_event: threading.Event,
    *,
    interval: float,
) -> threading.Thread | None:
    if config_path is None:
        return None
    path = Path(config_path)
    state = _ConfigWatchState(_config_stamp(path))

    def apply(new_cfg: BrokerConfig) -> None:
        _apply_reloaded_config(broker, ws_server, new_cfg)

    thread = threading.Thread(
        target=_watch_config,
        args=(path, state, apply, stop_event, interval),
        daemon=True,
    )
    thread.start()
    return thread


def _watch_config(
    path: Path,
    state: _ConfigWatchState,
    apply: Callable[[BrokerConfig], None],
    stop_event: threading.Event,
    interval: float,
) -> None:
    while not stop_event.wait(interval):
        stamp = _config_stamp(path)
        if stamp is None or stamp == state.stamp:
            continue
        try:
            cfg = load_config(path)
        except Exception as exc:
            print(f"valet: config reload failed: {exc}", file=sys.stderr)
            continue
        state.stamp = stamp
        apply(cfg)
        print(f"valet: reloaded config from {path}")


def _config_stamp(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size)


def _apply_reloaded_config(broker: Broker, ws_server, new_cfg: BrokerConfig) -> None:
    old_cfg = broker.cfg
    broker.reload(new_cfg)
    if ws_server is not None:
        ws_server.cfg = new_cfg  # type: ignore[attr-defined]
    _warn_if_listener_restart_needed(old_cfg, new_cfg)


def _warn_if_listener_restart_needed(old_cfg: BrokerConfig, new_cfg: BrokerConfig) -> None:
    if old_cfg.socket_path != new_cfg.socket_path:
        print(
            "valet: broker.socket_path changed; restart `valet serve` to rebind",
            file=sys.stderr,
        )
    if old_cfg.host.listen != new_cfg.host.listen:
        print(
            "valet: host.listen changed; restart `valet serve` to rebind LAN listener",
            file=sys.stderr,
        )
    if old_cfg.host.lan != new_cfg.host.lan:
        print(
            "valet: host.lan changed; restart `valet serve` to start or stop LAN listener",
            file=sys.stderr,
        )
