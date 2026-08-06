"""Client-side RPC abstraction shared by CLI and REPL."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import uuid
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

from .client_config import ClientConfig, ClientHost, load_client_config
from .config import BrokerConfig
from .server_uds import Connection
from .wsproto import WebSocketError, accept_key, client_key, read_http_headers, read_text, write_close, write_text

PROTOCOL = "valet-rpc/1"


class RpcError(ConnectionError):
    pass


StreamCallback = Callable[[dict], None]


@dataclass(frozen=True)
class Target:
    kind: str
    name: str = "local"
    host: Optional[ClientHost] = None

    @property
    def is_remote(self) -> bool:
        return self.kind == "websocket"


def resolve_target(
    *,
    host_name: Optional[str] = None,
    force_local: bool = False,
    client_config_path: Optional[str] = None,
) -> tuple[Target, ClientConfig]:
    client_cfg = load_client_config(client_config_path)
    if force_local:
        return Target(kind="uds", name="local"), client_cfg
    selected = host_name or client_cfg.default_host
    if selected:
        host = client_cfg.hosts.get(selected)
        if host is None:
            raise RpcError(f"unknown host {selected!r} in {client_cfg.path}")
        return Target(kind="websocket", name=selected, host=host), client_cfg
    return Target(kind="uds", name="local"), client_cfg


class ValetClient:
    def __init__(self, target: Target, cfg: Optional[BrokerConfig] = None):
        self.target = target
        self.cfg = cfg
        if target.kind == "uds":
            if cfg is None:
                raise RpcError("local target requires broker config")
            self._transport = _UdsRpcTransport(cfg.socket_path)
        elif target.kind == "websocket" and target.host is not None:
            self._transport = _WebSocketRpcTransport(target.host)
        else:
            raise RpcError("invalid target")

    def request(self, req: dict) -> dict:
        return self._transport.request(req)

    def request_stream(self, req: dict, on_event: StreamCallback) -> dict:
        return self._transport.request_stream(req, on_event)

    def close(self) -> None:
        self._transport.close()


class _UdsRpcTransport:
    def __init__(self, socket_path: str):
        self.conn = Connection(socket_path)

    def request(self, req: dict) -> dict:
        return self.conn.request(req)

    def request_stream(self, req: dict, on_event: StreamCallback) -> dict:
        return self.conn.request_stream(req, on_event)

    def close(self) -> None:
        self.conn.close()


class _WebSocketRpcTransport:
    def __init__(self, host: ClientHost):
        if not host.client_id or not host.key:
            raise RpcError(f"host {host.name!r} is missing client_id/key")
        self.host = host
        self.sock = _connect_websocket(host.url)
        self._authenticate()

    def request(self, req: dict) -> dict:
        request_id = _request_id()
        write_text(self.sock, json.dumps(_request_envelope(request_id, self.host.client_id, req)),
                   mask=True)
        while True:
            message = self._read_message()
            if message.get("request_id") != request_id:
                continue
            msg_type = message.get("type")
            if msg_type == "response":
                return dict(message.get("result") or {})
            if msg_type == "event" and message.get("event") == "completed":
                return dict(message.get("data") or {})
            if msg_type in ("error", "event") and message.get("event") == "failed":
                return _safe_error_response(message)

    def request_stream(self, req: dict, on_event: StreamCallback) -> dict:
        req = dict(req)
        req["stream"] = True
        request_id = _request_id()
        write_text(self.sock, json.dumps(_request_envelope(request_id, self.host.client_id, req)),
                   mask=True)
        cancelled = False
        while True:
            try:
                message = self._read_message()
            except KeyboardInterrupt:
                if cancelled:
                    raise
                self._send_cancel(request_id)
                cancelled = True
                continue
            if message.get("request_id") != request_id:
                continue
            if message.get("type") == "event":
                event = message.get("event")
                if event in ("stdout", "stderr"):
                    on_event({"op": "exec_chunk", "stream": event, "data": message.get("data", "")})
                    continue
                if event == "completed":
                    return dict(message.get("data") or {})
                if event == "failed":
                    return _safe_error_response(message)
                continue
            if message.get("type") == "response":
                return dict(message.get("result") or {})
            if message.get("type") == "error":
                return _safe_error_response(message)

    def close(self) -> None:
        write_close(self.sock, mask=True)
        try:
            self.sock.close()
        except OSError:
            pass

    def _authenticate(self) -> None:
        challenge = self._read_message()
        if challenge.get("type") != "auth.challenge":
            raise RpcError("host did not send an auth challenge")
        host_id = str(challenge.get("host_id", ""))
        if self.host.host_id and not hmac.compare_digest(self.host.host_id, host_id):
            raise RpcError("connected host identity did not match client config")
        nonce = str(challenge.get("nonce", ""))
        signature = _signature(self.host.key, host_id, nonce, self.host.client_id)
        response = {
            "protocol": PROTOCOL,
            "type": "auth.response",
            "client_id": self.host.client_id,
            "signature": signature,
        }
        write_text(self.sock, json.dumps(response), mask=True)
        accepted = self._read_message()
        if accepted.get("type") != "auth.ok":
            raise RpcError(str(accepted.get("detail") or "authentication failed"))

    def _send_cancel(self, request_id: str) -> None:
        write_text(self.sock, json.dumps({
            "protocol": PROTOCOL,
            "type": "cancel",
            "request_id": request_id,
        }), mask=True)

    def _read_message(self) -> dict:
        try:
            text = read_text(self.sock, expect_masked=False)
            message = json.loads(text)
        except (OSError, WebSocketError, json.JSONDecodeError) as exc:
            raise RpcError("websocket connection failed") from exc
        if message.get("protocol") != PROTOCOL:
            raise RpcError("unsupported RPC protocol")
        return message


def _connect_websocket(url: str) -> socket.socket:
    parsed = urlparse(url)
    if parsed.scheme != "ws":
        raise RpcError("Level 1 supports ws:// URLs; use wss:// through the future relay")
    host = parsed.hostname
    if host is None:
        raise RpcError("websocket URL is missing a host")
    port = parsed.port or 80
    path = parsed.path or "/rpc"
    if parsed.query:
        path += "?" + parsed.query
    sock = socket.create_connection((host, port), timeout=10)
    key = client_key()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    start, headers = read_http_headers(sock)
    if not start.startswith("HTTP/1.1 101"):
        raise RpcError(f"websocket upgrade failed: {start}")
    expected = accept_key(key)
    if headers.get("sec-websocket-accept") != expected:
        raise RpcError("websocket accept key mismatch")
    sock.settimeout(None)
    return sock


def _request_envelope(request_id: str, client_id: str, req: dict) -> dict:
    return {
        "protocol": PROTOCOL,
        "type": "request",
        "request_id": request_id,
        "client_id": client_id,
        "method": _method_for(req),
        "params": _params_for(req),
        "metadata": {"caller": "valet-cli"},
    }


def _method_for(req: dict) -> str:
    op = req.get("op", "exec")
    if op == "exec":
        return "exec.run"
    if op == "chdir":
        return "session.chdir"
    if op == "ping":
        return "host.ping"
    if op == "redaction_info":
        return "redaction.info"
    return str(op)


def _params_for(req: dict) -> dict:
    params = dict(req)
    params.pop("op", None)
    return params


def legacy_request_from_rpc(message: dict) -> dict:
    method = message.get("method")
    params = dict(message.get("params") or {})
    if method == "exec.run":
        return {"op": "exec", **params}
    if method == "session.chdir":
        return {"op": "chdir", **params}
    if method == "host.ping":
        return {"op": "ping", **params}
    if method == "redaction.info":
        return {"op": "redaction_info", **params}
    return {"op": str(method or "unknown"), **params}


def _signature(key: str, host_id: str, nonce: str, client_id: str) -> str:
    body = f"{host_id}:{nonce}:{client_id}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_signature(key: str, host_id: str, nonce: str, client_id: str, signature: str) -> bool:
    expected = _signature(key, host_id, nonce, client_id)
    return hmac.compare_digest(expected, signature)


def auth_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")


def _request_id() -> str:
    return uuid.uuid4().hex


def _safe_error_response(message: dict) -> dict:
    return {
        "ok": False,
        "error_class": str(message.get("error_class") or "RpcError"),
        "detail": str(message.get("detail") or "RPC request failed"),
    }
