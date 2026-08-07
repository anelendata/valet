"""Client-side RPC abstraction shared by CLI and REPL."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import unquote, urlparse

from .client_config import ClientConfig, ClientHost, load_client_config
from .config import BrokerConfig
from .server_uds import Connection
from .wsproto import WebSocketError, accept_key, client_key, read_http_headers, read_text, write_close, write_text

PROTOCOL = "valet-rpc/1"


class RpcError(ConnectionError):
    pass


class RpcAuthError(RpcError):
    """The host refused this client's identity (terminal, do not retry)."""
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
    client_cfg = load_client_config(
        client_config_path,
        required=client_config_path is not None,
    )
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
        self.sock: Optional[socket.socket] = None
        self._connect_with_backoff()

    def request(self, req: dict) -> dict:
        request_id = _request_id()
        try:
            self._write_request(request_id, req)
        except RpcAuthError:
            raise
        except RpcError as exc:
            return _transport_error_response(req, str(exc))
        while True:
            try:
                message = self._read_message()
            except RpcError:
                return self._lost_during_request_response(req)
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
        try:
            self._write_request(request_id, req)
        except RpcAuthError:
            raise
        except RpcError as exc:
            return _transport_error_response(req, str(exc))
        cancelled = False
        while True:
            try:
                message = self._read_message()
            except KeyboardInterrupt:
                if cancelled:
                    raise
                try:
                    self._send_cancel(request_id)
                except RpcError:
                    return self._lost_during_request_response(req)
                cancelled = True
                continue
            except RpcError:
                return self._lost_during_request_response(req)
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
        sock = self.sock
        self.sock = None
        if sock is None:
            return
        try:
            write_close(sock, mask=True)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _connect_with_backoff(self) -> None:
        self._close_socket()
        attempts = max(0, int(self.host.reconnect_max_retries)) + 1
        delay = max(0.0, float(self.host.reconnect_backoff_seconds))
        max_delay = max(delay, float(self.host.reconnect_backoff_max_seconds))
        last_error: Optional[BaseException] = None
        for attempt in range(attempts):
            try:
                self.sock = _connect_websocket(self.host.url)
                self._authenticate()
                return
            except RpcAuthError:
                # The host refused this identity; retrying will not help.
                self._close_socket()
                raise
            except (OSError, RpcError) as exc:
                last_error = exc
                self._close_socket()
                if attempt == attempts - 1:
                    break
                if delay > 0:
                    time.sleep(min(delay, max_delay))
                    delay = min(delay * 2, max_delay)
        raise RpcError("could not reconnect to websocket host") from last_error

    def _close_socket(self) -> None:
        sock = self.sock
        self.sock = None
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass

    def _write_request(self, request_id: str, req: dict) -> None:
        payload = json.dumps(_request_envelope(request_id, self.host.client_id, req))
        if self.sock is None:
            self._connect_with_backoff()
        try:
            self._send_text(payload)
        except RpcError:
            self._connect_with_backoff()
            self._send_text(payload)

    def _send_text(self, payload: str) -> None:
        if self.sock is None:
            raise RpcError("websocket is not connected")
        assert self.sock is not None
        try:
            write_text(self.sock, payload, mask=True)
        except (OSError, WebSocketError) as exc:
            self._close_socket()
            raise RpcError("websocket connection failed") from exc

    def _lost_during_request_response(self, req: dict) -> dict:
        try:
            self._connect_with_backoff()
        except RpcAuthError:
            raise
        except RpcError as exc:
            return _transport_error_response(req, str(exc))
        return _transport_error_response(
            req,
            "websocket connection lost during request; reconnected, please retry",
        )

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
            # A refused or revoked identity is terminal — surface it distinctly
            # so callers stop retrying and can tell the user they were rejected.
            raise RpcAuthError(str(accepted.get("detail") or "authentication failed"))

    def _send_cancel(self, request_id: str) -> None:
        self._send_text(json.dumps({
            "protocol": PROTOCOL,
            "type": "cancel",
            "request_id": request_id,
        }))

    def _read_message(self) -> dict:
        if self.sock is None:
            raise RpcError("websocket is not connected")
        try:
            text = read_text(self.sock, expect_masked=False)
            message = json.loads(text)
        except (OSError, WebSocketError, json.JSONDecodeError) as exc:
            self._close_socket()
            raise RpcError("websocket connection failed") from exc
        if message.get("protocol") != PROTOCOL:
            raise RpcError("unsupported RPC protocol")
        return message


def _connect_websocket(url: str) -> socket.socket:
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        raise RpcError("websocket URL must use ws:// or wss://")
    host = parsed.hostname
    if host is None:
        raise RpcError("websocket URL is missing a host")
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/rpc"
    if parsed.query:
        path += "?" + parsed.query

    sock = _open_websocket_socket(parsed.scheme, host, port)
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


def _open_websocket_socket(scheme: str, host: str, port: int) -> socket.socket:
    proxy = _proxy_for(scheme, host, port)
    if proxy is None:
        sock = _create_connection(host, port, via_proxy=False)
    else:
        sock = _connect_proxy_tunnel(proxy, host, port)
    if scheme == "wss":
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        except OSError as exc:
            raise RpcError("TLS setup for websocket connection failed") from exc
    return sock


def _create_connection(host: str, port: int, *, via_proxy: bool) -> socket.socket:
    try:
        return socket.create_connection((host, port), timeout=10)
    except (OSError, TimeoutError) as exc:
        target = "proxy" if via_proxy else "websocket destination"
        raise RpcError(f"could not connect to {target}") from exc


def _connect_proxy_tunnel(proxy, host: str, port: int) -> socket.socket:
    sock = _create_connection(proxy.hostname, proxy.port, via_proxy=True)
    authority = f"{host}:{port}"
    headers = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
    ]
    if proxy.authorization:
        headers.append(f"Proxy-Authorization: Basic {proxy.authorization}")
    request = "\r\n".join(headers) + "\r\n\r\n"
    try:
        sock.sendall(request.encode("ascii"))
        start, _headers = read_http_headers(sock)
    except (OSError, WebSocketError) as exc:
        raise RpcError("proxy CONNECT failed before a complete response") from exc

    parts = start.split(None, 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise RpcError("proxy CONNECT response was malformed")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise RpcError("proxy CONNECT response was malformed") from exc
    if status < 200 or status >= 300:
        raise RpcError(f"proxy CONNECT failed with HTTP {status}")
    return sock


@dataclass(frozen=True)
class _ProxyConfig:
    hostname: str
    port: int
    authorization: str = ""


def _proxy_for(scheme: str, host: str, port: int) -> Optional[_ProxyConfig]:
    no_proxy = _env_first(("NO_PROXY", "no_proxy"))
    if no_proxy and _no_proxy_matches(no_proxy, host, port):
        return None
    names = (
        ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
        if scheme == "wss"
        else ("HTTP_PROXY", "http_proxy")
    )
    raw = _env_first(names)
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    if parsed.scheme and parsed.scheme != "http":
        raise RpcError("unsupported proxy URL scheme")
    if parsed.hostname is None:
        raise RpcError("proxy URL is missing a host")
    auth = ""
    if parsed.username is not None:
        user = unquote(parsed.username)
        password = unquote(parsed.password or "")
        auth = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return _ProxyConfig(parsed.hostname, parsed.port or 80, auth)


def _env_first(names: tuple[str, ...]) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return ""


def _no_proxy_matches(no_proxy: str, host: str, port: int) -> bool:
    host = host.strip("[]").lower()
    for raw_item in no_proxy.split(","):
        item = raw_item.strip().lower()
        if not item:
            continue
        if item == "*":
            return True
        item_host, item_port = _split_no_proxy_item(item)
        if item_port is not None and item_port != port:
            continue
        if _host_matches_no_proxy_item(host, item_host):
            return True
    return False


def _split_no_proxy_item(item: str) -> tuple[str, Optional[int]]:
    if item.startswith("["):
        end = item.find("]")
        if end != -1:
            host = item[1:end]
            rest = item[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
    if item.count(":") == 1:
        maybe_host, maybe_port = item.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_host, int(maybe_port)
    return item, None


def _host_matches_no_proxy_item(host: str, item: str) -> bool:
    item = item.strip("[]")
    if not item:
        return False
    if item.startswith("."):
        suffix = item[1:]
        return host == suffix or host.endswith("." + suffix)
    return host == item or host.endswith("." + item)


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


def _transport_error_response(req: dict, detail: str) -> dict:
    return {
        "ok": False,
        "error_class": "ConnectionError",
        "detail": detail,
        "request_op": str(req.get("op", "exec")),
    }
