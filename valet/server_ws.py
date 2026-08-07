"""Level 1 WebSocket RPC host adapter."""
from __future__ import annotations

import getpass
import json
import queue
import select
import socket
import socketserver
import threading
from typing import Any

from .broker import Broker
from .config import BrokerConfig
from .errors import ConfigError
from .rpc import PROTOCOL, auth_nonce, legacy_request_from_rpc, verify_signature
from .wsproto import WebSocketError, accept_key, read_http_headers, read_text, write_close, write_text

# Sent to a client whose identity was removed from the config, right before the
# host closes the connection on reload.
REVOKED_REASON = "client identity was removed by the host"


class _ConnectionRegistry:
    """Tracks authenticated handlers so reload can revoke removed clients.

    Kept separate from the socket server so it can be unit-tested without
    binding a listener.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handlers: dict[int, Any] = {}

    def add(self, handler: Any) -> None:
        with self._lock:
            self._handlers[id(handler)] = handler

    def remove(self, handler: Any) -> None:
        with self._lock:
            self._handlers.pop(id(handler), None)

    def revoke_clients(self, removed_ids, reason: str) -> list[str]:
        """Revoke every tracked connection whose client_id was removed.

        Returns the client_ids actually revoked (one entry per connection).
        """
        removed = set(removed_ids)
        if not removed:
            return []
        with self._lock:
            targets = [h for h in self._handlers.values() if h.client_id in removed]
        revoked = []
        for handler in targets:
            if handler.revoke(reason):
                revoked.append(handler.client_id)
        return revoked


def _parse_listen(value: str) -> tuple[str, int]:
    if ":" not in value:
        raise ConfigError("host.listen must be in HOST:PORT form")
    host, port_text = value.rsplit(":", 1)
    return host, int(port_text)


def auth_rejection_reason(response, client_id, identity, signature, host_id, nonce):
    """Why an auth handshake is refused, or None when it is accepted.

    The reason is a fixed, non-sensitive label — never the signature or key —
    so it is safe to write to the audit log.
    """
    if response.get("type") != "auth.response":
        return "unexpected handshake message"
    if not client_id:
        return "missing client_id"
    if identity is None:
        return "client identity is not approved"
    if not verify_signature(identity.key, host_id, nonce, client_id, signature):
        return "signature verification failed"
    return None


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self._write_lock = threading.Lock()
        self._revoked = False
        self.client_id = ""
        registered = False
        try:
            self._upgrade()
            self.client_id = self._authenticate()
            self.server.connections.add(self)  # type: ignore[attr-defined]
            registered = True
            self._serve_rpc(self.client_id)
        except (OSError, WebSocketError, ConfigError):
            return
        finally:
            if registered:
                self.server.connections.remove(self)  # type: ignore[attr-defined]
            with self._write_lock:
                if not self._revoked:
                    try:
                        write_close(self.request, mask=False)
                    except OSError:
                        pass

    def revoke(self, reason: str) -> bool:
        """Send a final revocation message, then drop the connection.

        Called from the reload thread when this client's identity was removed.
        Returns True if it revoked a still-active connection, False if it was
        already revoked. Safe to call concurrently with the handler thread: the
        write lock serialises frames and the socket shutdown unblocks a reader.
        """
        with self._write_lock:
            if self._revoked:
                return False
            self._revoked = True
            try:
                write_text(self.request, json.dumps({
                    "protocol": PROTOCOL,
                    "type": "auth.revoked",
                    "error_class": "authentication_revoked",
                    "detail": reason,
                }), mask=False)
                write_close(self.request, mask=False)
            except OSError:
                pass
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        return True

    @property
    def broker(self) -> Broker:
        return self.server.broker  # type: ignore[attr-defined]

    @property
    def cfg(self) -> BrokerConfig:
        return self.server.cfg  # type: ignore[attr-defined]

    def _upgrade(self) -> None:
        start, headers = read_http_headers(self.request)
        parts = start.split()
        if len(parts) < 2 or parts[0] != "GET" or parts[1].split("?", 1)[0] != "/rpc":
            self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            raise WebSocketError("bad websocket path")
        key = headers.get("sec-websocket-key", "")
        if headers.get("upgrade", "").lower() != "websocket" or not key:
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            raise WebSocketError("bad websocket upgrade")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key(key)}\r\n"
            "\r\n"
        )
        self.request.sendall(response.encode("ascii"))

    def _authenticate(self) -> str:
        nonce = auth_nonce()
        challenge = {
            "protocol": PROTOCOL,
            "type": "auth.challenge",
            "host_id": self.cfg.host.id,
            "nonce": nonce,
        }
        write_text(self.request, json.dumps(challenge), mask=False)
        response = self._read_message()
        client_id = str(response.get("client_id", ""))
        signature = str(response.get("signature", ""))
        identity = self.cfg.identity.clients.get(client_id)
        reason = auth_rejection_reason(
            response, client_id, identity, signature, self.cfg.host.id, nonce
        )
        if reason is not None:
            self.broker.audit_security_rejection(
                op="auth",
                caller=client_id,
                transport="websocket",
                detail=reason,
                peer=self._peer_label(),
            )
            write_text(self.request, json.dumps({
                "protocol": PROTOCOL,
                "type": "auth.failed",
                "error_class": "authentication_failed",
                "detail": "client identity is not approved by this host",
            }), mask=False)
            raise WebSocketError("authentication failed")
        write_text(self.request, json.dumps({"protocol": PROTOCOL, "type": "auth.ok"}),
                   mask=False)
        return client_id

    def _peer_label(self) -> str:
        addr = self.client_address
        if isinstance(addr, tuple) and len(addr) >= 2:
            return f"{addr[0]}:{addr[1]}"
        return str(addr)

    def _serve_rpc(self, client_id: str) -> None:
        while True:
            message = self._read_message()
            if message.get("type") == "cancel":
                self._write_error(message, "operation_failed", "cancellation is not active")
                continue
            if message.get("type") != "request":
                self._write_error(message, "invalid_request", "expected request message")
                continue
            if message.get("client_id") != client_id:
                self._write_error(message, "authorization_denied", "client_id mismatch")
                continue
            request = legacy_request_from_rpc(message)
            audit_context = {
                "transport": "websocket",
                "caller": client_id or getpass.getuser(),
            }
            if request.get("op") == "exec" and request.get("stream"):
                self._stream_request(message, request, audit_context)
            else:
                response = self.broker.handle(request, audit_context=audit_context)
                self._write({
                    "protocol": PROTOCOL,
                    "type": "response",
                    "request_id": message.get("request_id"),
                    "result": response,
                })

    def _stream_request(self, message: dict, request: dict, audit_context: dict[str, Any]) -> None:
        sequence = 0
        cancel_event = threading.Event()
        done = threading.Event()
        events: queue.Queue[dict] = queue.Queue()

        def run_stream() -> None:
            try:
                for broker_event in self.broker.handle_stream(
                    request,
                    audit_context=audit_context,
                    cancel_event=cancel_event,
                ):
                    events.put(broker_event)
            finally:
                done.set()

        worker = threading.Thread(target=run_stream, daemon=True)
        worker.start()
        self._write_event(message, sequence, "accepted", True)
        while not done.is_set() or not events.empty():
            try:
                broker_event = events.get(timeout=0.05)
            except queue.Empty:
                broker_event = None
            if broker_event is not None:
                sequence += 1
                if broker_event.get("op") == "exec_chunk":
                    self._write_event(
                        message,
                        sequence,
                        str(broker_event.get("stream") or "stdout"),
                        broker_event.get("data") or "",
                    )
                else:
                    self._write_event(message, sequence, "completed", broker_event)
            readable, _, _ = select.select([self.request], [], [], 0)
            if readable:
                control = self._read_message()
                if (
                    control.get("type") == "cancel"
                    and control.get("request_id") == message.get("request_id")
                ):
                    cancel_event.set()
        worker.join(timeout=1)

    def _read_message(self) -> dict:
        try:
            message = json.loads(read_text(self.request, expect_masked=True))
        except json.JSONDecodeError as exc:
            raise WebSocketError("invalid JSON") from exc
        if message.get("protocol") != PROTOCOL:
            raise WebSocketError("unsupported RPC protocol")
        return message

    def _write_event(self, message: dict, sequence: int, event: str, data: Any) -> None:
        self._write({
            "protocol": PROTOCOL,
            "type": "event",
            "request_id": message.get("request_id"),
            "sequence": sequence,
            "event": event,
            "data": data,
        })

    def _write_error(self, message: dict, error_class: str, detail: str) -> None:
        self._write({
            "protocol": PROTOCOL,
            "type": "error",
            "request_id": message.get("request_id"),
            "error_class": error_class,
            "detail": detail,
        })

    def _write(self, payload: dict) -> None:
        with self._write_lock:
            if self._revoked:
                return
            write_text(self.request, json.dumps(payload), mask=False)


class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connections = _ConnectionRegistry()

    def disconnect_clients(self, removed_ids, reason: str = REVOKED_REASON) -> list[str]:
        """Revoke and drop every active connection for a removed client id."""
        return self.connections.revoke_clients(removed_ids, reason)


def make_server(cfg: BrokerConfig, *, broker: Broker | None = None) -> _Server:
    if not cfg.identity.clients:
        raise ConfigError(
            "identity.clients must contain at least one approved client before "
            "starting the LAN WebSocket listener"
        )
    server = _Server(_parse_listen(cfg.host.listen), _Handler)
    server.cfg = cfg  # type: ignore[attr-defined]
    server.broker = broker or Broker(cfg, audit_to_console=cfg.audit.console)  # type: ignore[attr-defined]
    return server


def serve(cfg: BrokerConfig) -> None:
    server = make_server(cfg)
    host, port = server.server_address[:2]
    print(
        f"valet: listening on ws://{host}:{port}/rpc "
        "(trusted LAN only). Ctrl-C to stop."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
