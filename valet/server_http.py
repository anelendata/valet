"""Optional HTTP transport for the valet broker.

The primary transport remains the Unix-domain socket. This adapter exposes the
same request/response JSON contract over HTTP for clients that cannot speak UDS.
Every request must carry ``Authorization: Bearer <token>``.
"""
from __future__ import annotations

import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .broker import Broker
from .config import BrokerConfig
from .errors import ConfigError

_MAX_REQUEST_BYTES = 1024 * 1024


def _validate_token(token: str) -> None:
    if not token or token.startswith("CHANGE_ME"):
        raise ConfigError(
            "http.bearer_token must be set before running `valet serve-http`"
        )


def _authorized_header(actual: str, token: str) -> bool:
    expected = f"Bearer {token}"
    return secrets.compare_digest(actual, expected)


def _decode_json_body(body: bytes) -> Any:
    if len(body) > _MAX_REQUEST_BYTES:
        raise ValueError("request body too large")
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"request was not valid JSON: {exc}") from exc


def handle_post(
    broker: Broker,
    bearer_token: str,
    path: str,
    authorization: str,
    body: bytes,
) -> tuple[HTTPStatus, dict, dict[str, str]]:
    """Handle one HTTP POST body. Split out so tests need no listening socket."""
    if path not in ("/", "/call"):
        return HTTPStatus.NOT_FOUND, {"ok": False, "detail": "not found"}, {}
    if not _authorized_header(authorization, bearer_token):
        return (
            HTTPStatus.UNAUTHORIZED,
            {
                "ok": False,
                "error_class": "Unauthorized",
                "detail": "missing or invalid bearer token",
            },
            {"WWW-Authenticate": 'Bearer realm="valet"'},
        )

    try:
        request = _decode_json_body(body)
    except ValueError as exc:
        response = {
            "ok": False,
            "error_class": "ValidationError",
            "detail": str(exc),
        }
    else:
        response = broker.handle(request)
    return HTTPStatus.OK, response, {}


class _Handler(BaseHTTPRequestHandler):
    server_version = "valet-http"
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        broker: Broker = self.server.broker  # type: ignore[attr-defined]
        bearer_token: str = self.server.bearer_token  # type: ignore[attr-defined]
        try:
            body = self._read_body()
        except ValueError as exc:
            status, response, extra_headers = HTTPStatus.OK, {
                "ok": False,
                "error_class": "ValidationError",
                "detail": str(exc),
            }, {}
        else:
            status, response, extra_headers = handle_post(
                broker,
                bearer_token,
                self.path,
                self.headers.get("Authorization", ""),
                body,
            )

        self._send_json(status, response, extra_headers)

    def do_GET(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"ok": False, "detail": "use POST with a JSON request body"},
            {"Allow": "POST"},
        )

    def log_message(self, format: str, *args: Any) -> None:
        # Keep daemon output quiet; command results are returned in JSON.
        return

    def _read_body(self) -> bytes:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise ValueError("missing Content-Length")
        try:
            length = int(raw_len)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length > _MAX_REQUEST_BYTES:
            raise ValueError("request body too large")
        if length < 0:
            raise ValueError("invalid Content-Length")
        return self.rfile.read(length)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = (json.dumps(payload) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def make_server(cfg: BrokerConfig) -> _Server:
    """Build an HTTP server without starting it. Used by tests."""
    _validate_token(cfg.http.bearer_token)
    server = _Server((cfg.http.host, cfg.http.port), _Handler)
    server.broker = Broker(cfg)  # type: ignore[attr-defined]
    server.bearer_token = cfg.http.bearer_token  # type: ignore[attr-defined]
    return server


def serve(cfg: BrokerConfig) -> None:
    server = make_server(cfg)
    host, port = server.server_address[:2]
    print(f"valet: listening on http://{host}:{port} with bearer auth. Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
