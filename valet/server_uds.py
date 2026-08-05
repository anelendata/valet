"""Primary transport: a Unix-domain-socket daemon.

Access control is the OS: the socket file is created 0600 and owned by the user
who started the daemon. No port, no network surface, no token. Protocol is
newline-delimited JSON — one request object per line, one response object per
line.
"""
from __future__ import annotations

import getpass
import json
import os
import socket
import socketserver
import stat
from pathlib import Path

from .broker import Broker
from .config import BrokerConfig
from .errors import ConfigError

# Both macOS and Linux cap AF_UNIX paths (~104 / ~108 bytes). Fail with a clear
# message instead of a raw OSError from bind()/connect().
_MAX_SOCK_PATH = 100


def _check_sock_path(path: str) -> None:
    if len(os.fsencode(path)) > _MAX_SOCK_PATH:
        raise ConfigError(
            f"socket_path is too long ({len(path)} bytes; limit ~{_MAX_SOCK_PATH}). "
            "Use a short path like ~/.valet/broker.sock."
        )


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        broker: Broker = self.server.broker  # type: ignore[attr-defined]
        for line in self.rfile:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                response = {"ok": False, "error_class": "ValidationError",
                            "detail": "request was not valid JSON"}
            else:
                if request.get("stream") and request.get("op", "exec") == "exec":
                    for event in broker.handle_stream(
                        request,
                        audit_context={"transport": "uds", "caller": getpass.getuser()},
                    ):
                        self.wfile.write((json.dumps(event) + "\n").encode("utf-8"))
                        self.wfile.flush()
                    continue
                response = broker.handle(
                    request,
                    audit_context={"transport": "uds", "caller": getpass.getuser()},
                )
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
            self.wfile.flush()


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(cfg: BrokerConfig) -> None:
    _check_sock_path(cfg.socket_path)
    sock_path = Path(cfg.socket_path)
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if sock_path.exists():
        sock_path.unlink()

    # Restrict the directory and (below) the socket to the owner.
    try:
        os.chmod(sock_path.parent, stat.S_IRWXU)
    except OSError:
        pass

    server = _Server(str(sock_path), _Handler)
    server.broker = Broker(cfg, audit_to_console=cfg.audit.console)  # type: ignore[attr-defined]
    os.chmod(sock_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    print(f"valet: listening on {sock_path} (0600). Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if sock_path.exists():
            sock_path.unlink()


class Connection:
    """A persistent client connection to the daemon.

    The daemon reads newline-delimited requests in a loop, so one connection
    can serve many requests — used by the interactive REPL. Leftover bytes
    after a response are buffered for the next ``request``.
    """

    def __init__(self, socket_path: str):
        socket_path = os.path.expanduser(socket_path)
        _check_sock_path(socket_path)
        self.socket_path = socket_path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(socket_path)
        self._buf = b""

    def request(self, req: dict) -> dict:
        self._sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        response = self._read_response()
        if response.get("op") != "exec_chunk":
            return response

        stdout = []
        stderr = []
        while response.get("op") == "exec_chunk":
            if response.get("stream") == "stderr":
                stderr.append(response.get("data") or "")
            else:
                stdout.append(response.get("data") or "")
            response = self._read_response()
        if response.get("op") == "exec":
            response = dict(response)
            response["stdout"] = "".join(stdout)
            response["stderr"] = "".join(stderr)
        return response

    def request_stream(self, req: dict, on_event) -> dict:
        self._sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        while True:
            response = self._read_response()
            if response.get("op") == "exec_chunk":
                on_event(response)
                continue
            return response

    def _read_response(self) -> dict:
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("daemon closed the connection")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return json.loads(line.decode("utf-8"))

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def call_once(socket_path: str, request: dict) -> dict:
    """Connect, send one request, return the parsed response. Used by client."""
    conn = Connection(socket_path)
    try:
        return conn.request(request)
    finally:
        conn.close()
