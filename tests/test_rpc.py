import dataclasses
import json
import threading
import uuid

import pytest

from valet.client_config import ClientHost, load_client_config
from valet.config import AuditConfig, ClientIdentity, HostConfig, IdentityConfig
from valet.errors import ConfigError
from valet.rpc import PROTOCOL, RpcError, Target, ValetClient, _connect_websocket, _signature, legacy_request_from_rpc
from valet.server_ws import make_server
from valet.wsproto import accept_key, read_text, write_text


_PROXY_ENV = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)


@pytest.fixture(autouse=True)
def clear_proxy_env(monkeypatch):
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeout = "initial"

    def recv(self, n):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        out, rest = chunk[:n], chunk[n:]
        if rest:
            self.chunks.insert(0, rest)
        return out

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        pass


def _ws_upgrade_response(key="test-key"):
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        f"Sec-WebSocket-Accept: {accept_key(key)}\r\n"
        "\r\n"
    ).encode("ascii")


def test_client_config_is_remote_subset(tmp_path):
    path = tmp_path / "client.toml"
    path.write_text(
        "[client]\n"
        'id = "client_a"\n'
        'key = "secret-client-key"\n'
        'default_host = "main"\n'
        "\n"
        "[hosts.main]\n"
        'url = "ws://127.0.0.1:8766/rpc"\n'
        'host_id = "main-host-id"\n'
    )

    cfg = load_client_config(path)

    assert cfg.default_host == "main"
    assert cfg.hosts["main"].url == "ws://127.0.0.1:8766/rpc"
    assert cfg.hosts["main"].client_id == "client_a"
    assert cfg.hosts["main"].key == "secret-client-key"
    assert cfg.hosts["main"].host_id == "main-host-id"


def test_explicit_missing_client_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="client config not found"):
        load_client_config(tmp_path / "missing-client.toml", required=True)


def test_rpc_request_maps_to_legacy_broker_request():
    request = legacy_request_from_rpc({
        "method": "exec.run",
        "params": {"cmd": ["echo", "hi"], "shell": False, "stream": True},
    })

    assert request == {
        "op": "exec",
        "cmd": ["echo", "hi"],
        "shell": False,
        "stream": True,
    }


def test_connect_websocket_without_proxy_connects_directly(monkeypatch):
    monkeypatch.setattr("valet.rpc.client_key", lambda: "test-key")
    sock = FakeSocket([_ws_upgrade_response()])
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        return sock

    monkeypatch.setattr("valet.rpc.socket.create_connection", connect)

    assert _connect_websocket("ws://dest.test:8766/rpc") is sock
    assert calls == [(("dest.test", 8766), 10)]
    assert sock.sent[0].startswith(b"GET /rpc HTTP/1.1\r\n")
    assert b"CONNECT" not in sock.sent[0]
    assert sock.timeout is None


def test_connect_websocket_uses_http_proxy_connect(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.local:3128")
    monkeypatch.setattr("valet.rpc.client_key", lambda: "test-key")
    sock = FakeSocket([
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        _ws_upgrade_response(),
    ])
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        return sock

    monkeypatch.setattr("valet.rpc.socket.create_connection", connect)

    assert _connect_websocket("ws://dest.test:8766/rpc") is sock
    assert calls == [(("proxy.local", 3128), 10)]
    assert sock.sent[0].startswith(b"CONNECT dest.test:8766 HTTP/1.1\r\n")
    assert b"Host: dest.test:8766\r\n" in sock.sent[0]
    assert sock.sent[1].startswith(b"GET /rpc HTTP/1.1\r\n")


def test_connect_websocket_rejects_proxy_forbidden_without_leaking_credentials(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://user:super-secret@proxy.local:3128")
    sock = FakeSocket([b"HTTP/1.1 403 Forbidden\r\n\r\n"])
    monkeypatch.setattr("valet.rpc.socket.create_connection", lambda _address, timeout: sock)

    with pytest.raises(RpcError) as excinfo:
        _connect_websocket("ws://dest.test:8766/rpc")

    detail = str(excinfo.value)
    assert "HTTP 403" in detail
    assert "user" not in detail
    assert "super-secret" not in detail


@pytest.mark.parametrize(
    ("chunks", "message"),
    [
        ([b"not-http\r\n\r\n"], "malformed"),
        ([], "complete response"),
    ],
)
def test_connect_websocket_proxy_bad_response_errors(monkeypatch, chunks, message):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.local:3128")
    sock = FakeSocket(chunks)
    monkeypatch.setattr("valet.rpc.socket.create_connection", lambda _address, timeout: sock)

    with pytest.raises(RpcError, match=message):
        _connect_websocket("ws://dest.test:8766/rpc")


def test_connect_websocket_reads_fragmented_proxy_headers(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://proxy.local:3128")
    monkeypatch.setattr("valet.rpc.client_key", lambda: "test-key")
    sock = FakeSocket([
        b"HTTP/1.1 2",
        b"00 Connection",
        b" Established\r\n",
        b"Proxy-Agent: test\r\n",
        b"\r\n",
        _ws_upgrade_response(),
    ])
    monkeypatch.setattr("valet.rpc.socket.create_connection", lambda _address, timeout: sock)

    assert _connect_websocket("ws://dest.test:8766/rpc") is sock
    assert sock.sent[1].startswith(b"GET /rpc HTTP/1.1\r\n")


@pytest.mark.parametrize(
    ("no_proxy", "url"),
    [
        ("dest.test", "ws://dest.test:8766/rpc"),
        ("10.0.0.100:8766", "ws://10.0.0.100:8766/rpc"),
        (".example.test", "ws://api.example.test:8766/rpc"),
        ("*", "ws://anything.test:8766/rpc"),
    ],
)
def test_connect_websocket_no_proxy_bypasses_proxy(monkeypatch, no_proxy, url):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.local:3128")
    monkeypatch.setenv("NO_PROXY", no_proxy)
    monkeypatch.setattr("valet.rpc.client_key", lambda: "test-key")
    sock = FakeSocket([_ws_upgrade_response()])
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        return sock

    monkeypatch.setattr("valet.rpc.socket.create_connection", connect)

    assert _connect_websocket(url) is sock
    assert calls[0][0][0] != "proxy.local"
    assert sock.sent[0].startswith(b"GET /rpc HTTP/1.1\r\n")


def test_connect_websocket_wss_wraps_tls_after_proxy_tunnel(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.local:3128")
    monkeypatch.setattr("valet.rpc.client_key", lambda: "test-key")
    sock = FakeSocket([
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        _ws_upgrade_response(),
    ])
    monkeypatch.setattr("valet.rpc.socket.create_connection", lambda _address, timeout: sock)
    wrapped = []

    class FakeContext:
        def wrap_socket(self, raw_sock, server_hostname):
            wrapped.append((raw_sock, server_hostname, list(raw_sock.sent)))
            return raw_sock

    monkeypatch.setattr("valet.rpc.ssl.create_default_context", lambda: FakeContext())

    assert _connect_websocket("wss://secure.test:9443/rpc") is sock
    assert wrapped == [(sock, "secure.test", [sock.sent[0]])]
    assert sock.sent[0].startswith(b"CONNECT secure.test:9443 HTTP/1.1\r\n")
    assert sock.sent[1].startswith(b"GET /rpc HTTP/1.1\r\n")


@pytest.fixture
def ws_server(cfg):
    host_cfg = HostConfig(id="test-host", listen="127.0.0.1:0")
    identity = IdentityConfig(
        clients={"client_a": ClientIdentity(name="test client", key="client-secret")}
    )
    server = make_server(dataclasses.replace(
        cfg,
        audit=AuditConfig(console=False),
        host=host_cfg,
        identity=identity,
    ))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"ws://{host}:{port}/rpc"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _remote_client(cfg, url):
    host = ClientHost(
        name="test-host",
        url=url,
        client_id="client_a",
        key="client-secret",
    )
    return ValetClient(Target(kind="websocket", name="test-host", host=host), cfg)


def test_websocket_rpc_ping(cfg, ws_server):
    client = _remote_client(cfg, ws_server)
    try:
        resp = client.request({"op": "ping"})
    finally:
        client.close()

    assert resp["ok"] is True
    assert resp["pong"] is True


def test_websocket_rpc_streams_exec_chunks(cfg, ws_server):
    client = _remote_client(cfg, ws_server)
    chunks = []
    try:
        resp = client.request_stream(
            {"op": "exec", "cmd": "printf 'one\\ntwo\\n'", "shell": True},
            chunks.append,
        )
    finally:
        client.close()

    assert [chunk["data"] for chunk in chunks] == ["one\n", "two\n"]
    assert resp["op"] == "exec"
    assert resp["ok"] is True
    assert resp["streamed"] is True


def test_websocket_rpc_cancel_stops_streamed_exec(ws_server):
    sock = _connect_websocket(ws_server)
    try:
        challenge = json.loads(read_text(sock, expect_masked=False))
        signature = _signature(
            "client-secret",
            challenge["host_id"],
            challenge["nonce"],
            "client_a",
        )
        write_text(sock, json.dumps({
            "protocol": PROTOCOL,
            "type": "auth.response",
            "client_id": "client_a",
            "signature": signature,
        }), mask=True)
        assert json.loads(read_text(sock, expect_masked=False))["type"] == "auth.ok"

        request_id = uuid.uuid4().hex
        write_text(sock, json.dumps({
            "protocol": PROTOCOL,
            "type": "request",
            "request_id": request_id,
            "client_id": "client_a",
            "method": "exec.run",
            "params": {"cmd": "sleep 5", "shell": True, "stream": True, "timeout": 10},
        }), mask=True)
        assert json.loads(read_text(sock, expect_masked=False))["event"] == "accepted"
        write_text(sock, json.dumps({
            "protocol": PROTOCOL,
            "type": "cancel",
            "request_id": request_id,
        }), mask=True)

        final = None
        while final is None:
            message = json.loads(read_text(sock, expect_masked=False))
            if message.get("event") == "completed":
                final = message["data"]
        assert final["exit_code"] == 130
        assert final["ok"] is False
    finally:
        sock.close()
