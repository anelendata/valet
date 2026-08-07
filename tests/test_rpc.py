import dataclasses
import json
import threading
import uuid

import pytest

from valet.client_config import ClientHost, load_client_config
from valet.config import AuditConfig, ClientIdentity, HostConfig, IdentityConfig
from valet.errors import ConfigError
from valet.rpc import (
    PROTOCOL,
    RpcError,
    Target,
    ValetClient,
    _WebSocketRpcTransport,
    _connect_websocket,
    _signature,
    legacy_request_from_rpc,
)
from valet.server_ws import auth_rejection_reason, make_server
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


class FakeRpcSocket:
    def __init__(self, messages, *, fail_request_write=False, read_error=False):
        self.messages = list(messages)
        self.fail_request_write = fail_request_write
        self.read_error = read_error
        self.sent = []
        self.closed = False

    def close(self):
        self.closed = True


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


def test_client_config_loads_reconnect_defaults_and_host_overrides(tmp_path):
    path = tmp_path / "client.toml"
    path.write_text(
        "[client]\n"
        'id = "client_a"\n'
        'key = "secret-client-key"\n'
        'default_host = "main"\n'
        "reconnect_max_retries = 7\n"
        "reconnect_backoff_seconds = 0.5\n"
        "reconnect_backoff_max_seconds = 4.0\n"
        "\n"
        "[hosts.main]\n"
        'url = "ws://127.0.0.1:8766/rpc"\n'
        "\n"
        "[hosts.fast]\n"
        'url = "ws://127.0.0.1:8767/rpc"\n'
        "reconnect_max_retries = 2\n"
        "reconnect_backoff_seconds = 0.1\n"
        "reconnect_backoff_max_seconds = 0.2\n"
    )

    cfg = load_client_config(path)

    assert cfg.hosts["main"].reconnect_max_retries == 7
    assert cfg.hosts["main"].reconnect_backoff_seconds == 0.5
    assert cfg.hosts["main"].reconnect_backoff_max_seconds == 4.0
    assert cfg.hosts["fast"].reconnect_max_retries == 2
    assert cfg.hosts["fast"].reconnect_backoff_seconds == 0.1
    assert cfg.hosts["fast"].reconnect_backoff_max_seconds == 0.2


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


def _auth_challenge():
    return {
        "protocol": PROTOCOL,
        "type": "auth.challenge",
        "host_id": "test-host",
        "nonce": "nonce",
    }


def _auth_ok():
    return {"protocol": PROTOCOL, "type": "auth.ok"}


def _rpc_host(**overrides):
    values = {
        "name": "test-host",
        "url": "ws://127.0.0.1:8766/rpc",
        "client_id": "client_a",
        "key": "client-secret",
        "host_id": "test-host",
        "reconnect_max_retries": 2,
        "reconnect_backoff_seconds": 0.1,
        "reconnect_backoff_max_seconds": 0.2,
    }
    values.update(overrides)
    return ClientHost(**values)


def _install_fake_rpc_io(monkeypatch):
    def fake_read_text(sock, expect_masked):
        if sock.messages:
            return json.dumps(sock.messages.pop(0))
        if sock.read_error:
            raise OSError("connection lost")
        raise AssertionError("unexpected websocket read")

    def fake_write_text(sock, text, mask):
        message = json.loads(text)
        if message.get("type") == "request" and sock.fail_request_write:
            sock.fail_request_write = False
            raise OSError("broken pipe")
        sock.sent.append(message)

    monkeypatch.setattr("valet.rpc.read_text", fake_read_text)
    monkeypatch.setattr("valet.rpc.write_text", fake_write_text)
    monkeypatch.setattr("valet.rpc.write_close", lambda sock, mask: None)
    monkeypatch.setattr("valet.rpc.time.sleep", lambda seconds: None)


def test_websocket_transport_retries_initial_connect_with_backoff(monkeypatch):
    _install_fake_rpc_io(monkeypatch)
    sleeps = []
    attempts = []
    sock = FakeRpcSocket([_auth_challenge(), _auth_ok()])

    def connect(url):
        attempts.append(url)
        if len(attempts) < 3:
            raise RpcError("host unavailable")
        return sock

    monkeypatch.setattr("valet.rpc._connect_websocket", connect)
    monkeypatch.setattr("valet.rpc.time.sleep", sleeps.append)

    transport = _WebSocketRpcTransport(_rpc_host())
    try:
        assert attempts == [
            "ws://127.0.0.1:8766/rpc",
            "ws://127.0.0.1:8766/rpc",
            "ws://127.0.0.1:8766/rpc",
        ]
        assert sleeps == [0.1, 0.2]
    finally:
        transport.close()


def test_websocket_transport_reconnects_when_idle_socket_write_fails(monkeypatch):
    _install_fake_rpc_io(monkeypatch)
    monkeypatch.setattr("valet.rpc._request_id", lambda: "req-1")
    first = FakeRpcSocket([_auth_challenge(), _auth_ok()], fail_request_write=True)
    second = FakeRpcSocket([
        _auth_challenge(),
        _auth_ok(),
        {
            "protocol": PROTOCOL,
            "type": "response",
            "request_id": "req-1",
            "result": {"ok": True, "pong": True},
        },
    ])
    sockets = [first, second]
    monkeypatch.setattr("valet.rpc._connect_websocket", lambda _url: sockets.pop(0))

    transport = _WebSocketRpcTransport(_rpc_host())
    try:
        resp = transport.request({"op": "ping"})
    finally:
        transport.close()

    assert resp == {"ok": True, "pong": True}
    assert first.closed is True
    second_requests = [message for message in second.sent if message.get("type") == "request"]
    assert len(second_requests) == 1
    assert second_requests[0]["method"] == "host.ping"


def test_websocket_transport_does_not_replay_after_read_failure(monkeypatch):
    _install_fake_rpc_io(monkeypatch)
    monkeypatch.setattr("valet.rpc._request_id", lambda: "req-1")
    first = FakeRpcSocket([_auth_challenge(), _auth_ok()], read_error=True)
    second = FakeRpcSocket([_auth_challenge(), _auth_ok()])
    sockets = [first, second]
    monkeypatch.setattr("valet.rpc._connect_websocket", lambda _url: sockets.pop(0))

    transport = _WebSocketRpcTransport(_rpc_host())
    try:
        resp = transport.request_stream({"op": "exec", "cmd": "touch marker"}, lambda _event: None)
    finally:
        transport.close()

    first_requests = [message for message in first.sent if message.get("type") == "request"]
    second_requests = [message for message in second.sent if message.get("type") == "request"]
    assert len(first_requests) == 1
    assert second_requests == []
    assert resp["ok"] is False
    assert resp["error_class"] == "ConnectionError"
    assert "reconnected" in resp["detail"]


@pytest.fixture
def ws_server(cfg):
    host_cfg = HostConfig(id="test-host", listen="127.0.0.1:0")
    identity = IdentityConfig(
        clients={"client_a": ClientIdentity(key="client-secret")}
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


def _reason(**overrides):
    identity = ClientIdentity(key="client-secret")
    good_sig = _signature("client-secret", "host-1", "nonce-1", "client_a")
    args = {
        "response": {"type": "auth.response", "client_id": "client_a"},
        "client_id": "client_a",
        "identity": identity,
        "signature": good_sig,
        "host_id": "host-1",
        "nonce": "nonce-1",
    }
    args.update(overrides)
    return auth_rejection_reason(
        args["response"],
        args["client_id"],
        args["identity"],
        args["signature"],
        args["host_id"],
        args["nonce"],
    )


def test_auth_rejection_reason_accepts_valid_handshake():
    assert _reason() is None


def test_auth_rejection_reason_flags_wrong_message_type():
    assert _reason(response={"type": "request"}) == "unexpected handshake message"


def test_auth_rejection_reason_flags_missing_client_id():
    assert _reason(client_id="", response={"type": "auth.response"}) == "missing client_id"


def test_auth_rejection_reason_flags_unapproved_client():
    assert _reason(identity=None) == "client identity is not approved"


def test_auth_rejection_reason_flags_bad_signature():
    assert _reason(signature="deadbeef") == "signature verification failed"
