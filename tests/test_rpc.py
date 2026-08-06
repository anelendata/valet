import dataclasses
import json
import threading
import uuid

import pytest

from valet.client_config import ClientHost, load_client_config
from valet.config import AuditConfig, ClientIdentity, HostConfig, IdentityConfig
from valet.rpc import PROTOCOL, Target, ValetClient, _connect_websocket, _signature, legacy_request_from_rpc
from valet.server_ws import make_server
from valet.wsproto import read_text, write_text


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
