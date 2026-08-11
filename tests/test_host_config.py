import dataclasses
import json

import pytest

from valet.broker import Broker
from valet.cli import main
from valet.config import AuditConfig, ClientIdentity, IdentityConfig, load_config
from valet.server_host import _apply_reloaded_config


class _FakeWsServer:
    """Stand-in for the LAN server that records disconnect calls."""

    def __init__(self, cfg=None):
        self.cfg = cfg
        self.disconnect_calls = []

    def disconnect_clients(self, removed_ids, reason=None):
        self.disconnect_calls.append((set(removed_ids), reason))
        # Emulate the real server: every removed id had one live connection.
        return list(removed_ids)


def _config(path):
    path.write_text(
        "[broker]\n"
        'fingerprint_salt = "test-salt"\n'
        "\n"
        "[host]\n"
        'id = "test-host"\n'
        'listen = "0.0.0.0:8766"\n'
        "\n"
        "[workspaces.main]\n"
        f'path = "{path.parent}"\n'
    )


def test_host_lan_defaults_off(tmp_path):
    path = tmp_path / "config.toml"
    _config(path)

    cfg = load_config(path)

    assert cfg.host.lan is False


def test_host_lan_can_be_enabled_in_config(tmp_path):
    path = tmp_path / "config.toml"
    _config(path)
    text = path.read_text()
    path.write_text(text.replace('[host]\n', '[host]\nlan = true\n'))

    cfg = load_config(path)

    assert cfg.host.lan is True


def test_exec_env_table_loads(tmp_path):
    path = tmp_path / "config.toml"
    _config(path)
    path.write_text(
        path.read_text()
        + '\n[exec.env]\n'
        'AWS_SHARED_CREDENTIALS_FILE = "$VALET_WORKSPACE/.aws/credentials"\n'
    )

    cfg = load_config(path)

    assert cfg.exec.env == {
        "AWS_SHARED_CREDENTIALS_FILE": "$VALET_WORKSPACE/.aws/credentials"
    }


def test_exec_env_invalid_name_is_rejected(tmp_path):
    from valet.errors import ConfigError

    path = tmp_path / "config.toml"
    _config(path)
    path.write_text(path.read_text() + '\n[exec.env]\n"BAD NAME" = "x"\n')

    with pytest.raises(ConfigError):
        load_config(path)


def test_serve_uses_configured_host_daemon(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    _config(path)
    text = path.read_text()
    path.write_text(text.replace('[host]\n', '[host]\nlan = true\n'))
    called = {}

    def fake_serve_host(cfg, *, config_path):
        called["cfg"] = cfg
        called["config_path"] = config_path

    monkeypatch.setattr("valet.cli.serve_host", fake_serve_host)

    assert main(["-c", str(path), "serve"]) == 0
    assert called["cfg"].host.lan is True
    assert called["config_path"] == path


def test_clients_add_updates_host_config(tmp_path, capsys, monkeypatch):
    path = tmp_path / "config.toml"
    _config(path)
    # Pin IP detection off so the placeholder is deterministic regardless of the
    # host running the tests.
    monkeypatch.setattr("valet.cli._detect_lan_ip", lambda: None)

    rc = main(["-c", str(path), "clients", "add", "local box"])

    assert rc == 0
    cfg = load_config(path)
    assert "local-box" in cfg.identity.clients
    assert "client-local-box" not in cfg.identity.clients
    assert cfg.identity.clients["local-box"].key
    out = capsys.readouterr().out
    assert 'id = "local-box"' in out
    # The section is named after the host, so host_id is implied and omitted.
    assert "[hosts.test-host]" in out
    assert "host_id" not in out
    assert 'url = "ws://<host-lan-ip>:8766/rpc"' in out


def test_clients_add_fills_detected_lan_ip(tmp_path, capsys, monkeypatch):
    path = tmp_path / "config.toml"
    _config(path)
    # A wildcard-bound host fills the detected LAN IP into the client snippet.
    monkeypatch.setattr("valet.cli._detect_lan_ip", lambda: "192.168.1.42")

    rc = main(["-c", str(path), "clients", "add", "local box"])

    assert rc == 0
    out = capsys.readouterr().out
    assert 'url = "ws://192.168.1.42:8766/rpc"' in out


def test_clients_add_url_flag_overrides_detection(tmp_path, capsys, monkeypatch):
    path = tmp_path / "config.toml"
    _config(path)
    # An explicit --url always wins, even when detection would succeed.
    monkeypatch.setattr("valet.cli._detect_lan_ip", lambda: "192.168.1.42")

    rc = main(["-c", str(path), "clients", "add", "local box",
               "--url", "ws://valet.example:9999/rpc"])

    assert rc == 0
    assert 'url = "ws://valet.example:9999/rpc"' in capsys.readouterr().out


def test_clients_add_rotates_existing_with_yes(tmp_path):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    first = load_config(path).identity.clients["local-box"].key

    assert main(["-c", str(path), "clients", "add", "local box", "--yes"]) == 0
    second = load_config(path).identity.clients["local-box"].key

    assert second
    assert second != first


def test_clients_add_existing_requires_confirmation(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    first = load_config(path).identity.clients["local-box"].key
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    rc = main(["-c", str(path), "clients", "add", "local box"])
    second = load_config(path).identity.clients["local-box"].key

    assert rc == 1
    assert second == first


def test_clients_list_prints_approved_clients(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    capsys.readouterr()

    rc = main(["-c", str(path), "clients", "list"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "local-box" in out
    assert "key=set" in out
    assert load_config(path).identity.clients["local-box"].key not in out


def test_clients_remove_deletes_approved_client(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    capsys.readouterr()

    rc = main(["-c", str(path), "clients", "remove", "local box"])

    assert rc == 0
    assert "local-box" not in load_config(path).identity.clients
    out = capsys.readouterr().out
    assert "removed client" in out
    assert "local-box" in out


def test_clients_remove_missing_client_reports_not_found(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)

    rc = main(["-c", str(path), "clients", "remove", "missing"])

    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_clients_add_rejects_empty_id(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)

    rc = main(["-c", str(path), "clients", "add", "!!!"])

    assert rc == 2
    assert "client id" in capsys.readouterr().err


def test_legacy_name_prefixed_identity_still_loads(tmp_path):
    # Configs written before the id-only schema carry a `name` field and a
    # `client-` prefixed section. They must keep authenticating: the section
    # name is the id, and the legacy `name` is ignored.
    path = tmp_path / "config.toml"
    _config(path)
    path.write_text(
        path.read_text()
        + '\n[identity.clients.client-legacy-box]\n'
        'name = "legacy box"\n'
        'key = "legacy-key"\n'
    )

    cfg = load_config(path)

    assert "client-legacy-box" in cfg.identity.clients
    assert cfg.identity.clients["client-legacy-box"].key == "legacy-key"
    assert not hasattr(cfg.identity.clients["client-legacy-box"], "name")


def test_reloaded_config_updates_broker_and_websocket_server_state(cfg):
    broker = Broker(cfg, audit_to_console=False)
    ws_server = _FakeWsServer(cfg)
    new_cfg = dataclasses.replace(
        cfg,
        policy=dataclasses.replace(cfg.policy, deny_exec=("echo",)),
        identity=IdentityConfig(
            clients={"new-client": ClientIdentity(key="new-key")}
        ),
    )

    _apply_reloaded_config(broker, ws_server, new_cfg)

    resp = broker.handle({"op": "exec", "cmd": "echo hi"})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert ws_server.cfg.identity.clients["new-client"].key == "new-key"
    # Adding a client removes nobody, so no disconnect is attempted.
    assert ws_server.disconnect_calls == []


def _identity_cfg(cfg, client_ids):
    return dataclasses.replace(
        cfg,
        identity=IdentityConfig(
            clients={cid: ClientIdentity(key=f"key-{cid}") for cid in client_ids}
        ),
    )


def test_reload_disconnects_only_removed_clients(cfg):
    old_cfg = _identity_cfg(cfg, ["keep", "drop"])
    new_cfg = _identity_cfg(cfg, ["keep"])
    broker = Broker(old_cfg, audit_to_console=False)
    ws_server = _FakeWsServer(old_cfg)

    _apply_reloaded_config(broker, ws_server, new_cfg)

    assert ws_server.disconnect_calls == [({"drop"}, None)]
    assert ws_server.cfg is new_cfg


def test_reload_without_removals_does_not_disconnect(cfg):
    old_cfg = _identity_cfg(cfg, ["keep"])
    new_cfg = _identity_cfg(cfg, ["keep", "added"])
    broker = Broker(old_cfg, audit_to_console=False)
    ws_server = _FakeWsServer(old_cfg)

    _apply_reloaded_config(broker, ws_server, new_cfg)

    assert ws_server.disconnect_calls == []


def test_reload_audits_client_revocation(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    old_cfg = dataclasses.replace(
        _identity_cfg(cfg, ["drop"]),
        audit=AuditConfig(log_path=str(audit_log)),
    )
    new_cfg = dataclasses.replace(old_cfg, identity=IdentityConfig(clients={}))
    broker = Broker(old_cfg, audit_to_console=False)
    ws_server = _FakeWsServer(old_cfg)

    _apply_reloaded_config(broker, ws_server, new_cfg)

    event = json.loads(audit_log.read_text().strip())
    assert event["op"] == "auth"
    assert event["phase"] == "session"
    assert event["decision"] == "denied"
    assert event["error_class"] == "authentication_revoked"
    assert event["caller"] == "drop"
