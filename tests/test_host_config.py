import dataclasses

from valet.broker import Broker
from valet.cli import main
from valet.config import ClientIdentity, IdentityConfig, load_config
from valet.server_host import _apply_reloaded_config


def _config(path):
    path.write_text(
        "[broker]\n"
        'fingerprint_salt = "test-salt"\n'
        "\n"
        "[host]\n"
        'id = "test-host"\n'
        'listen = "0.0.0.0:8766"\n'
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


def test_clients_add_updates_host_config(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)

    rc = main(["-c", str(path), "clients", "add", "local box"])

    assert rc == 0
    cfg = load_config(path)
    assert "client-local-box" in cfg.identity.clients
    assert cfg.identity.clients["client-local-box"].name == "local box"
    assert cfg.identity.clients["client-local-box"].key
    out = capsys.readouterr().out
    assert 'id = "client-local-box"' in out
    assert 'host_id = "test-host"' in out
    assert 'url = "ws://<host-lan-ip>:8766/rpc"' in out


def test_clients_add_rotates_existing_with_yes(tmp_path):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    first = load_config(path).identity.clients["client-local-box"].key

    assert main(["-c", str(path), "clients", "add", "local box", "--yes"]) == 0
    second = load_config(path).identity.clients["client-local-box"].key

    assert second
    assert second != first


def test_clients_add_existing_requires_confirmation(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    first = load_config(path).identity.clients["client-local-box"].key
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    rc = main(["-c", str(path), "clients", "add", "local box"])
    second = load_config(path).identity.clients["client-local-box"].key

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
    assert "client-local-box" in out
    assert "name=local box" in out
    assert "key=set" in out
    assert load_config(path).identity.clients["client-local-box"].key not in out


def test_clients_remove_deletes_approved_client(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)
    assert main(["-c", str(path), "clients", "add", "local box"]) == 0
    capsys.readouterr()

    rc = main(["-c", str(path), "clients", "remove", "local box"])

    assert rc == 0
    assert "client-local-box" not in load_config(path).identity.clients
    out = capsys.readouterr().out
    assert "removed client" in out
    assert "client-local-box" in out


def test_clients_remove_missing_client_reports_not_found(tmp_path, capsys):
    path = tmp_path / "config.toml"
    _config(path)

    rc = main(["-c", str(path), "clients", "remove", "missing"])

    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_reloaded_config_updates_broker_and_websocket_server_state(cfg):
    class WsServer:
        pass

    broker = Broker(cfg, audit_to_console=False)
    ws_server = WsServer()
    ws_server.cfg = cfg
    new_cfg = dataclasses.replace(
        cfg,
        policy=dataclasses.replace(cfg.policy, deny=("echo",)),
        identity=IdentityConfig(
            clients={"new-client": ClientIdentity(name="new", key="new-key")}
        ),
    )

    _apply_reloaded_config(broker, ws_server, new_cfg)

    resp = broker.handle({"op": "exec", "cmd": "echo hi"})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert ws_server.cfg.identity.clients["new-client"].key == "new-key"
