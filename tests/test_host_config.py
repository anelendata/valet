from valet.cli import main
from valet.config import load_config


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

    def fake_serve_host(cfg):
        called["cfg"] = cfg

    monkeypatch.setattr("valet.cli.serve_host", fake_serve_host)

    assert main(["-c", str(path), "serve"]) == 0
    assert called["cfg"].host.lan is True


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
