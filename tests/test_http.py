import dataclasses
import json

import pytest

from valet.broker import Broker
from valet.config import HttpConfig, load_config
from valet.errors import ConfigError
from valet.server_http import handle_post, make_server


@pytest.fixture
def http_cfg(cfg):
    http = HttpConfig(host="127.0.0.1", port=0, bearer_token="test-http-token")
    return dataclasses.replace(cfg, http=http)


def _post(cfg, payload, token="test-http-token"):
    return handle_post(
        Broker(cfg),
        cfg.http.bearer_token,
        "/call",
        f"Bearer {token}",
        json.dumps(payload).encode("utf-8"),
    )


def test_http_adapter_handles_broker_request(http_cfg):
    status, body, _headers = _post(http_cfg, {"op": "ping"})
    assert status == 200
    assert body["ok"] is True
    assert body["pong"] is True


def test_http_adapter_requires_bearer_token(http_cfg):
    status, body, headers = _post(http_cfg, {"op": "ping"}, token="wrong-token")
    assert status == 401
    assert body["ok"] is False
    assert body["error_class"] == "Unauthorized"
    assert headers["WWW-Authenticate"] == 'Bearer realm="valet"'


def test_http_adapter_rejects_bad_json(http_cfg):
    status, body, _headers = handle_post(
        Broker(http_cfg),
        http_cfg.http.bearer_token,
        "/call",
        "Bearer test-http-token",
        b"{not-json",
    )
    assert status == 200
    assert body["ok"] is False
    assert body["error_class"] == "ValidationError"


def test_http_adapter_requires_configured_token(cfg):
    c = dataclasses.replace(cfg, http=HttpConfig(host="127.0.0.1", port=0))
    with pytest.raises(ConfigError):
        make_server(c)


def test_http_config_defaults_to_loopback(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("[broker]\nfingerprint_salt = 'fixed-test-salt'\n")
    cfg = load_config(path)
    assert cfg.http.host == "127.0.0.1"
    assert cfg.http.port == 8765


def test_http_config_can_override_host(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        "[broker]\nfingerprint_salt = 'fixed-test-salt'\n\n"
        "[http]\nhost = '0.0.0.0'\nport = 8877\nbearer_token = 'token'\n"
    )
    cfg = load_config(path)
    assert cfg.http.host == "0.0.0.0"
    assert cfg.http.port == 8877
    assert cfg.http.bearer_token == "token"
