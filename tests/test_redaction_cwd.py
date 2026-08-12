"""Relative secret_file_paths cover the whole workspace regardless of a command's
cwd — including when the command runs INSIDE the secret directory.

Regression: relative patterns used to resolve against the command's cwd, so
`cd`-ing into a `.config`/`.secrets` dir put the anchor ABOVE cwd, `**/.config/**`
matched nothing, and the file's value was never loaded -> the secret leaked.
"""
from valet.broker import Broker
from valet.config import BrokerConfig, ExecConfig, PolicyConfig, RedactionConfig


def _broker(workspace):
    return Broker(BrokerConfig(
        socket_path="/tmp/valet-test.sock",
        timeout_seconds=5,
        fingerprint_salt="s",
        exec=ExecConfig(workspace=str(workspace), shell=True),
        redaction=RedactionConfig(secret_file_paths=("**/creds/**",), extra_values=()),
        policy=PolicyConfig(),
    ))


def test_secret_masked_regardless_of_cwd(tmp_path):
    secret_dir = tmp_path / "skills" / "note-com" / "creds"
    secret_dir.mkdir(parents=True)
    hexval = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    (secret_dir / "session.txt").write_text(hexval + "\n")

    broker = _broker(tmp_path)
    ws = broker.workspaces[broker.default_workspace]
    root = ws.root()

    cwds = [
        root,                                            # at the workspace root
        str(secret_dir),                                 # INSIDE the secret dir
        str(tmp_path / "skills"),                         # a sibling subtree
        None,                                            # no cwd -> workspace root
    ]
    for cwd in cwds:
        r = ws.redactor_for(cwd)
        assert hexval in r.secret_values, f"not loaded for cwd={cwd}"
        assert hexval not in r.redact(f"x {hexval} y"), f"not masked for cwd={cwd}"
