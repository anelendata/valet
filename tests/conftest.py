import textwrap

import pytest

from valet.config import (
    BrokerConfig,
    ExecConfig,
    PolicyConfig,
    RedactionConfig,
)


@pytest.fixture
def secret_file(tmp_path):
    """A fake secret-values file with a long secret value and trivial ones."""
    p = tmp_path / "secret_values_test"
    p.write_text(textwrap.dedent(
        """\
        DB_PASSWORD=sup3r-s3cret-value-do-not-leak
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY
        STAGE=prod
        RETRIES=3
        """
    ))
    return p


@pytest.fixture
def workspace(tmp_path):
    d = tmp_path / "ws"
    d.mkdir()
    return d


@pytest.fixture
def cfg(workspace, secret_file):
    """A permissive broker config that redacts the fixture secret file."""
    return BrokerConfig(
        socket_path="/tmp/valet-test.sock",
        timeout_seconds=5,
        fingerprint_salt="test-salt-fixed",
        exec=ExecConfig(workspace=str(workspace), shell=True),
        redaction=RedactionConfig(
            secret_file_paths=(
                str(secret_file), "env_values_test", "secret_values_test",
            ),
            extra_values=(),
        ),
        policy=PolicyConfig(),
    )
