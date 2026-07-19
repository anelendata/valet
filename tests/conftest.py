import textwrap

import pytest

from valet.config import BrokerConfig, Project


@pytest.fixture
def secret_file(tmp_path):
    """A fake .secrets file with a long secret value and a trivial one."""
    p = tmp_path / ".secrets"
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
def project(tmp_path, secret_file):
    proj_dir = tmp_path / "demo_billing"
    proj_dir.mkdir()
    return Project(
        alias="demo_billing",
        project_dir=str(proj_dir),
        workspace_dir=str(proj_dir / ".workspace"),
        aws_profile="demo-billing-prod",
        stages=("prod", "dev"),
        secret_sources=(str(secret_file),),
    )


@pytest.fixture
def cfg(project):
    return BrokerConfig(
        socket_path=str("/tmp/valet-test.sock"),
        handoff_bin="handoff",
        timeout_seconds=5,
        fingerprint_salt="test-salt-fixed",
        projects={project.alias: project},
    )
