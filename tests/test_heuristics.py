"""Heuristic redaction: mask values that look secret without knowing them."""
from valet.heuristics import (
    key_is_sensitive,
    redact_high_entropy,
    redact_suspected,
)


def test_sensitive_key_names():
    for k in ("AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "api_key",
              "CLIENT_SECRET", "auth_token", "REFRESH_TOKEN"):
        assert key_is_sensitive(k), k


def test_non_sensitive_key_names():
    for k in ("AWS_PROFILE", "region", "client_id", "STAGE", "timeout", "monkey"):
        assert not key_is_sensitive(k), k


def test_env_assignment_masks_only_sensitive_value():
    out = redact_suspected("export AWS_PROFILE=tiny; export DB_PASSWORD=hunter2secret")
    assert "AWS_PROFILE=tiny" in out          # non-secret kept
    assert "hunter2secret" not in out         # secret masked
    assert "DB_PASSWORD=[REDACTED:suspected]" in out


def test_key_value_dump_masks_values():
    # Format emitted by `handoff secrets print` (YAML list of {key, value}).
    text = (
        "secrets:\n"
        "- key: DB_PASSWORD\n"
        "  level: task\n"
        "  value: sup3r-s3cret-runtime\n"
    )
    out = redact_suspected(text)
    assert "sup3r-s3cret-runtime" not in out
    assert "value: [REDACTED:suspected]" in out
    assert "key: DB_PASSWORD" in out          # the name stays visible


def test_key_value_dump_masks_wrapped_value_continuations():
    text = (
        "- key: google_client_secret\n"
        "  level: resource group\n"
        "  value: \"{\\n  \\\"private_key_id\\\": "
        "\\\"1afbedbd65fedc34591eac1a79a9de2aff1aefe64\\\"\\\n"
        "    ,\\n  \\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----abc\\\"\"\n"
        "  updated_at: 2026-08-03\n"
    )
    out = redact_suspected(text)
    assert "1afbedbd65fedc34591eac1a79a9de2aff1aefe64" not in out
    assert "PRIVATE KEY" not in out
    assert "value: [REDACTED:suspected]" in out
    assert "updated_at: 2026-08-03" in out


def test_colon_and_json_forms():
    assert "myplainpw" not in redact_suspected("password: myplainpw")
    assert "s3cr3ttoken" not in redact_suspected('  "api_key": "s3cr3ttoken",')


def test_known_token_shapes():
    for tok in (
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "xoxb-123456789012-abcdefghijkl",
        "AKIAIOSFODNN7EXAMPLE",
    ):
        out = redact_suspected(f"here is {tok} ok")
        assert tok not in out
        assert "[REDACTED" in out


def test_json_all_shapes_redacted_and_valid():
    import json

    cases = [
        '{\n  "AWS_PROFILE": "tiny",\n  "db_password": "hunter2secret",\n'
        '  "port": 5432,\n  "nested": { "client_secret": "shhhh-nested" }\n}',
        '{"db_password": "hunter2secret", "region": "us-east-1", "token": "abc123def456"}',
        '{"password":"nowhitespacesecret"}',
        '{"api_key": 1234567890}',
        '[{"name":"a","secret":"leakme1"},{"name":"b","secret":"leakme2"}]',
    ]
    leaks = ["hunter2secret", "shhhh-nested", "abc123def456",
             "nowhitespacesecret", "1234567890", "leakme1", "leakme2"]
    for src in cases:
        out = redact_suspected(src)
        for s in leaks:
            assert s not in out, (src, s)
        json.loads(out)  # must remain valid JSON


def test_json_keeps_non_sensitive_values():
    out = redact_suspected('{"region": "us-east-1", "port": 5432}')
    assert "us-east-1" in out and "5432" in out


def test_non_secret_output_untouched():
    text = "total 24\ndrwxr-xr-x 3 user staff 96 Jul 19 file.txt\nregion: us-east-1"
    assert redact_suspected(text) == text


# --- opt-in high-entropy scan ------------------------------------------------

def test_high_entropy_masks_bare_unknown_secrets():
    for s in ("xK9mQ2vL8pR4tZ7wN3jF6dH1sB5cY0a",
              "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
              "hunter2-super-secret-password"):
        out = redact_high_entropy(s)
        assert s not in out
        assert "high-entropy" in out


def test_high_entropy_keeps_hashes_uuids_and_numbers():
    for s in ("9f2c1ab3de4567890abcdef1234567890abcdef12",  # git sha (hex)
              "550e8400-e29b-41d4-a716-446655440000",       # uuid
              "12345678901234567890",                       # decimal id
              "abc123"):                                    # too short
        assert redact_high_entropy(s) == s


def test_high_entropy_keeps_non_sensitive_lowercase_slugs():
    text = "handoff-etl-saasoptics-tiny-rest-so-tiny-1"
    assert redact_high_entropy(text) == text


def test_high_entropy_masks_sensitive_lowercase_slugs():
    text = "hunter2-super-secret-password"
    assert redact_high_entropy(text) == "[REDACTED:high-entropy]"


def test_high_entropy_masks_mid_line():
    out = redact_high_entropy("deploy id xK9mQ2vL8pR4tZ7wN3jF6dH1sB5cY0a done")
    assert "xK9mQ2vL8pR4tZ7wN3jF6dH1sB5cY0a" not in out
    assert out.startswith("deploy id ") and out.endswith(" done")


def test_high_entropy_leaves_paths_alone():
    # Paths contain '/', excluded from the candidate alphabet.
    text = "/usr/local/lib/python3.11/site-packages/somepackage/module.py"
    assert redact_high_entropy(text) == text
