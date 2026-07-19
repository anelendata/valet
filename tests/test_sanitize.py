"""Raw sensitive-looking strings are redacted."""
from valet.sanitize import Redactor, fingerprint
from valet.secrets import load_secret_values


def test_known_secret_value_is_redacted(secret_file):
    values = load_secret_values([str(secret_file)])
    red = Redactor.build(values, salt="s")
    leaky = "connecting with password sup3r-s3cret-value-do-not-leak now"
    out = red.redact(leaky)
    assert "sup3r-s3cret-value-do-not-leak" not in out
    assert "REDACTED:secret:" in out
    assert red.is_clean(out)


def test_trivial_values_not_loaded(secret_file):
    values = load_secret_values([str(secret_file)])
    # "3" (RETRIES) and "prod" (STAGE) must not become redaction targets.
    assert "3" not in values
    assert "prod" not in values


def test_backstop_masks_account_id_and_arn():
    red = Redactor.build([], salt="s")
    text = "arn:aws:events:us-east-1:123456789012:rule/foo and acct 123456789012"
    out = red.redact(text)
    assert "123456789012" not in out
    assert "[REDACTED:arn]" in out
    assert "[REDACTED:acct_id]" in out


def test_backstop_masks_access_key_id():
    red = Redactor.build([], salt="s")
    out = red.redact("key AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED" in out  # caught by the token/heuristic or backstop layer


def test_suspected_can_be_disabled():
    red = Redactor.build([], salt="s", suspected=False)
    out = red.redact("DB_PASSWORD=plaintextsecret")
    assert out == "DB_PASSWORD=plaintextsecret"  # heuristics off, nothing masked


def test_fingerprint_is_stable_and_opaque():
    a = fingerprint("my-task-rule", "salt")
    b = fingerprint("my-task-rule", "salt")
    c = fingerprint("my-task-rule", "different-salt")
    assert a == b            # stable → identity comparison works
    assert a != c            # salted
    assert "my-task-rule" not in a
    assert a.startswith("h:")


def test_is_clean_detects_residual_secret():
    red = Redactor.build(["topsecretvalue"], salt="s")
    assert red.is_clean("nothing here") is True
    assert red.is_clean("oops topsecretvalue") is False
