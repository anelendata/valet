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


def test_backstop_masks_email_addresses():
    red = Redactor.build([], salt="s")
    text = "Contact alice.smith+alerts@example.co.uk or bob@example.com."
    out = red.redact(text)

    assert "alice.smith+alerts@example.co.uk" not in out
    assert "bob@example.com" not in out
    assert out == "Contact [REDACTED:email] or [REDACTED:email]."


def test_secret_file_paths_are_not_masked_only_their_contents():
    # A secret file's PATH is not itself secret (the agent can list it); masking
    # it is meaningless noise. Only the file's contents (a known value) are hidden.
    red = Redactor.build(["swy-session-tok-abcdef123456"], salt="s")
    out = red.redact(
        "updated ./projects/safeway/.secrets/swy_shared_session.txt "
        "token=swy-session-tok-abcdef123456"
    )
    assert "./projects/safeway/.secrets/swy_shared_session.txt" in out
    assert "secret_path" not in out and "env_path" not in out
    assert "swy-session-tok-abcdef123456" not in out


def test_home_aws_credential_path_is_still_de_identified():
    red = Redactor.build([], salt="s")
    out = red.redact("loaded /Users/alice/.aws/credentials profile default")
    assert "/Users/alice/.aws/credentials" not in out
    assert "[REDACTED:aws_path]" in out


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


def test_workspace_root_is_virtualized():
    red = Redactor.build([], salt="s", workspace_root="/Users/x/projects")
    # The root itself and paths beneath it collapse to the "./" virtual root.
    assert red.redact("/Users/x/projects") == "./"
    assert red.redact("cwd=/Users/x/projects\n") == "cwd=./\n"
    assert red.redact("/Users/x/projects/zendesk/files") == "./zendesk/files"


def test_workspace_root_virtualization_respects_boundaries():
    red = Redactor.build([], salt="s", workspace_root="/Users/x/projects")
    # A sibling that merely shares the prefix must not be rewritten.
    assert red.redact("/Users/x/projectsX") == "/Users/x/projectsX"
    assert red.redact("/Users/x/projects-old/a") == "/Users/x/projects-old/a"
    # A same-named dir under a different parent is left alone (lookbehind).
    assert red.redact("/other/Users/x/projects") == "/other/Users/x/projects"


def test_workspace_root_absent_leaves_paths_untouched():
    red = Redactor.build([], salt="s")
    assert red.redact("/Users/x/projects/a") == "/Users/x/projects/a"


def test_home_prefix_outside_workspace_becomes_tilde():
    red = Redactor.build(
        [], salt="s",
        workspace_root="/Users/x/anelen/projects",
        home_dir="/Users/x",
    )
    # A sibling of the workspace, under home but not under the workspace root.
    out = red.redact("/usr/local/bin/gcloud: /Users/x/projects/app/.venv/bin/gcloud: nope")
    assert "/Users/x" not in out
    assert "~/projects/app/.venv/bin/gcloud" in out


def test_home_prefix_bare_becomes_tilde():
    red = Redactor.build([], salt="s", workspace_root="/Users/x/ws", home_dir="/Users/x")
    assert red.redact("home is /Users/x here") == "home is ~ here"


def test_workspace_still_virtualized_when_home_redaction_on():
    red = Redactor.build([], salt="s", workspace_root="/Users/x/ws", home_dir="/Users/x")
    assert red.redact("/Users/x/ws/sub") == "./sub"


def test_home_redaction_off_without_home_dir():
    red = Redactor.build([], salt="s", workspace_root="/Users/x/ws")
    assert red.redact("/Users/x/projects/app") == "/Users/x/projects/app"


# ---- Aho-Corasick redaction backends (AHO_CORASICK) -------------------------

def _use_backend(monkeypatch, backend):
    from valet import sanitize
    monkeypatch.setattr(sanitize, "AHO_CORASICK", backend)
    sanitize._AC_PREP_CACHE.clear()


def _backends():
    """The matcher backends available in this environment (+ None = naive)."""
    from valet import sanitize
    from valet.multimatch import AhoCorasick, HAS_PYAHOCORASICK, PyAhoCorasick
    yield None
    yield AhoCorasick
    if HAS_PYAHOCORASICK:
        yield PyAhoCorasick


def test_all_backends_match_naive_on_non_overlapping_values(monkeypatch):
    import random

    from valet.multimatch import AhoCorasick

    rng = random.Random(7)
    # Distinct tokens, none a substring of another; fillers use letters that can
    # never contain a token ('tok' has no a-h chars), so matches don't overlap.
    vocab = [f"tok{i}z" for i in range(200)]
    for trial in range(60):
        parts = []
        for _ in range(rng.randint(4, 30)):
            if rng.random() < 0.4:
                parts.append(rng.choice(vocab))
            else:
                parts.append("".join(rng.choice("abcdefgh") for _ in range(rng.randint(1, 6))))
        text = " ".join(parts)
        red = Redactor.build(list(set(vocab)), salt="s", suspected=False, high_entropy=False)

        _use_backend(monkeypatch, None)
        naive_out = red.redact(text)
        for backend in _backends():
            if backend is None:
                continue
            _use_backend(monkeypatch, backend)
            assert red.redact(text) == naive_out, (trial, backend, text)
        assert red.is_clean(naive_out)


def test_backends_mask_all_secrets_even_when_overlapping(monkeypatch):
    for backend in _backends():
        if backend is None:
            continue
        _use_backend(monkeypatch, backend)
        red = Redactor.build(["abc", "cde", "bcd"], salt="s", suspected=False, high_entropy=False)
        out = red.redact("xx abcde yy")
        assert red.is_clean(out), backend
        for v in ("abc", "cde", "bcd"):
            assert v not in out


def test_backends_still_mask_long_values_via_naive(monkeypatch):
    from valet import sanitize

    long_secret = "L" + "0123456789" * 40  # > _AC_MAX_PATTERN_LEN (256)
    assert len(long_secret) > sanitize._AC_MAX_PATTERN_LEN
    for backend in _backends():
        if backend is None:
            continue
        _use_backend(monkeypatch, backend)
        red = Redactor.build([long_secret, "shorttok"], salt="s", suspected=False, high_entropy=False)
        out = red.redact(f"start {long_secret} mid shorttok end")
        assert long_secret not in out, backend
        assert "shorttok" not in out
        assert red.is_clean(out)
