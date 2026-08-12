"""Secret-value extraction, including YAML sources."""
import os

from valet.secrets import (
    SecretIndex,
    _from_yaml,
    _parse_text,
    load_secret_values,
)


def test_yaml_suffix_extracts_scalar_leaves():
    text = (
        "db_password: sup3r-secret-value\n"
        "api:\n"
        "  token: tok_live_abcdef123456\n"
        "  retries: 3\n"
    )
    values = _parse_text("creds.yaml", ".yaml", text)
    assert "sup3r-secret-value" in values
    assert "tok_live_abcdef123456" in values
    assert "3" in values  # numbers are stringified like JSON


def test_yml_suffix_is_also_yaml():
    values = _parse_text("creds.yml", ".yml", "token: abcdef-ghijkl-secret\n")
    assert "abcdef-ghijkl-secret" in values


def test_secrets_file_is_parsed_as_yaml():
    # A `.secrets` file has no fixed format and is frequently YAML.
    text = "services:\n  - name: db\n    password: nested-list-secret\n"
    values = _parse_text(".secrets", "", text)
    assert "nested-list-secret" in values


def test_yaml_bools_and_null_are_not_values():
    values = list(_from_yaml("enabled: true\nmissing: null\nname: prod\n"))
    assert "True" not in values
    assert "None" not in values


def test_yaml_multiple_documents():
    text = "token: first-doc-secret\n---\ntoken: second-doc-secret\n"
    values = list(_from_yaml(text))
    assert "first-doc-secret" in values
    assert "second-doc-secret" in values


def test_malformed_yaml_never_raises():
    # Unbalanced brackets — PyYAML raises internally; we must return nothing.
    assert list(_from_yaml("key: [unclosed\n")) == []


def test_load_secret_values_masks_yaml_value(tmp_path):
    src = tmp_path / "creds.yaml"
    src.write_text("api_token: yaml-loaded-secret-value\n")
    values = load_secret_values([str(src)])
    assert "yaml-loaded-secret-value" in values


def test_load_secret_values_expands_directory_recursively(tmp_path):
    # A directory source loads every file beneath it — this is what lets a
    # *directory* of secrets (e.g. `.secrets/`) be redacted, not just a file
    # literally named `.secrets`.
    d = tmp_path / "secretdir"
    (d / "nested").mkdir(parents=True)
    (d / "session.txt").write_text("swy-session-9f83ab21c4d5e6f7a8b90\n")
    (d / "nested" / "extra.env").write_text("API_KEY=abcd1234efgh5678ijkl9012\n")

    values = load_secret_values([str(d)])

    assert "swy-session-9f83ab21c4d5e6f7a8b90" in values
    assert "abcd1234efgh5678ijkl9012" in values


def test_load_secret_values_expands_recursive_glob(tmp_path):
    d = tmp_path / "secretdir"
    (d / "nested").mkdir(parents=True)
    (d / "nested" / "deep.txt").write_text("token-value-deep-abcdef123456\n")

    values = load_secret_values([str(d / "**")])

    assert "token-value-deep-abcdef123456" in values


def test_load_secret_values_shallow_glob_skips_nested(tmp_path):
    d = tmp_path / "secretdir"
    (d / "nested").mkdir(parents=True)
    (d / "top.txt").write_text("top-secret-value-abcdef123456\n")
    (d / "nested" / "deep.txt").write_text("deep-secret-value-abcdef123456\n")

    values = load_secret_values([str(d / "*")])

    assert "top-secret-value-abcdef123456" in values
    assert "deep-secret-value-abcdef123456" not in values


def test_recursive_glob_matches_nested_secret_dir(tmp_path):
    # Regression: a secret dir nested under the workspace (e.g.
    # skills/foo/.secrets/) must be covered. A bare "dir/**" only matches at the
    # top level, which previously let a nested secret leak; a "**/"-prefixed
    # pattern matches the dir at any depth. (Uses a generic dir name so it runs
    # under sandboxes that deny creating literal `.secrets`.)
    top = tmp_path / "creds"
    nested = tmp_path / "skills" / "foo" / "creds"
    top.mkdir(parents=True)
    nested.mkdir(parents=True)
    (top / "top.txt").write_text("top-secret-abcdef123456\n")
    (nested / "session.txt").write_text("nested-secret-abcdef123456\n")

    shallow = load_secret_values([str(tmp_path / "creds" / "**")])
    assert "top-secret-abcdef123456" in shallow
    assert "nested-secret-abcdef123456" not in shallow          # the footgun

    recursive = load_secret_values([str(tmp_path / "**" / "creds" / "**")])
    assert "top-secret-abcdef123456" in recursive
    assert "nested-secret-abcdef123456" in recursive            # now covered


def test_example_config_relative_secret_paths_are_recursive():
    # Guard the shipped default: every RELATIVE secret_file_paths entry must be
    # "**/"-prefixed so nested secret dirs are covered. Absolute / ~-rooted
    # patterns are exempt (they match the filesystem directly).
    import tomllib

    from valet.cli import _example_config_path

    raw = tomllib.loads(_example_config_path().read_text())
    paths = raw["redaction"]["secret_file_paths"]
    relative = [p for p in paths if not (os.path.isabs(p) or p.startswith("~"))]
    assert relative, "expected some relative secret_file_paths in the example"
    offenders = [p for p in relative if not p.startswith("**/")]
    assert not offenders, (
        f"relative secret_file_paths must start with '**/' to cover nested "
        f"secret dirs; offenders: {offenders}"
    )


def test_load_secret_values_tolerates_missing_source(tmp_path):
    assert load_secret_values([str(tmp_path / "does-not-exist.txt")]) == []


# ---- SecretIndex cache ------------------------------------------------------

def test_secret_index_matches_load_secret_values(tmp_path):
    d = tmp_path / "creds"
    d.mkdir()
    (d / "a.txt").write_text("secret-value-abcdef123456\n")
    sources = [str(d / "**")]

    idx = SecretIndex()
    assert idx.values_for(sources) == load_secret_values(sources)


def test_secret_index_reuses_scan_until_a_file_changes(tmp_path, monkeypatch):
    d = tmp_path / "creds"
    d.mkdir()
    f = d / "a.txt"
    f.write_text("secret-value-abcdef123456\n")
    sources = [str(d / "**")]

    idx = SecretIndex(ttl_seconds=999)  # never rebuild on TTL; only on change

    # Force a cache hit path by counting scans.
    import valet.secrets as secrets_mod
    calls = {"n": 0}
    real_expand = secrets_mod._expand_all

    def counting_expand(srcs):
        calls["n"] += 1
        return real_expand(srcs)

    monkeypatch.setattr(secrets_mod, "_expand_all", counting_expand)

    first = idx.values_for(sources)
    assert "secret-value-abcdef123456" in first
    assert calls["n"] == 1

    # Second call with nothing changed -> served from cache, no rescan.
    idx.values_for(sources)
    assert calls["n"] == 1

    # Editing an indexed file invalidates immediately, even under a huge TTL.
    f.write_text("new-secret-value-zyxwvu987654\n")
    updated = idx.values_for(sources)
    assert "new-secret-value-zyxwvu987654" in updated
    assert "secret-value-abcdef123456" not in updated
    assert calls["n"] == 2


def test_secret_index_ttl_picks_up_a_brand_new_file(tmp_path):
    d = tmp_path / "creds"
    d.mkdir()
    (d / "a.txt").write_text("first-secret-abcdef123456\n")
    sources = [str(d / "**")]

    idx = SecretIndex(ttl_seconds=0)  # always past TTL -> always rescans
    assert "first-secret-abcdef123456" in idx.values_for(sources)

    # A file added later is not tracked by the previous entry's stamps, so only
    # the TTL rebuild finds it; ttl=0 forces that on the next call.
    (d / "b.txt").write_text("second-secret-zyxwvu987654\n")
    later = idx.values_for(sources)
    assert "first-secret-abcdef123456" in later
    assert "second-secret-zyxwvu987654" in later
