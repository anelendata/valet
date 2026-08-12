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


# ---- pruned recursive-glob expansion ----------------------------------------

def _ref_glob_files(pattern):
    """Reference: plain recursive glob, files only (what we must not under-match)."""
    from glob import glob
    return sorted(m for m in glob(pattern, recursive=True) if os.path.isfile(m))


def _build_plain_tree(base):
    """A tree with only non-hidden, non-pruned intermediate dirs."""
    (base / "top.txt").write_text("t")
    (base / "creds").mkdir()
    (base / "creds" / "a.txt").write_text("a")
    (base / "creds" / "sub").mkdir()
    (base / "creds" / "sub" / "b.txt").write_text("b")
    proj = base / "proj" / "x"
    (proj / "creds").mkdir(parents=True)
    (proj / "creds" / "c.txt").write_text("c")
    (proj / "x.env").write_text("e")


def test_pruned_expand_matches_glob_on_plain_tree(tmp_path):
    # With no hidden intermediate dirs and no pruned dirs, the pruned expander
    # must return EXACTLY what glob(recursive=True) returns — proving the
    # outer-recursion reimplementation preserves matching.
    from valet.secrets import _expand_source

    _build_plain_tree(tmp_path)
    for pat in [
        str(tmp_path / "**" / "creds" / "**"),
        str(tmp_path / "**" / "x.env"),
        str(tmp_path / "**"),
        str(tmp_path / "creds" / "**"),
    ]:
        assert sorted(_expand_source(pat)) == _ref_glob_files(pat), pat


def test_pruned_expand_skips_prune_dirs(tmp_path):
    from valet.secrets import _expand_source

    _build_plain_tree(tmp_path)
    leak = tmp_path / "node_modules" / "creds" / "leak.txt"
    leak.parent.mkdir(parents=True)
    leak.write_text("x")

    pat = str(tmp_path / "**" / "creds" / "**")
    got = sorted(_expand_source(pat))
    assert str(leak) in _ref_glob_files(pat)          # glob would crawl it
    assert str(leak) not in got                       # we prune node_modules
    assert set(got) == set(_ref_glob_files(pat)) - {str(leak)}


def test_pruned_expand_keeps_dir_named_in_pattern(tmp_path):
    # A dir in the prune set is NOT pruned when the pattern names it explicitly.
    from valet.secrets import _expand_source

    leak = tmp_path / "node_modules" / "creds" / "leak.txt"
    leak.parent.mkdir(parents=True)
    leak.write_text("x")

    pat = str(tmp_path / "**" / "node_modules" / "**")
    assert str(leak) in sorted(_expand_source(pat))


def test_pruned_expand_descends_hidden_intermediate_dirs(tmp_path):
    # glob's ** skips hidden dirs; our walk descends them, so a secret dir nested
    # under a hidden dir is caught (a safe superset of glob).
    from valet.secrets import _expand_source

    secret = tmp_path / ".config" / "app" / "creds" / "s.txt"
    secret.parent.mkdir(parents=True)
    secret.write_text("x")

    pat = str(tmp_path / "**" / "creds" / "**")
    assert str(secret) in sorted(_expand_source(pat))
    assert str(secret) not in _ref_glob_files(pat)    # glob misses it


def test_pruned_expand_matches_glob_on_random_trees(tmp_path):
    # Differential fuzz: on random trees with no hidden/pruned dirs, the pruned
    # expander must equal glob for several pattern shapes. Guards against a tree
    # depth/shape where the reimplemented recursion under- or over-matches.
    import random

    from valet.secrets import _expand_source

    rng = random.Random(1234)
    names = ["a", "b", "c", "d", "proj", "src", "note-com"]
    for t in range(25):
        root = tmp_path / f"t{t}"
        root.mkdir()
        # Grow a handful of random directories and drop files (some in `creds/`).
        dirs = [root]
        for _ in range(rng.randint(3, 12)):
            parent = rng.choice(dirs)
            child = parent / rng.choice(names)
            child.mkdir(exist_ok=True)
            dirs.append(child)
            if rng.random() < 0.5:
                (child / f"f{rng.randint(0, 4)}.txt").write_text("x")
            if rng.random() < 0.4:
                c = child / "creds"
                c.mkdir(exist_ok=True)
                (c / f"s{rng.randint(0, 3)}.txt").write_text("x")
                (c / "note.env").write_text("x")

        for pat in [
            str(root / "**" / "creds" / "**"),
            str(root / "**" / "note.env"),
            str(root / "**" / "*.txt"),
            str(root / "**"),
        ]:
            assert sorted(_expand_source(pat)) == _ref_glob_files(pat), (t, pat)


def _ref_glob_union(patterns):
    out = set()
    for p in patterns:
        out.update(_ref_glob_files(p))
    return sorted(out)


def test_expand_all_grouped_matches_glob_union_on_plain_tree(tmp_path):
    # The grouped single-walk fast path must return the same files as running
    # each pattern through glob separately (plain tree: no hidden/pruned dirs).
    from valet.secrets import _expand_all

    _build_plain_tree(tmp_path)
    sources = [
        str(tmp_path / "**" / "creds" / "**"),   # dir anchor
        str(tmp_path / "**" / "x.env"),          # file anchor
    ]
    assert sorted(_expand_all(sources)) == _ref_glob_union(sources)


def test_expand_all_grouped_prunes_and_dedupes(tmp_path):
    from valet.secrets import _expand_all

    _build_plain_tree(tmp_path)
    leak = tmp_path / "node_modules" / "creds" / "leak.txt"
    leak.parent.mkdir(parents=True)
    leak.write_text("x")
    # Overlapping patterns (creds dir anchor + a broad .txt file set) must not
    # double-count, and the pruned dir must be excluded from the dir-anchor walk.
    sources = [
        str(tmp_path / "**" / "creds" / "**"),
        str(tmp_path / "**" / "a.txt"),
    ]
    got = sorted(_expand_all(sources))
    assert got == sorted(set(got))                 # de-duped
    assert str(leak) not in got                    # node_modules pruned


def test_expand_all_grouped_matches_glob_union_on_random_trees(tmp_path):
    # Differential fuzz for the grouped path: many patterns, one walk == union of
    # per-pattern globs, across random shapes.
    import random

    from valet.secrets import _expand_all

    rng = random.Random(99)
    names = ["a", "b", "c", "proj", "src", "note-com"]
    for t in range(20):
        root = tmp_path / f"t{t}"
        root.mkdir()
        dirs = [root]
        for _ in range(rng.randint(3, 12)):
            parent = rng.choice(dirs)
            child = parent / rng.choice(names)
            child.mkdir(exist_ok=True)
            dirs.append(child)
            if rng.random() < 0.5:
                (child / f"f{rng.randint(0, 4)}.txt").write_text("x")
            if rng.random() < 0.4:
                c = child / "creds"
                c.mkdir(exist_ok=True)
                (c / f"s{rng.randint(0, 3)}.txt").write_text("x")
                (c / "note.env").write_text("x")

        sources = [
            str(root / "**" / "creds" / "**"),
            str(root / "**" / "note.env"),
        ]
        assert sorted(_expand_all(sources)) == _ref_glob_union(sources), (t, sources)
