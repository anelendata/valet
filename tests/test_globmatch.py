"""Shared glob matcher used by policy (deny_read) and secrets (index exclusion)."""
from valet.globmatch import path_matches_globs


def test_recursive_prefix_matches_any_depth():
    assert path_matches_globs("/ws/a/b/cap.har", ["**/*.har"])
    assert path_matches_globs("/ws/x/.env", ["**/.env"])
    assert path_matches_globs("/ws/skills/foo/.secrets/tok", ["**/.secrets/**"])


def test_non_matching_paths():
    assert not path_matches_globs("/ws/a/b/notes.txt", ["**/*.har"])
    assert not path_matches_globs("/ws/a/b/env.txt", ["**/.env"])


def test_absolute_pattern():
    assert path_matches_globs("/home/u/.aws/credentials", ["/home/u/.aws/**"])
    assert not path_matches_globs("/home/u/.config/x", ["/home/u/.aws/**"])


def test_no_recursive_prefix_does_not_match_at_depth():
    # Paths are made absolute before matching, so `*.har` (no `**/`) never
    # matches a real file — you need the `**/` prefix. This is why the config
    # examples all use `**/*.har`.
    assert not path_matches_globs("/ws/a/cap.har", ["*.har"])


def test_empty_patterns_never_match():
    assert not path_matches_globs("/ws/a/cap.har", [])
