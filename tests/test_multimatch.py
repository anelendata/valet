"""Aho-Corasick multi-pattern matcher used by the redactor."""
import random

from valet.multimatch import AhoCorasick


def mark(s):
    return f"[{s}]"


def test_basic_matches():
    ac = AhoCorasick(["abc", "xyz"])
    assert ac.replace("1abc2xyz3", mark) == "1[abc]2[xyz]3"


def test_longest_pattern_ending_here_wins():
    ac = AhoCorasick(["abc", "abcd"])
    assert ac.replace("Xabcd", mark) == "X[abcd]"


def test_overlapping_matches_merge_into_one_span():
    ac = AhoCorasick(["abc", "cde"])   # overlap at 'c'
    assert ac.replace("abcde", mark) == "[abcde]"


def test_separated_matches_stay_distinct():
    ac = AhoCorasick(["ab"])
    assert ac.replace("ab cd ab", mark) == "[ab] cd [ab]"


def test_repeated_adjacent_matches():
    ac = AhoCorasick(["ab"])
    assert ac.replace("abab", mark) == "[ab][ab]"


def test_no_match_returns_text_unchanged():
    ac = AhoCorasick(["zzz"])
    assert ac.replace("hello world", mark) == "hello world"


def test_empty_automaton_is_identity():
    assert AhoCorasick([]).replace("hello", mark) == "hello"
    assert AhoCorasick(["", ""]).replace("hello", mark) == "hello"


def test_no_pattern_substring_survives():
    patterns = ["alpha", "beta", "gamma", "al", "mm"]
    ac = AhoCorasick(patterns)
    text = "xx alpha yy beta zz gamma qq alpha mm"
    out = ac.replace(text, lambda s: "#")
    for p in patterns:
        assert p not in out


def _brute_cover(text, patterns):
    """Reference: mark every index covered by any pattern occurrence."""
    covered = [False] * len(text)
    for p in patterns:
        if not p:
            continue
        start = text.find(p)
        while start != -1:
            for i in range(start, start + len(p)):
                covered[i] = True
            start = text.find(p, start + 1)
    return covered


def test_fuzz_covers_exactly_the_matched_positions():
    rng = random.Random(2024)
    alphabet = "abcde"
    for _ in range(300):
        patterns = list({
            "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))
            for _ in range(rng.randint(1, 6))
        })
        text = "".join(rng.choice(alphabet + "  ") for _ in range(rng.randint(0, 40)))
        ac = AhoCorasick(patterns)
        # Sentinel replacement: every covered char -> '#', uncovered untouched.
        out = ac.replace(text, lambda s: "#" * len(s))
        want_covered = _brute_cover(text, patterns)
        got = "".join(
            "#" if want_covered[i] else text[i] for i in range(len(text))
        )
        assert out == got, (patterns, text)


def test_pyahocorasick_matches_inhouse_backend():
    import random

    import pytest

    ahocorasick = pytest.importorskip("ahocorasick")  # noqa: F841
    from valet.multimatch import PyAhoCorasick

    rng = random.Random(2025)
    alphabet = "abcde"
    for _ in range(300):
        patterns = list({
            "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))
            for _ in range(rng.randint(1, 6))
        })
        text = "".join(rng.choice(alphabet + "  ") for _ in range(rng.randint(0, 40)))
        inhouse = AhoCorasick(patterns).replace(text, mark)
        cext = PyAhoCorasick(patterns).replace(text, mark)
        assert inhouse == cext, (patterns, text)


def test_pyahocorasick_raises_clearly_when_missing():
    import valet.multimatch as mm

    if mm.HAS_PYAHOCORASICK:
        import pytest
        pytest.skip("pyahocorasick is installed")
    import pytest
    with pytest.raises(RuntimeError, match="pyahocorasick is not installed"):
        mm.PyAhoCorasick(["x"])
