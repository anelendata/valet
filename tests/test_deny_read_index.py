"""Files matching policy.deny_read are excluded from the redaction index.

A file a command may not read can never reach the agent through valet, so there
is nothing to redact from it — and indexing it would over-mask from its
non-secret contents (a `.har` capture's URLs, hostnames, timestamps). A sibling
secret file that is *not* denied stays indexed.
"""
from valet.broker import Broker
from valet.config import BrokerConfig, ExecConfig, PolicyConfig, RedactionConfig
from valet.secrets import SecretIndex

HAR_TOKEN = "tok-abcdef123456"
HAR_WORD = "substack"
OTHER_SECRET = "realsecret-zyxwvu987654"


def _setup(tmp_path):
    d = tmp_path / "skills" / "note-com" / "sec"
    d.mkdir(parents=True)
    (d / "cap.har").write_text(
        '{"host": "%s", "cookie": "%s"}\n' % (HAR_WORD, HAR_TOKEN)
    )
    (d / "creds.txt").write_text(OTHER_SECRET + "\n")
    return d


def _redactor(tmp_path, deny):
    cfg = BrokerConfig(
        socket_path="/tmp/valet-test.sock",
        timeout_seconds=5,
        fingerprint_salt="s",
        exec=ExecConfig(workspace=str(tmp_path), shell=True),
        redaction=RedactionConfig(secret_file_paths=("**/sec/**",), extra_values=()),
        policy=PolicyConfig(deny_read=deny),
    )
    broker = Broker(cfg)
    ws = broker.workspaces[broker.default_workspace]
    return ws.redactor_for(ws.root())


def _masked(r, s):
    return s not in r.redact(f"x {s} y")


def test_har_indexed_when_not_denied(tmp_path):
    _setup(tmp_path)
    r = _redactor(tmp_path, ())
    assert _masked(r, HAR_TOKEN)          # its leaves are indexed
    assert _masked(r, HAR_WORD)           # ...including the over-masking noise
    assert _masked(r, OTHER_SECRET)


def test_deny_read_file_excluded_from_index(tmp_path):
    _setup(tmp_path)
    r = _redactor(tmp_path, ("**/*.har",))
    # the .har is blocked from reading, so it is not indexed at all:
    assert not _masked(r, HAR_TOKEN)
    assert not _masked(r, HAR_WORD)       # no more over-masking of 'substack'
    # a sibling secret file that is NOT denied is still indexed:
    assert _masked(r, OTHER_SECRET)


def test_deny_globs_are_part_of_the_cache_key(tmp_path):
    _setup(tmp_path)
    idx = SecretIndex()
    sources = [str(tmp_path / "**" / "sec" / "**")]
    with_har = set(idx.values_for(sources))
    without_har = set(idx.values_for(sources, ("**/*.har",)))
    assert HAR_TOKEN in with_har
    assert HAR_TOKEN not in without_har           # different key -> re-scanned
    assert OTHER_SECRET in with_har and OTHER_SECRET in without_har
