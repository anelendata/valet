"""Secret-value extraction, including YAML sources."""
from valet.secrets import _from_yaml, _parse_text, load_secret_values


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
