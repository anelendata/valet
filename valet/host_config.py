"""Edit host-side config for Level 1 client identities."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClientKeyUpdate:
    client_id: str
    name: str
    key: str
    existed: bool


def generate_client_key() -> str:
    return secrets.token_urlsafe(32)


def find_client_identity(path: Path, name: str) -> str | None:
    text = path.read_text()
    client_id, existed = _find_client_identity(text, name)
    return client_id if existed else None


def upsert_client_identity(
    path: Path,
    *,
    name: str,
    key: str | None = None,
) -> ClientKeyUpdate:
    text = path.read_text()
    client_id, existed = _find_client_identity(text, name)
    if client_id is None:
        client_id = _client_id_for_name(name)
    key = key or generate_client_key()
    updated = _replace_or_append_identity(text, client_id=client_id, name=name, key=key)
    path.write_text(updated)
    return ClientKeyUpdate(client_id=client_id, name=name, key=key, existed=existed)


def client_config_snippet(
    update: ClientKeyUpdate,
    *,
    host_name: str,
    url: str,
    host_id: str,
) -> str:
    return (
        "[client]\n"
        f'id = "{_toml_escape(update.client_id)}"\n'
        f'key = "{_toml_escape(update.key)}"\n'
        f'default_host = "{_toml_escape(host_name)}"\n'
        "\n"
        f"[hosts.{_toml_key(host_name)}]\n"
        f'url = "{_toml_escape(url)}"\n'
        f'host_id = "{_toml_escape(host_id)}"\n'
    )


def _find_client_identity(text: str, name: str) -> tuple[str | None, bool]:
    for client_id, start, end in _identity_sections(text):
        body = text[start:end]
        configured_name = _read_string_value(body, "name")
        if client_id == name or configured_name == name:
            return client_id, True
    return None, False


def _replace_or_append_identity(text: str, *, client_id: str, name: str, key: str) -> str:
    section = _identity_section(client_id, name, key)
    for existing_id, start, end in _identity_sections(text):
        if existing_id == client_id:
            return text[:start] + section + text[end:]
    separator = "" if text.endswith("\n") else "\n"
    return text + separator + "\n" + section


def _identity_sections(text: str) -> list[tuple[str, int, int]]:
    header_re = re.compile(r"(?m)^\[identity\.clients\.([^\]]+)\]\s*$")
    any_header_re = re.compile(r"(?m)^\[[^\]]+\]\s*$")
    sections = []
    for match in header_re.finditer(text):
        next_header = any_header_re.search(text, match.end())
        end = next_header.start() if next_header else len(text)
        sections.append((_unquote_toml_key(match.group(1).strip()), match.start(), end))
    return sections


def _identity_section(client_id: str, name: str, key: str) -> str:
    return (
        f"[identity.clients.{_toml_key(client_id)}]\n"
        f'name = "{_toml_escape(name)}"\n'
        f'key = "{_toml_escape(key)}"\n'
    )


def _read_string_value(text: str, key: str) -> str | None:
    match = re.search(rf'(?m)^\s*{re.escape(key)}\s*=\s*"((?:[^"\\]|\\.)*)"\s*$', text)
    if not match:
        return None
    return bytes(match.group(1), "utf-8").decode("unicode_escape")


def _client_id_for_name(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name.strip()).strip("-").lower()
    return "client-" + (slug or secrets.token_hex(4))


def _toml_key(value: str) -> str:
    if re.match(r"^[A-Za-z0-9_-]+$", value):
        return value
    return '"' + _toml_escape(value) + '"'


def _unquote_toml_key(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return bytes(value[1:-1], "utf-8").decode("unicode_escape")
    return value


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
