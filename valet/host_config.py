"""Edit host-side config for Level 1 client identities.

A client identity is a single ``[identity.clients.<id>]`` section whose ``<id>``
is the client id used for challenge-response auth. The id is the only
identifier — there is no separate display name, and no ``client-`` prefix is
added (the section already namespaces it under ``identity.clients``).
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClientKeyUpdate:
    client_id: str
    key: str
    existed: bool


@dataclass(frozen=True)
class ClientIdentityEntry:
    client_id: str
    has_key: bool


def generate_client_key() -> str:
    return secrets.token_urlsafe(32)


def normalize_client_id(raw: str) -> str:
    """Coerce a client id into a config-safe bare-key form.

    Spaces and other punctuation collapse to hyphens; the result is lowercased.
    Raises ``ValueError`` when nothing usable remains.
    """
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", raw.strip()).strip("-").lower()
    if not slug:
        raise ValueError("client id must contain at least one letter or digit")
    return slug


def find_client_identity(path: Path, client_id: str) -> str | None:
    text = path.read_text()
    normalized = normalize_client_id(client_id)
    existing_id, existed = _find_client_identity(text, normalized)
    return existing_id if existed else None


def list_client_identities(path: Path) -> list[ClientIdentityEntry]:
    text = path.read_text()
    entries = []
    for client_id, start, end in _identity_sections(text):
        body = text[start:end]
        entries.append(ClientIdentityEntry(
            client_id=client_id,
            has_key=bool(_read_string_value(body, "key")),
        ))
    return entries


def upsert_client_identity(
    path: Path,
    *,
    client_id: str,
    key: str | None = None,
) -> ClientKeyUpdate:
    text = path.read_text()
    normalized = normalize_client_id(client_id)
    _existing_id, existed = _find_client_identity(text, normalized)
    key = key or generate_client_key()
    updated = _replace_or_append_identity(text, client_id=normalized, key=key)
    path.write_text(updated)
    return ClientKeyUpdate(client_id=normalized, key=key, existed=existed)


def remove_client_identity(path: Path, client_id: str) -> ClientIdentityEntry | None:
    text = path.read_text()
    normalized = normalize_client_id(client_id)
    existing_id, existed = _find_client_identity(text, normalized)
    if not existed or existing_id is None:
        return None
    for section_id, start, end in _identity_sections(text):
        if section_id != existing_id:
            continue
        body = text[start:end]
        entry = ClientIdentityEntry(
            client_id=section_id,
            has_key=bool(_read_string_value(body, "key")),
        )
        updated = text[:start] + text[end:]
        updated = re.sub(r"\n{3,}", "\n\n", updated).rstrip() + "\n"
        path.write_text(updated)
        return entry
    return None


def client_config_snippet(
    update: ClientKeyUpdate,
    *,
    host_name: str,
    url: str,
    host_id: str,
) -> str:
    # host_id defaults to the section name on the client, so only emit it when
    # the section is labelled differently from the host's own id.
    host_id_line = (
        f'host_id = "{_toml_escape(host_id)}"\n' if host_id and host_id != host_name else ""
    )
    return (
        "[client]\n"
        f'id = "{_toml_escape(update.client_id)}"\n'
        f'key = "{_toml_escape(update.key)}"\n'
        f'default_host = "{_toml_escape(host_name)}"\n'
        "reconnect_max_retries = 5\n"
        "reconnect_backoff_seconds = 0.25\n"
        "reconnect_backoff_max_seconds = 3.0\n"
        "\n"
        f"[hosts.{_toml_key(host_name)}]\n"
        f'url = "{_toml_escape(url)}"\n'
        f"{host_id_line}"
    )


def _find_client_identity(text: str, client_id: str) -> tuple[str | None, bool]:
    for section_id, start, end in _identity_sections(text):
        if section_id == client_id:
            return section_id, True
    return None, False


def _replace_or_append_identity(text: str, *, client_id: str, key: str) -> str:
    section = _identity_section(client_id, key)
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


def _identity_section(client_id: str, key: str) -> str:
    return (
        f"[identity.clients.{_toml_key(client_id)}]\n"
        f'key = "{_toml_escape(key)}"\n'
    )


def _read_string_value(text: str, key: str) -> str | None:
    match = re.search(rf'(?m)^\s*{re.escape(key)}\s*=\s*"((?:[^"\\]|\\.)*)"\s*$', text)
    if not match:
        return None
    return bytes(match.group(1), "utf-8").decode("unicode_escape")


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
