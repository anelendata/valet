"""Edit host-side ``[workspaces.<id>]`` sections in config.toml.

A workspace is a named directory the agent's commands are confined to. The host
admin manages them with ``valet workspaces add`` / ``valet workspaces list``,
which read and rewrite the config text directly so comments and unrelated
sections are preserved.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspaceEntry:
    workspace_id: str
    path: str
    is_default: bool


@dataclass(frozen=True)
class WorkspaceAdd:
    workspace_id: str
    path: str
    made_default: bool


@dataclass(frozen=True)
class WorkspaceRemove:
    workspace_id: str
    path: str
    was_default: bool
    remaining: int


def normalize_workspace_id(raw: str) -> str:
    """Coerce a workspace id into a config-safe bare-key form.

    Spaces and other punctuation collapse to hyphens; the result is lowercased.
    Raises ``ValueError`` when nothing usable remains.
    """
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", raw.strip()).strip("-").lower()
    if not slug:
        raise ValueError("workspace id must contain at least one letter or digit")
    return slug


def find_workspace(path: Path, workspace_id: str) -> WorkspaceEntry | None:
    normalized = normalize_workspace_id(workspace_id)
    for entry in list_workspaces(path):
        if entry.workspace_id == normalized:
            return entry
    return None


def list_workspaces(path: Path) -> list[WorkspaceEntry]:
    text = path.read_text()
    default_id = _read_default_workspace(text)
    entries = []
    for wid, start, end in _workspace_sections(text):
        body = text[start:end]
        entries.append(WorkspaceEntry(
            workspace_id=wid,
            path=_read_string_value(body, "path") or "",
            is_default=(wid == default_id),
        ))
    return entries


def add_workspace(
    path: Path,
    *,
    workspace_id: str,
    workspace_path: str,
    make_default: bool = False,
) -> WorkspaceAdd:
    """Add (or replace) a ``[workspaces.<id>]`` section.

    The added workspace becomes ``[exec].default_workspace`` when ``make_default``
    is set, or when it is the first workspace in the config (so a fresh
    single-workspace config keeps working without extra edits). ``make_default``
    replaces any existing default.
    """
    text = path.read_text()
    normalized = normalize_workspace_id(workspace_id)
    had_workspaces = bool(_workspace_sections(text))
    section = _workspace_section(normalized, workspace_path)

    replaced = False
    for wid, start, end in _workspace_sections(text):
        if wid == normalized:
            text = text[:start] + section + text[end:]
            replaced = True
            break
    if not replaced:
        separator = "" if text.endswith("\n") else "\n"
        text = text + separator + "\n" + section

    # First-ever workspace always becomes the default; otherwise only on request.
    should_default = make_default or not had_workspaces
    made_default = False
    if should_default and _read_default_workspace(text) != normalized:
        text = _set_default_workspace(text, normalized)
        made_default = True

    path.write_text(text)
    return WorkspaceAdd(
        workspace_id=normalized, path=workspace_path, made_default=made_default
    )


def remove_workspace(path: Path, workspace_id: str) -> WorkspaceRemove | None:
    """Delete a ``[workspaces.<id>]`` section (and its sub-tables) from the config.

    The workspace *directory on disk is left untouched* — only the config entry is
    removed. If the removed workspace was the default, the ``default_workspace``
    pointer is cleared too. Returns the removed entry, or None if not found.
    """
    text = path.read_text()
    normalized = normalize_workspace_id(workspace_id)
    default_id = _read_default_workspace(text)
    for wid, start, end in _workspace_sections(text):
        if wid != normalized:
            continue
        ws_path = _read_string_value(text[start:end], "path") or ""
        was_default = wid == default_id
        updated = text[:start] + text[end:]
        if was_default:
            updated = re.sub(
                r"(?m)^[ \t]*default_workspace[ \t]*=.*\n?", "", updated, count=1)
        updated = re.sub(r"\n{3,}", "\n\n", updated).rstrip() + "\n"
        path.write_text(updated)
        remaining = len(_workspace_sections(updated))
        return WorkspaceRemove(
            workspace_id=wid, path=ws_path,
            was_default=was_default, remaining=remaining,
        )
    return None


def _workspace_section(workspace_id: str, workspace_path: str) -> str:
    return (
        f"[workspaces.{_toml_key(workspace_id)}]\n"
        f'path = "{_toml_escape(workspace_path)}"\n'
    )


def _workspace_sections(text: str) -> list[tuple[str, int, int]]:
    header_re = re.compile(r"(?m)^\[workspaces\.([^\].]+)\]\s*$")
    any_header_re = re.compile(r"(?m)^\[[^\]]+\]\s*$")
    sections = []
    for match in header_re.finditer(text):
        # The section body ends at the next section header that is NOT one of
        # this workspace's own sub-tables ([workspaces.<id>.exec], .policy, ...).
        wid = _unquote_toml_key(match.group(1).strip())
        pos = match.end()
        while True:
            nxt = any_header_re.search(text, pos)
            if nxt is None:
                end = len(text)
                break
            header = nxt.group(0).strip()
            if header.startswith(f"[workspaces.{wid}."):
                pos = nxt.end()
                continue
            end = nxt.start()
            break
        sections.append((wid, match.start(), end))
    return sections


def _read_default_workspace(text: str) -> str | None:
    """The ``default_workspace`` value from the ``[exec]`` section, if any."""
    exec_body = _section_body(text, "exec")
    if exec_body is None:
        return None
    return _read_string_value(exec_body, "default_workspace")


def _set_default_workspace(text: str, workspace_id: str) -> str:
    """Set ``default_workspace`` under ``[exec]``.

    Replaces an existing ``default_workspace`` assignment (so ``--make-default``
    can override the current default); otherwise inserts the key, creating the
    ``[exec]`` section if it is absent.
    """
    line = f'default_workspace = "{_toml_escape(workspace_id)}"'
    # Replace an existing assignment. Use a function replacement so the id (and
    # any escapes) are inserted verbatim, not treated as regex backreferences.
    text, replaced = re.subn(
        r"(?m)^\s*default_workspace\s*=.*$", lambda _m: line, text, count=1
    )
    if replaced:
        return text
    exec_match = re.search(r"(?m)^\[exec\]\s*$", text)
    if exec_match is None:
        separator = "" if text.endswith("\n") else "\n"
        return text + separator + "\n[exec]\n" + line + "\n"
    insert_at = exec_match.end()
    if insert_at < len(text) and text[insert_at] == "\n":
        insert_at += 1
    return text[:insert_at] + line + "\n" + text[insert_at:]


def _section_body(text: str, name: str) -> str | None:
    match = re.search(rf"(?m)^\[{re.escape(name)}\]\s*$", text)
    if match is None:
        return None
    any_header_re = re.compile(r"(?m)^\[[^\]]+\]\s*$")
    nxt = any_header_re.search(text, match.end())
    end = nxt.start() if nxt else len(text)
    return text[match.end():end]


def _read_string_value(text: str, key: str) -> str | None:
    # Accept both TOML string forms: "basic" (escapes processed) and 'literal'
    # (verbatim), so a hand-edited single-quoted value is still detected.
    basic = re.search(rf'(?m)^\s*{re.escape(key)}\s*=\s*"((?:[^"\\]|\\.)*)"\s*$', text)
    if basic:
        return bytes(basic.group(1), "utf-8").decode("unicode_escape")
    literal = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*'([^']*)'\s*$", text)
    if literal:
        return literal.group(1)
    return None


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
