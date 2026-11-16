"""Minimal reader for Spring `application*.properties` and `application*.yml` files.

Standard library only. It flattens keys to dotted lower-case names and returns
`{key: (value, line_number)}`. It is not a full YAML parser: it handles nesting by
indentation, quoted values, inline `# comments`, simple lists and `key: value` list
items, which is what Spring configuration files normally contain.
"""
from __future__ import annotations

import re
from pathlib import Path

BLOCK_SCALARS = {"|", "|-", "|+", ">", ">-", ">+"}


def read_config(path: Path) -> dict[str, tuple[str, int]]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if Path(path).suffix.lower() == ".properties":
        return _read_properties(lines)
    return _read_yaml(lines)


def _read_properties(lines: list[str]) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        match = re.match(r"([^=:\s]+)\s*[=:\s]\s*(.*)$", line)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip()
        if value:
            out[key] = (value, number)
    return out


def _clean_value(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] in ("\"", "'"):
        quote = raw[0]
        i = 1
        while i < len(raw):
            if raw[i] == "\\" and quote == '"':
                i += 2
                continue
            if raw[i] == quote:
                return raw[1:i]
            i += 1
        return raw[1:]
    match = re.search(r"\s#", raw)
    if match:
        raw = raw[: match.start()]
    return raw.strip()


def _read_yaml(lines: list[str]) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    stack: list[tuple[int, str, bool]] = []  # (indent, path, is_list_item_marker)
    counters: dict[str, int] = {}
    skip_deeper_than: int | None = None

    def path_of(name: str) -> str:
        return (stack[-1][1] + "." + name) if stack else name

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped == "---":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if skip_deeper_than is not None:
            if indent > skip_deeper_than:
                continue
            skip_deeper_than = None

        if stripped.startswith("- ") or stripped == "-":
            while stack and (stack[-1][0] > indent or (stack[-1][0] == indent and stack[-1][2])):
                stack.pop()
            parent = stack[-1][1] if stack else ""
            index = counters.get(parent, 0)
            counters[parent] = index + 1
            item_path = f"{parent}[{index}]"
            body = stripped[1:].strip()
            kv = re.match(r"([^\s#:][^:]*?):(?:\s+(.*))?$", body) if body else None
            if kv and not body.startswith(('"', "'")):
                stack.append((indent, item_path, True))
                value = _clean_value(kv.group(2) or "")
                if value:
                    out[(item_path + "." + kv.group(1).strip()).lower()] = (value, number)
            elif body:
                value = _clean_value(body)
                if value:
                    out[item_path.lower()] = (value, number)
            continue

        match = re.match(r"([^\s#:][^:]*?):(?:\s+(.*))?$", stripped)
        if not match:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = match.group(1).strip().strip("\"'")
        full = path_of(key).lower()
        rest = (match.group(2) or "").strip()
        if rest in BLOCK_SCALARS:
            skip_deeper_than = indent
            continue
        value = _clean_value(rest) if rest else ""
        if value or rest[:1] in ("\"", "'"):
            out[full] = (value, number)
        else:
            stack.append((indent, full, False))
    return out
