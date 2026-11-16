"""Rules added after 0.2: configuration files, web, tokens, passwords, data and refresh tokens.

Each check has the signature `check(project, rules) -> Iterator[dict]`, like the rules in scan.py.
"""
from __future__ import annotations

import re

from core import make_finding

SECRET_KEY = re.compile(r"secret|password|passwd|token|api-?key|private-?key|credential")
NON_SECRET_SUFFIXES = (
    "-expiration", "-ttl", "-validity", "-length", "-policy", "-enabled", "-header", "-prefix",
    "-uri", "-url", "-name", "-type", "-endpoint", "-algorithm",
)
NOT_A_SECRET_VALUE = re.compile(r"^(true|false|\d+(\.\d+)?)$", re.I)
PLACEHOLDER = re.compile(r"^\$\{[^}:]*(?::(.*))?\}$", re.S)
DEV_PROFILE = re.compile(r"^application-(dev|development|local|test|h2|sample|example)\b", re.I)


def _last_segment(key: str) -> str:
    return re.sub(r"\[\d+\]$", "", key.rsplit(".", 1)[-1])


def check_sec008(project, rules):
    for path, entries in project.config:
        dev = bool(DEV_PROFILE.match(path.name))
        for key, (value, line) in entries.items():
            last = _last_segment(key)
            if not SECRET_KEY.search(last) or last.endswith(NON_SECRET_SUFFIXES):
                continue
            value = value.strip()
            if not value or NOT_A_SECRET_VALUE.match(value) or value.startswith("{cipher}"):
                continue
            placeholder = PLACEHOLDER.match(value)
            if placeholder and not (placeholder.group(1) or "").strip():
                continue
            embedded_default = bool(placeholder)
            low = dev or embedded_default
            detail = (
                f"{key} has a placeholder with a literal default value." if embedded_default
                else f"{key} is set to a literal value."
            )
            yield make_finding(
                rules, "SEC008", project, path, line, detail,
                confidence="medium" if low else "high", severity="low" if low else None,
            )


def _config_items(project, key_base):
    for path, entries in project.config:
        for key, (value, line) in entries.items():
            if key == key_base or key.startswith(key_base + "["):
                yield path, key, value, line


def check_sec009(project, rules):
    for path, key, value, line in _config_items(project, "management.endpoints.web.exposure.include"):
        items = [v.strip().strip("\"'") for v in value.split(",")]
        if "*" in items:
            yield make_finding(rules, "SEC009", project, path, line, "All actuator endpoints are exposed over HTTP.", confidence="high")


def check_sec010(project, rules):
    for base in ("server.error.include-stacktrace", "spring.web.error.include-stacktrace"):
        for path, key, value, line in _config_items(project, base):
            if value.strip().lower() == "always":
                yield make_finding(rules, "SEC010", project, path, line, f"{key} is set to always.")


COOKIE_KEYS = (
    "server.servlet.session.cookie.secure", "server.servlet.session.cookie.http-only",
    "server.reactive.session.cookie.secure", "server.reactive.session.cookie.http-only",
)
COOKIE_CODE = r"\.(?:setHttpOnly|setSecure|httpOnly|secure)\(\s*false\s*\)"


def check_sec011(project, rules):
    for base in COOKIE_KEYS:
        for path, key, value, line in _config_items(project, base):
            if value.strip().lower() == "false":
                yield make_finding(rules, "SEC011", project, path, line, f"{key} is false.")
    for path, _text, match, line in project.grep(COOKIE_CODE):
        yield make_finding(rules, "SEC011", project, path, line, f"{match.group(0)} turns a cookie protection off.")


CHECKS_MORE = {
    "SEC008": check_sec008,
    "SEC009": check_sec009,
    "SEC010": check_sec010,
    "SEC011": check_sec011,
}
