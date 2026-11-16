"""Shared helpers for the spring-security-advisor scripts: project loading, comment stripping, findings."""
from __future__ import annotations

import json
import re
from pathlib import Path

from config_reader import read_config

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "rules.json"
SKIP_DIRS = {".git", "target", "build", "node_modules", ".gradle", ".idea", ".mvn", "out"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
LIMITS = [
    "Rule-based pattern matching on source text, not a full Java parser.",
    "Does not run the application, resolve dependencies or inspect the network.",
    "Does not prove that a project is secure: absence of findings is not a security guarantee.",
    "Rules were checked against the Spring Security 7.0 reference; older versions can differ.",
]


class ScanError(Exception):
    pass


# --------------------------------------------------------------------------- helpers


def load_rules() -> dict[str, dict]:
    try:
        rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"cannot read rules file {RULES_FILE}: {exc}") from exc
    return {rule["id"]: rule for rule in rules}


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, keeping strings, offsets and line numbers."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        two = text[i : i + 2]
        if text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end == -1 else end + 3
            out.append(text[i:end])
            i = end
        elif text[i] in "\"'":
            quote = text[i]
            j = i + 1
            while j < n and text[j] != quote and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(text[i:j])
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def find_matching(text: str, open_idx: int) -> int:
    """Index of the parenthesis closing the one at open_idx (or end of text)."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


TEST_SOURCE_SET = re.compile(r"(?i)test|^it$|^e2e$|integ")


def is_test_path(path: Path, root: Path) -> bool:
    """Test code is decided by the source-set directory (src/<set>/...), never by package or class names.

    `src/main/java/it/acme/Shop.java` is main code; `src/testFixtures`, `src/integration-test`, `src/e2e`
    and `src/it` are test source sets. Without a `src/<set>/` layout the old convention is used.
    """
    parts = path.relative_to(root).parts
    directories = parts[:-1]
    if "src" in directories:
        index = directories.index("src")
        if index + 1 < len(directories):
            return bool(TEST_SOURCE_SET.search(directories[index + 1]))
    return any(p in ("test", "tests") for p in directories) or path.name.endswith(("Test.java", "Tests.java", "IT.java"))


class Project:
    def __init__(self, root: Path):
        if not root.is_dir():
            raise ScanError(f"not a directory: {root}")
        self.root = root.resolve()
        self.java: list[tuple[Path, str]] = []  # (path, comment-free text), main code only
        self.config: list[tuple[Path, dict[str, tuple[str, int]]]] = []  # main config files only
        self.counts = {"java": 0, "java_test_skipped": 0, "config": 0, "build": 0}
        self.boot_version: str | None = None
        self._load()

    def _load(self) -> None:
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or any(p in SKIP_DIRS for p in path.relative_to(self.root).parts):
                continue
            name = path.name
            try:
                if name.endswith(".java"):
                    if is_test_path(path, self.root):
                        self.counts["java_test_skipped"] += 1
                        continue
                    self.java.append((path, strip_comments(path.read_text(encoding="utf-8", errors="replace"))))
                    self.counts["java"] += 1
                elif name == "pom.xml" or name.startswith("build.gradle"):
                    self.counts["build"] += 1
                    self._read_build(path.read_text(encoding="utf-8", errors="replace"))
                elif re.fullmatch(r"application.*\.(ya?ml|properties)", name):
                    self.counts["config"] += 1
                    if not is_test_path(path, self.root):
                        self.config.append((path, read_config(path)))
            except OSError:
                continue

    def _read_build(self, text: str) -> None:
        patterns = [
            r"spring-boot-starter-parent\s*</artifactId>\s*<version>\s*([^<\s]+)",
            r"org\.springframework\.boot['\"]\)?\s*version\s*['\"]([^'\"]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match and not self.boot_version:
                self.boot_version = match.group(1)

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def grep(self, pattern: str, skip_imports: bool = True):
        """Yield (path, text, match, line) for each match in main Java code."""
        regex = re.compile(pattern)
        for path, text in self.java:
            for match in regex.finditer(text):
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.start())
                line_text = text[line_start : len(text) if line_end == -1 else line_end]
                if skip_imports and line_text.lstrip().startswith(("import ", "package ")):
                    continue
                yield path, text, match, line_of(text, match.start())



def make_finding(rules, rule_id, project, path, line, detail, confidence="high", severity=None):
    rule = rules[rule_id]
    return {
        "id": rule_id,
        "severity": severity or rule["severity"],
        "title": rule["title"],
        "file": project.rel(path) if path else None,
        "line": line,
        "detail": detail,
        "risk": rule["risk"],
        "fix": rule["fix"],
        "source": f'{rule["source"]} (checked {rule["checked"]})',
        "type": rule["type"],
        "confidence": confidence,
        "category": rule.get("category"),
    }

