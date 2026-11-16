"""Shared helpers for the scanner tests."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "plugins" / "spring-security-advisor" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import scan  # noqa: E402


def write_project(tmp, files):
    for rel, content in files.items():
        path = Path(tmp) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="")
    return Path(tmp)


def scan_files(files):
    """Write a temporary project with these relative paths and return its findings."""
    with tempfile.TemporaryDirectory() as tmp:
        write_project(tmp, files)
        return scan.run_scan(Path(tmp))["findings"]


def signals_for(files):
    """Return the signals of a temporary project (implemented with the signals module)."""
    with tempfile.TemporaryDirectory() as tmp:
        write_project(tmp, files)
        return scan.run_scan(Path(tmp))["signals"]
