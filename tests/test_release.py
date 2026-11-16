import json
import unittest
from pathlib import Path

from helpers import FIXTURES_DIR, ROOT, scan

PLUGIN = ROOT / "plugins" / "spring-security-advisor"


class Release(unittest.TestCase):
    def test_versions_and_changelog(self):
        self.assertEqual(scan.VERSION, "1.0.0")
        self.assertEqual(json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())["version"], "1.0.0")
        first = next(l for l in (ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## "))
        self.assertEqual(first, "## 1.0.0")

    def test_rule_ids_are_contiguous(self):
        ids = [r["id"] for r in json.loads((PLUGIN / "rules" / "rules.json").read_text())]
        self.assertEqual(ids, [f"SEC{n:03d}" for n in range(1, len(ids) + 1)])

    def test_readme_documents_rules_and_score(self):
        readme = (ROOT / "README.md").read_text()
        for heading in ("## Score", "## Rules", "## Skills"):
            self.assertIn(heading, readme)
        for rule in json.loads((PLUGIN / "rules" / "rules.json").read_text()):
            self.assertIn(rule["id"], readme)
        for needle in ("20 / 10 / 3", "69", "79", "70%", "`audit`"):
            self.assertIn(needle, readme)

    def test_clean_fixtures_have_no_finding_above_low(self):
        for name in ("fixed", "stateless-api"):
            findings = scan.run_scan(FIXTURES_DIR / name)["findings"]
            self.assertTrue(all(f["severity"] == "low" for f in findings), name)


if __name__ == "__main__":
    unittest.main()
