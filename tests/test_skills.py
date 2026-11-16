import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "plugins" / "spring-security-advisor" / "skills"


def read_skill(name):
    text = (SKILLS_DIR / name / "SKILL.md").read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert match, f"{name}: missing frontmatter"
    front = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        front[key.strip()] = value.strip()
    return front, match.group(2)


class SkillStructure(unittest.TestCase):
    def test_every_skill_folder_has_matching_frontmatter(self):
        folders = [p for p in SKILLS_DIR.iterdir() if p.is_dir()]
        self.assertTrue(folders)
        for folder in folders:
            front, _ = read_skill(folder.name)
            self.assertEqual(front.get("name"), folder.name)
            self.assertTrue(front.get("description"))
            self.assertLessEqual(len(front["description"]), 1024)

    def test_expected_skill_set(self):
        self.assertEqual({p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}, {"audit", "map", "review"})

    def test_audit_contract(self):
        _, body = read_skill("audit")
        low = body.lower()
        for needle in ["scan.py", "checklist", "score", "--answers", "evidence", "cannot_determine", "provisional",
                       "not covered", "limits", "answer in the user's language", "${claude_plugin_root}",
                       "temporary directory", "read-only", "never say", "--baseline", "--save"]:
            self.assertIn(needle, low, needle)

    def test_audit_explains_not_applicable_and_grade_rules(self):
        _, body = read_skill("audit")
        low = body.lower()
        self.assertIn("needs a note", low)
        self.assertIn("provisional_reasons", body)
        self.assertIn("grade is withheld", low)

    def test_review_points_to_audit_and_is_read_only(self):
        _, body = read_skill("review")
        self.assertIn("/spring-security-advisor:audit", body)
        self.assertIn("read-only", body.lower())

    def test_map_mentions_signals(self):
        _, body = read_skill("map")
        self.assertIn("signals", body)


if __name__ == "__main__":
    unittest.main()
