import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES_DIR, ROOT, SCRIPTS, scan  # noqa: F401
import scoring  # noqa: E402

CHECKLIST_FILE = ROOT / "plugins" / "spring-security-advisor" / "checklists" / "checklist.json"
SIGNAL_NAMES = {"rate_limiting", "login_throttling", "refresh_token", "token_revocation", "locking",
                "jwt_validation", "password_reset", "input_validation", "logout", "audit_events"}

SYN = {
    "categories": {"tokens": {"label": "Tokens", "weight": 60}, "authorization": {"label": "Authorization", "weight": 40}},
    "items": [
        {"id": "T1", "category": "tokens", "weight": 3, "question": "q1"},
        {"id": "T2", "category": "tokens", "weight": 1, "question": "q2"},
        {"id": "A1", "category": "authorization", "weight": 2, "question": "q3"},
    ],
}


def eff(**answers):
    base = {i["id"]: {"answer": "yes", "evidence": ["x:1"], "note": ""} for i in SYN["items"]}
    for key, value in answers.items():
        base[key] = {"answer": value, "evidence": [], "note": ""}
    return base


def finding(rule="SEC001", severity="high", typ="certain bug", category="tokens"):
    return {"id": rule, "severity": severity, "type": typ, "category": category, "title": "t", "file": "f", "line": 1}


def score(findings=(), effective=None, checklist=SYN):
    return scoring.compute_score(list(findings), effective or eff(), checklist, {})


class ChecklistFile(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(CHECKLIST_FILE.read_text(encoding="utf-8"))

    def test_item_integrity(self):
        ids = [i["id"] for i in self.data["items"]]
        self.assertEqual(len(ids), len(set(ids)))
        for item in self.data["items"]:
            for key in ("id", "category", "weight", "question", "look_for", "signals", "source", "status", "checked"):
                self.assertIn(key, item, item["id"])
            self.assertIn(item["weight"], (1, 2, 3), item["id"])
            self.assertIn(item["category"], self.data["categories"], item["id"])
            self.assertTrue(set(item["signals"]) <= SIGNAL_NAMES, item["id"])
            self.assertEqual(item["status"], "V", item["id"])
            self.assertRegex(item["checked"], r"^\d{4}-\d{2}-\d{2}$")

    def test_category_weights_sum_to_100(self):
        self.assertEqual(sum(c["weight"] for c in self.data["categories"].values()), 100)

    def test_rule_categories_exist_in_checklist(self):
        rules = json.loads((ROOT / "plugins/spring-security-advisor/rules/rules.json").read_text())
        for rule in rules:
            self.assertIn(rule["category"], self.data["categories"], rule["id"])


class ValidateAnswers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "A.java").write_text("line1\nline2\nline3\n")

    def tearDown(self):
        self.tmp.cleanup()

    def run_validate(self, answers):
        return scoring.validate_answers({"answers": answers}, SYN["items"], self.root)

    def test_valid_evidence_is_kept(self):
        effective, warnings = self.run_validate([{"id": "T1", "answer": "yes", "evidence": ["src/A.java:2"]}])
        self.assertEqual(effective["T1"]["answer"], "yes")
        self.assertEqual(warnings, [])

    def test_bad_evidence_downgrades_to_cannot_determine(self):
        for ev in ([], ["../etc/passwd:1"], ["/etc/passwd:1"], ["src/Missing.java:1"], ["src/A.java:99"],
                   ["src/A.java:0"], ["src/A.java"], ["src:1"]):
            effective, warnings = self.run_validate([{"id": "T1", "answer": "yes", "evidence": ev}])
            self.assertEqual(effective["T1"]["answer"], "cannot_determine", ev)
            self.assertTrue(any("T1" in w for w in warnings), ev)

    def test_no_without_evidence_is_accepted(self):
        effective, _ = self.run_validate([{"id": "T1", "answer": "no"}])
        self.assertEqual(effective["T1"]["answer"], "no")

    def test_unknown_duplicate_unanswered_and_invalid(self):
        effective, warnings = self.run_validate([
            {"id": "ZZZ", "answer": "yes", "evidence": ["src/A.java:1"]},
            {"id": "T1", "answer": "no"}, {"id": "T1", "answer": "partial", "evidence": ["src/A.java:1"]},
            {"id": "T2", "answer": "maybe"},
        ])
        self.assertEqual(effective["T1"]["answer"], "partial")
        self.assertEqual(effective["T2"]["answer"], "cannot_determine")
        self.assertEqual(effective["A1"]["answer"], "cannot_determine")
        text = " ".join(warnings)
        for needle in ("ZZZ", "duplicate", "T2"):
            self.assertIn(needle, text)

    def test_structural_errors_raise(self):
        with self.assertRaises(scoring.ScoreError):
            scoring.validate_answers([], SYN["items"], self.root)
        with self.assertRaises(scoring.ScoreError):
            scoring.validate_answers({"answers": "x"}, SYN["items"], self.root)


class ComputeScore(unittest.TestCase):
    def test_all_yes_is_a(self):
        r = score()
        self.assertEqual((r["total"], r["grade"], r["coverage"], r["provisional"]), (100, "A", 1.0, False))

    def test_weights_and_category_scores(self):
        r = score(effective=eff(T1="no"))
        self.assertEqual(r["categories"]["tokens"]["score"], 25)
        self.assertEqual(r["total"], 55)  # (60*25 + 40*100) / 100
        self.assertEqual(r["grade"], "F")

    def test_partial_earns_half(self):
        r = score(effective=eff(T1="partial"))
        self.assertEqual(r["categories"]["tokens"]["score"], 63)  # (1.5 + 1) / 4 = 62.5, rounded half up

    def test_not_applicable_does_not_count(self):
        r = score(effective=eff(T1="not_applicable"))
        self.assertEqual(r["categories"]["tokens"]["score"], 100)
        self.assertEqual(r["coverage"], 1.0)

    def test_cannot_determine_is_excluded_and_lowers_coverage(self):
        r = score(effective=eff(T1="cannot_determine", A1="cannot_determine"))
        self.assertEqual(r["coverage"], round(1 / 3, 2))
        self.assertTrue(r["provisional"])
        self.assertIsNone(r["categories"]["authorization"]["score"])
        self.assertEqual(r["total"], 100)

    def test_cap_79_for_a_critical_no(self):
        checklist = json.loads(json.dumps(SYN))
        checklist["items"].append({"id": "T3", "category": "tokens", "weight": 20, "question": "q"})
        effective = eff(T1="no")
        effective["T3"] = {"answer": "yes", "evidence": ["x:1"], "note": ""}
        r = score(effective=effective, checklist=checklist)
        self.assertEqual(r["total"], 79)
        self.assertEqual(len(r["caps_applied"]), 1)

    def test_cap_69_only_for_high_certain_bugs(self):
        r = score([finding()])
        self.assertEqual(r["total"], 69)
        r = score([finding(typ="risk to evaluate")])
        self.assertEqual(r["total"], 88)  # tokens 80, authorization 100
        self.assertEqual(r["caps_applied"], [])

    def test_both_caps_the_lower_wins(self):
        checklist = json.loads(json.dumps(SYN))
        checklist["items"].append({"id": "T3", "category": "tokens", "weight": 40, "question": "q"})
        effective = eff(T1="no")
        effective["T3"] = {"answer": "yes", "evidence": ["x:1"], "note": ""}
        r = score([finding()], effective=effective, checklist=checklist)
        self.assertEqual(r["total"], 69)
        self.assertEqual(len(r["caps_applied"]), 2)

    def test_repeat_penalty_and_rules_only_basis(self):
        all_cd = {i["id"]: {"answer": "cannot_determine", "evidence": [], "note": ""} for i in SYN["items"]}
        r = score([finding(typ="risk to evaluate")] * 3, effective=all_cd)
        self.assertEqual(r["categories"]["tokens"]["score"], 70)  # 100 - (20 + 5 + 5)
        self.assertEqual(r["categories"]["tokens"]["basis"], "rules_only")
        self.assertEqual(r["total"], 70)

    def test_empty_project_has_no_score(self):
        all_cd = {i["id"]: {"answer": "cannot_determine", "evidence": [], "note": ""} for i in SYN["items"]}
        r = score(effective=all_cd)
        self.assertEqual((r["total"], r["grade"], r["coverage"], r["provisional"]), (None, None, 0.0, True))

    def test_penalty_is_floored_at_zero(self):
        r = score([finding(typ="risk to evaluate")] * 20)
        self.assertEqual(r["categories"]["tokens"]["score"], 0)

    def test_top_actions_sorted_limited_and_deterministic(self):
        effective = eff(T1="no", T2="no", A1="no")
        r = score([finding()], effective=effective)
        actions = r["top_actions"]
        self.assertLessEqual(len(actions), 5)
        impacts = [a["impact"] for a in actions]
        self.assertEqual(impacts, sorted(impacts, reverse=True))
        self.assertEqual(r, score([finding()], effective=effective))
        self.assertEqual(set(actions[0]), {"kind", "id", "impact", "detail"})


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "scan.py"), *args], capture_output=True, text=True)

    def answers(self, name):
        return str(FIXTURES_DIR / "answers" / name)

    def test_checklist_command_prints_items(self):
        out = json.loads(self.run_cli("checklist").stdout)
        self.assertIn("items", out)
        self.assertGreater(len(out["items"]), 20)

    def test_score_race_vs_safe(self):
        race = self.run_cli("score", str(FIXTURES_DIR / "refresh-race"), "--answers", self.answers("refresh-race.json"))
        safe = self.run_cli("score", str(FIXTURES_DIR / "refresh-safe"), "--answers", self.answers("refresh-safe.json"))
        self.assertEqual(race.returncode, 0, race.stderr)
        self.assertEqual(safe.returncode, 0, safe.stderr)
        r, s = json.loads(race.stdout), json.loads(safe.stdout)
        self.assertGreater(r["findings_count"], 0)
        self.assertLessEqual(r["total"], 79)
        self.assertGreater(s["total"], r["total"])

    def test_text_format_and_provisional(self):
        out = self.run_cli("score", str(FIXTURES_DIR / "refresh-race"), "--answers", self.answers("refresh-race.json"),
                           "--format", "text").stdout
        self.assertIn("provisional", out.lower())
        self.assertRegex(out, r"Grade: [A-F]")

    def test_baseline_and_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "p"
            project.mkdir()
            (project / "src/main/java").mkdir(parents=True)
            (project / "src/main/java/A.java").write_text("class A {}")
            answers = Path(tmp) / "answers.json"
            answers.write_text(json.dumps({"answers": [{"id": "AUTHZ-01", "answer": "no"}]}))
            first = self.run_cli("score", str(project), "--answers", str(answers), "--save")
            self.assertEqual(first.returncode, 0, first.stderr)
            saved = project / ".spring-security-advisor" / "last-audit.json"
            self.assertTrue(saved.is_file())
            self.assertEqual({p.name for p in project.rglob("*") if p.is_file() and ".spring" not in str(p)}, {"A.java"})
            answers.write_text(json.dumps({"answers": [{"id": "AUTHZ-01", "answer": "yes", "evidence": ["src/main/java/A.java:1"]}]}))
            second = json.loads(self.run_cli("score", str(project), "--answers", str(answers), "--baseline", str(saved)).stdout)
            self.assertGreater(second["delta"]["total"], 0)

    def test_invalid_answers_file_is_a_json_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json")
            r = self.run_cli("score", str(FIXTURES_DIR / "fixed"), "--answers", str(bad))
            self.assertEqual(r.returncode, 2)
            self.assertIn("error", json.loads(r.stderr))


if __name__ == "__main__":
    unittest.main()
