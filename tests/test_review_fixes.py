import time
import unittest

from helpers import scan_files, signals_for
import scoring  # noqa: E402

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
        base[key] = {"answer": value, "evidence": [], "note": "n"}
    return base


def run(rule, files):
    return [f for f in scan_files(files) if f["id"] == rule]


class ScoreHonesty(unittest.TestCase):
    def test_not_applicable_needs_a_note(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            items = SYN["items"]
            effective, warnings = scoring.validate_answers({"answers": [{"id": "T1", "answer": "not_applicable"}]}, items, Path(tmp))
            self.assertEqual(effective["T1"]["answer"], "cannot_determine")
            self.assertTrue(any("T1" in w and "note" in w for w in warnings))
            effective, _ = scoring.validate_answers({"answers": [{"id": "T1", "answer": "not_applicable", "note": "token-only API"}]}, items, Path(tmp))
            self.assertEqual(effective["T1"]["answer"], "not_applicable")

    def test_not_applicable_counts_as_not_assessed(self):
        r = scoring.compute_score([], eff(T1="not_applicable", T2="not_applicable"), SYN, {})
        self.assertEqual(r["coverage"], 0.33)
        self.assertTrue(r["provisional"])
        self.assertEqual(r["items"], {"total": 3, "assessed": 1, "not_applicable": 2, "cannot_determine": 0})

    def test_unassessed_critical_item_makes_the_score_provisional(self):
        r = scoring.compute_score([], eff(T1="cannot_determine"), SYN, {})
        self.assertTrue(r["provisional"])
        self.assertTrue(any("critical" in reason and "T1" in reason for reason in r["provisional_reasons"]))

    def test_unassessed_category_makes_the_score_provisional(self):
        r = scoring.compute_score([], eff(T1="cannot_determine", T2="cannot_determine"), SYN, {})
        self.assertTrue(any("Tokens" in reason for reason in r["provisional_reasons"]))

    def test_grade_is_withheld_below_half_coverage(self):
        r = scoring.compute_score([], eff(T1="cannot_determine", T2="cannot_determine"), SYN, {})
        self.assertEqual(r["coverage"], 0.33)
        self.assertIsNone(r["grade"])
        self.assertIsNotNone(r["total"])
        r = scoring.compute_score([], eff(T1="cannot_determine"), SYN, {})
        self.assertEqual(r["coverage"], 0.67)
        self.assertIsNotNone(r["grade"])

    def test_clean_complete_answers_are_not_provisional(self):
        r = scoring.compute_score([], eff(), SYN, {})
        self.assertFalse(r["provisional"])
        self.assertEqual(r["provisional_reasons"], [])

    def test_text_explains_why(self):
        text = scoring.format_score_text(scoring.compute_score([], eff(T1="cannot_determine", T2="cannot_determine"), SYN, {}))
        self.assertIn("Grade: not assigned", text)
        self.assertIn("1 of 3 items assessed", text)
        self.assertIn("Provisional because", text)


class TestSourceSets(unittest.TestCase):
    BAD = "class C { Object e = new NoOpPasswordEncoder(); }"

    def test_main_code_with_it_test_packages_is_scanned(self):
        for path in ["src/main/java/it/acme/shop/C.java", "src/main/java/com/acme/test/Prod.java",
                     "src/main/java/com/acme/FooTest.java", "src/main/java/com/acme/ReportIT.java",
                     "module/src/main/java/it/x/C.java"]:
            self.assertEqual(len(run("SEC001", {path: self.BAD})), 1, path)

    def test_every_test_source_set_is_skipped(self):
        for path in ["src/test/java/C.java", "src/testFixtures/java/C.java", "src/integration-test/java/C.java",
                     "src/integrationTest/java/C.java", "src/integTest/java/C.java", "src/functionalTest/java/C.java",
                     "src/e2e/java/C.java", "src/it/java/C.java", "module/src/test/java/C.java"]:
            self.assertEqual(run("SEC001", {path: self.BAD}), [], path)
        self.assertEqual(signals_for({"src/testFixtures/java/A.java": "class A { Bucket b; }"})["rate_limiting"], [])


class Sec008NonSecrets(unittest.TestCase):
    def cfg(self, text, name="application.yml"):
        return run("SEC008", {"src/main/resources/" + name: text})

    def test_real_world_non_secrets_are_not_reported(self):
        for text in [
            "logging:\n  level:\n    com.example.security.JwtTokenProvider: DEBUG\n",
            "logging:\n  level:\n    org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter: TRACE\n",
            "spring:\n  security:\n    oauth2:\n      authorizationserver:\n        client:\n          web:\n            token:\n              access-token-time-to-live: 30m\n              refresh-token-time-to-live: 7d\n              access-token-format: reference\n",
            "app:\n  token-duration: PT15M\n  refresh-token-duration: 7d\n",
            "app:\n  secret-file: /run/secrets/jwt\n  token-path: classpath:keys/token.pem\n  token-issuer: https://issuer.example\n",
            "app:\n  password-encoder: bcrypt\n  credentials-provider: env\n",
            "app:\n  secret: \"#{systemProperties['x']}\"\n",
            "app:\n  secret: ${JWT_SECRET}-suffix\n",
            "app:\n  password: ENC(abcDEF123)\n",
        ]:
            self.assertEqual(self.cfg(text), [], text)
        self.assertEqual(self.cfg("j.secret=${A}${B}\n", "application.properties"), [])

    def test_real_secrets_are_still_reported(self):
        for text in ["jwt:\n  secret: abc123\n", "spring:\n  datasource:\n    password: hunter2\n", "app:\n  api-key: k9\n"]:
            self.assertEqual(len(self.cfg(text)), 1, text)


class Sec023Bounds(unittest.TestCase):
    def test_large_file_is_scanned_quickly(self):
        body = "class S {\n void f() {\n" + "x.findById(a);\n" * 20000 + " }\n String c = \"refresh_token\";\n}\n"
        start = time.perf_counter()
        run("SEC023", {"src/main/java/S.java": body})
        self.assertLess(time.perf_counter() - start, 5.0)

    def test_unrelated_getter_and_save_do_not_fire(self):
        code = ('class C {\n String K = "refresh_token";\n'
                ' String a(User u) { return u.getName(); }\n'
                ' void b(User u) { userRepository.save(u); }\n}\n')
        self.assertEqual(run("SEC023", {"src/main/java/C.java": code}), [])

    def test_lookup_without_refresh_context_does_not_fire(self):
        code = ('class C {\n String K = "refresh_token";\n'
                ' void a(long id) { var u = userRepository.findById(id); userRepository.save(u); }\n}\n')
        self.assertEqual(run("SEC023", {"src/main/java/C.java": code}), [])

    def test_lookup_and_revoke_in_one_method_still_fires(self):
        code = ('class C {\n void a(String t) {\n  var r = refreshTokenRepository.findByToken(t);\n'
                '  r.setRevoked(true);\n  refreshTokenRepository.save(r);\n }\n}\n')
        found = run("SEC023", {"src/main/java/C.java": code})
        self.assertEqual([f["line"] for f in found], [3])


if __name__ == "__main__":
    unittest.main()
