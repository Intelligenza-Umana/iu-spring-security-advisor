import unittest

from helpers import FIXTURES_DIR, scan, signals_for

NAMES = {"rate_limiting", "login_throttling", "refresh_token", "token_revocation", "locking",
         "jwt_validation", "password_reset", "input_validation", "logout", "audit_events"}


def sec024(path):
    return [f for f in scan.run_scan(path)["findings"] if f["id"] == "SEC024"]


class Signals(unittest.TestCase):
    def test_all_signal_names_are_always_present(self):
        self.assertEqual(set(signals_for({"src/main/java/A.java": "class A {}"})), NAMES)
        self.assertEqual(set(scan.run_scan(FIXTURES_DIR / "fixed")["signals"]), NAMES)

    def test_refresh_race_fixture_has_refresh_but_no_lock_or_limit(self):
        sig = scan.run_scan(FIXTURES_DIR / "refresh-race")["signals"]
        self.assertTrue(sig["refresh_token"])
        self.assertEqual(sig["locking"], [])
        self.assertEqual(sig["rate_limiting"], [])
        entry = sig["refresh_token"][0]
        self.assertEqual(set(entry), {"file", "line", "text"})

    def test_refresh_safe_fixture_has_lock_and_limit(self):
        sig = scan.run_scan(FIXTURES_DIR / "refresh-safe")["signals"]
        self.assertTrue(sig["locking"])
        self.assertTrue(sig["rate_limiting"])

    def test_each_pattern_family_is_detected(self):
        code = """class A {
            void f() { /* x */ }
            @Valid void v() {}
            void g() { http.logout(l -> l); LoginAttemptService failedAttempts; revokeToken(); jti();
                       JwtDecoder d; passwordResetToken(); AuthenticationSuccessEvent e; @Version long v; }
        }"""
        sig = signals_for({"src/main/java/A.java": code})
        for name in ("input_validation", "logout", "login_throttling", "token_revocation", "jwt_validation",
                     "password_reset", "audit_events", "locking"):
            self.assertTrue(sig[name], name)

    def test_test_sources_are_ignored(self):
        sig = signals_for({"src/test/java/ATest.java": "class ATest { Bucket b; @Lock int x; }"})
        self.assertEqual(sig["rate_limiting"], [])
        self.assertEqual(sig["locking"], [])


class Sec024(unittest.TestCase):
    def test_fires_on_the_race_fixture_at_the_lookup(self):
        found = sec024(FIXTURES_DIR / "refresh-race")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["file"], "src/main/java/demo/RefreshService.java")
        self.assertEqual(found[0]["line"], 15)
        self.assertEqual((found[0]["severity"], found[0]["confidence"], found[0]["category"]),
                         ("medium", "medium", "tokens"))

    def test_silent_when_a_lock_exists_on_the_refresh_path(self):
        self.assertEqual(sec024(FIXTURES_DIR / "refresh-safe"), [])

    def test_silent_without_refresh_token_signal(self):
        code = "class S { void f() { var x = repo.findByName(n); repo.save(x); } }"
        findings = [f for f in __import__("helpers").scan_files({"src/main/java/S.java": code}) if f["id"] == "SEC024"]
        self.assertEqual(findings, [])


class MapSignals(unittest.TestCase):
    def test_map_includes_signals(self):
        self.assertIn("signals", scan.run_map(FIXTURES_DIR / "refresh-safe"))


if __name__ == "__main__":
    unittest.main()
