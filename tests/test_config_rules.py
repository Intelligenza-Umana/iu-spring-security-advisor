import tempfile
import unittest
from pathlib import Path

from helpers import scan_files, write_project  # noqa: F401  (also puts scripts on sys.path)
import config_reader  # noqa: E402


def read(text, name="application.yml"):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.write_bytes(text.encode("utf-8"))
        return config_reader.read_config(path)


def by_id(findings, rule_id):
    return [f for f in findings if f["id"] == rule_id]


class Reader(unittest.TestCase):
    def test_nested_yaml_with_quotes_comments_and_lists(self):
        cfg = read("spring:\n  datasource:\n    password: hunter2\njwt:\n  secret: \"abc\"  # note\nlist:\n  - a\n  - b\n")
        self.assertEqual(cfg["spring.datasource.password"], ("hunter2", 3))
        self.assertEqual(cfg["jwt.secret"], ("abc", 5))
        self.assertEqual(cfg["list[0]"], ("a", 7))
        self.assertEqual(cfg["list[1]"], ("b", 8))

    def test_properties_keys_are_lowercased_and_hash_inside_value_is_kept(self):
        cfg = read("# comment\nJwt.Secret = ab#cd\n\nother=1\n", "application.properties")
        self.assertEqual(cfg["jwt.secret"], ("ab#cd", 2))
        self.assertEqual(cfg["other"], ("1", 4))

    def test_crlf_and_empty_and_key_without_value(self):
        self.assertEqual(read(""), {})
        cfg = read("a:\r\n  b: 1\r\nc:\r\n")
        self.assertEqual(cfg["a.b"], ("1", 2))
        self.assertNotIn("c", cfg)

    def test_unicode_value(self):
        self.assertEqual(read("name: caffè\n")["name"], ("caffè", 1))


class Sec008(unittest.TestCase):
    def run_cfg(self, content, name="application.yml"):
        return by_id(scan_files({"src/main/resources/" + name: content}), "SEC008")

    def test_literal_secrets_are_reported(self):
        for text in ["jwt:\n  secret: abc123\n", "spring:\n  datasource:\n    password: hunter2\n", "app:\n  api-key: k9\n"]:
            found = self.run_cfg(text)
            self.assertEqual(len(found), 1, text)
            self.assertEqual(found[0]["category"], "secrets_config")
            self.assertEqual(found[0]["severity"], "high")

    def test_properties_file_is_read_too(self):
        self.assertEqual(len(self.run_cfg("jwt.secret=abc123\n", "application.properties")), 1)

    def test_placeholders_and_non_secrets_are_not_reported(self):
        for text in ["jwt:\n  secret: ${JWT_SECRET}\n", "db:\n  password: ${DB_PASS:}\n", "db:\n  password:\n",
                     "jwt:\n  secret-expiration: 3600\n", "password-policy:\n  min-length: 8\n",
                     "jwt:\n  token-prefix: Bearer\n", "feature:\n  token-enabled: true\n"]:
            self.assertEqual(self.run_cfg(text), [], text)

    def test_placeholder_with_literal_default_is_low(self):
        found = self.run_cfg("jwt:\n  secret: ${JWT_SECRET:devsecret}\n")
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["severity"], found[0]["confidence"]), ("low", "medium"))

    def test_dev_profiles_are_low_and_value_is_never_printed(self):
        found = self.run_cfg("jwt:\n  secret: sup3rs3cr3tvalue\n", "application-dev.yml")
        self.assertEqual((found[0]["severity"], found[0]["confidence"]), ("low", "medium"))
        self.assertEqual(found[0]["line"], 2)
        for key, value in found[0].items():
            self.assertNotIn("sup3rs3cr3tvalue", str(value), key)

    def test_test_resources_are_skipped(self):
        found = by_id(scan_files({"src/test/resources/application.yml": "jwt:\n  secret: abc\n"}), "SEC008")
        self.assertEqual(found, [])


class Sec009To011(unittest.TestCase):
    def cfg(self, rule, text, name="application.yml"):
        return by_id(scan_files({"src/main/resources/" + name: text}), rule)

    def test_actuator_wildcard(self):
        self.assertEqual(len(self.cfg("SEC009", 'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n')), 1)
        self.assertEqual(len(self.cfg("SEC009", "management.endpoints.web.exposure.include=*\n", "application.properties")), 1)
        self.assertEqual(len(self.cfg("SEC009", 'management:\n  endpoints:\n    web:\n      exposure:\n        include:\n          - "*"\n')), 1)
        self.assertEqual(self.cfg("SEC009", "management.endpoints.web.exposure.include=health,info\n", "application.properties"), [])

    def test_stacktrace_always(self):
        self.assertEqual(len(self.cfg("SEC010", "server.error.include-stacktrace=always\n", "application.properties")), 1)
        self.assertEqual(len(self.cfg("SEC010", "spring:\n  web:\n    error:\n      include-stacktrace: always\n")), 1)
        self.assertEqual(self.cfg("SEC010", "server.error.include-stacktrace=never\n", "application.properties"), [])

    def test_cookie_flags_in_config_and_code(self):
        self.assertEqual(len(self.cfg("SEC011", "server.servlet.session.cookie.secure=false\n", "application.properties")), 1)
        self.assertEqual(len(self.cfg("SEC011", "server:\n  servlet:\n    session:\n      cookie:\n        http-only: false\n")), 1)
        self.assertEqual(self.cfg("SEC011", "server.servlet.session.cookie.secure=true\n", "application.properties"), [])
        code = "class C { void f(jakarta.servlet.http.Cookie c) { c.setHttpOnly(false); c.setSecure(false); } }"
        self.assertEqual(len(by_id(scan_files({"src/main/java/C.java": code}), "SEC011")), 2)
        ok = "class C { void f(jakarta.servlet.http.Cookie c) { c.setHttpOnly(true); c.setSecure(true); } }"
        self.assertEqual(by_id(scan_files({"src/main/java/C.java": ok}), "SEC011"), [])
        commented = "class C { // c.setHttpOnly(false);\n }"
        self.assertEqual(by_id(scan_files({"src/main/java/C.java": commented}), "SEC011"), [])

    def test_crlf_keeps_line_numbers(self):
        found = self.cfg("SEC010", "a: 1\r\nserver:\r\n  error:\r\n    include-stacktrace: always\r\n")
        self.assertEqual(found[0]["line"], 4)


if __name__ == "__main__":
    unittest.main()
