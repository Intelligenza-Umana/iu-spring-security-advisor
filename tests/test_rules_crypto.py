import unittest

from helpers import scan_files


def run(rule, code, path="src/main/java/C.java"):
    return [f for f in scan_files({path: code}) if f["id"] == rule]


def wrap(body, name="C"):
    return f"class {name} {{ void f() {{ {body} }} }}"


class Sec016(unittest.TestCase):
    def test_unsigned_parsing(self):
        for body in ["Jwts.parser().build().parseClaimsJwt(t);", "p.parseUnsecuredClaims(t);",
                     "p.parseUnsecuredContent(t);", "Jwts.parser().unsecured().build();"]:
            found = run("SEC016", wrap(body))
            self.assertEqual(len(found), 1, body)
            self.assertEqual((found[0]["severity"], found[0]["category"]), ("high", "tokens"))

    def test_signed_parsing_is_fine(self):
        self.assertEqual(run("SEC016", wrap("Jwts.parser().verifyWith(k).build().parseSignedClaims(t);")), [])

    def test_comment_and_tests_ignored(self):
        self.assertEqual(run("SEC016", wrap("// p.parseUnsecuredClaims(t);")), [])
        self.assertEqual(run("SEC016", wrap("p.parseUnsecuredClaims(t);"), "src/test/java/CTest.java"), [])


class Sec017(unittest.TestCase):
    def test_builder_without_expiration(self):
        found = run("SEC017", wrap('String s = Jwts.builder().subject("u").signWith(k).compact();'))
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["severity"], found[0]["confidence"], found[0]["category"]),
                         ("medium", "medium", "tokens"))

    def test_builder_with_expiration_is_fine(self):
        for exp in [".expiration(new Date())", ".setExpiration(d)"]:
            self.assertEqual(run("SEC017", wrap(f"String s = Jwts.builder(){exp}.signWith(k).compact();")), [])


class Sec018And019(unittest.TestCase):
    def test_deprecated_encoders(self):
        for enc in ["StandardPasswordEncoder", "Md4PasswordEncoder", "MessageDigestPasswordEncoder", "LdapShaPasswordEncoder"]:
            found = run("SEC018", wrap(f'Object e = new {enc}("x");'))
            self.assertEqual(len(found), 1, enc)
            self.assertEqual((found[0]["severity"], found[0]["category"]), ("high", "passwords"))

    def test_adaptive_encoders_are_fine(self):
        for enc in ["BCryptPasswordEncoder()", "Argon2PasswordEncoder(16, 32, 1, 1 << 14, 3)", "Pbkdf2PasswordEncoder(\"s\", 16, 310000, 256)"]:
            self.assertEqual(run("SEC018", wrap(f"Object e = new {enc};")), [])

    def test_md5_near_passwords(self):
        near = wrap('String password = "x"; var d = MessageDigest.getInstance("MD5");')
        found = run("SEC019", near)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["severity"], found[0]["confidence"]), ("medium", "medium"))
        self.assertEqual(len(run("SEC019", wrap('String password = "x"; var d = MessageDigest.getInstance("SHA-1");'))), 1)

    def test_md5_elsewhere_and_sha256_are_fine(self):
        self.assertEqual(run("SEC019", wrap('var d = MessageDigest.getInstance("MD5");')), [])
        self.assertEqual(run("SEC019", wrap('String password = "x"; var d = MessageDigest.getInstance("SHA-256");')), [])


class Sec020(unittest.TestCase):
    def test_low_cost(self):
        found = run("SEC020", wrap("Object e = new BCryptPasswordEncoder(4);"))
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["severity"], found[0]["category"]), ("low", "passwords"))

    def test_default_high_and_non_literal_are_fine(self):
        for arg in ["", "10", "12", "cost", "BCryptVersion.$2A, 12"]:
            self.assertEqual(run("SEC020", wrap(f"Object e = new BCryptPasswordEncoder({arg});")), [], arg)

    def test_version_plus_low_cost(self):
        self.assertEqual(len(run("SEC020", wrap("Object e = new BCryptPasswordEncoder(BCryptVersion.$2A, 5);"))), 1)


class Sec021(unittest.TestCase):
    def test_insecure_random_in_secret_related_class(self):
        for name, body in [("TokenService", "var r = new Random();"), ("ResetCodes", "double d = Math.random();"),
                           ("OtpGenerator", "int n = ThreadLocalRandom.current().nextInt();")]:
            found = run("SEC021", wrap(body, name), f"src/main/java/{name}.java")
            self.assertEqual(len(found), 1, name)
            self.assertEqual((found[0]["severity"], found[0]["confidence"]), ("medium", "medium"))

    def test_unrelated_class_and_secure_random_are_fine(self):
        self.assertEqual(run("SEC021", wrap("var r = new Random();", "ReportService"), "src/main/java/ReportService.java"), [])
        self.assertEqual(run("SEC021", wrap("var r = new SecureRandom();", "TokenService"), "src/main/java/TokenService.java"), [])


if __name__ == "__main__":
    unittest.main()
