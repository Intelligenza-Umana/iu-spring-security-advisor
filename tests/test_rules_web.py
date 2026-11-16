import unittest

from helpers import scan_files


def run(rule, code, path="src/main/java/C.java"):
    return [f for f in scan_files({path: code}) if f["id"] == rule]


def wrap(body):
    return "class C { void f(Object http, Object cors) { " + body + " } }"


class Sec012And013(unittest.TestCase):
    def test_wildcard_with_credentials_is_high(self):
        for body in ['cfg.setAllowedOriginPatterns(List.of("*")); cfg.setAllowCredentials(true);',
                     'cfg.addAllowedOrigin("*"); cfg.setAllowCredentials(true);',
                     'r.addMapping("/**").allowedOrigins("*").allowCredentials(true);',
                     'r.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);']:
            found = run("SEC012", wrap(body))
            self.assertEqual(len(found), 1, body)
            self.assertEqual((found[0]["severity"], found[0]["category"]), ("high", "session_csrf_cors"))
            self.assertEqual(run("SEC013", wrap(body)), [], body)

    def test_explicit_origin_with_credentials_is_fine(self):
        body = 'cfg.setAllowedOrigins(List.of("https://app.example")); cfg.setAllowCredentials(true);'
        self.assertEqual(run("SEC012", wrap(body)) + run("SEC013", wrap(body)), [])

    def test_wildcard_without_credentials_is_low(self):
        found = run("SEC013", wrap('cfg.setAllowedOrigins(List.of("*"));'))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "low")
        self.assertEqual(run("SEC012", wrap('cfg.setAllowedOrigins(List.of("*"));')), [])

    def test_cross_origin_annotation(self):
        for ann in ["@CrossOrigin", "@CrossOrigin()", '@CrossOrigin("*")', '@CrossOrigin(origins = "*")',
                    "@CrossOrigin(maxAge = 3600)"]:
            self.assertEqual(len(run("SEC013", ann + " class C {}")), 1, ann)
        for ann in ['@CrossOrigin("https://app.example")', '@CrossOrigin(origins = "https://app.example")']:
            self.assertEqual(run("SEC013", ann + " class C {}"), [], ann)

    def test_comments_and_test_sources_are_ignored(self):
        body = '// cfg.addAllowedOrigin("*"); cfg.setAllowCredentials(true);'
        self.assertEqual(run("SEC012", wrap(body)), [])
        self.assertEqual(run("SEC012", wrap('cfg.addAllowedOrigin("*"); cfg.setAllowCredentials(true);'),
                             "src/test/java/CTest.java"), [])


class Sec014(unittest.TestCase):
    def test_catch_all_permit(self):
        for body in ["http.authorizeHttpRequests(a -> a.anyRequest().permitAll());",
                     'http.authorizeHttpRequests(a -> a.requestMatchers("/**").permitAll());']:
            found = run("SEC014", wrap(body))
            self.assertEqual(len(found), 1, body)
            self.assertEqual((found[0]["severity"], found[0]["category"]), ("high", "authorization"))

    def test_normal_rules_are_fine(self):
        for body in ["http.authorizeHttpRequests(a -> a.anyRequest().authenticated());",
                     'http.authorizeHttpRequests(a -> a.requestMatchers("/login").permitAll().anyRequest().authenticated());']:
            self.assertEqual(run("SEC014", wrap(body)), [], body)

    def test_commented_out_is_ignored(self):
        self.assertEqual(run("SEC014", wrap("// http.authorizeHttpRequests(a -> a.anyRequest().permitAll());")), [])


class Sec015(unittest.TestCase):
    def test_headers_disabled(self):
        for body in ["http.headers(h -> h.disable());", "http.headers().disable();",
                     "http.headers(AbstractHttpConfigurer::disable);",
                     "http.headers(h -> h.frameOptions(f -> f.disable()));",
                     "http.headers().frameOptions().disable();"]:
            found = run("SEC015", wrap(body))
            self.assertEqual(len(found), 1, body)
            self.assertEqual((found[0]["severity"], found[0]["category"]), ("medium", "headers_actuator"))

    def test_other_frame_options_are_fine(self):
        self.assertEqual(run("SEC015", wrap("http.headers(h -> h.frameOptions(f -> f.sameOrigin()));")), [])


if __name__ == "__main__":
    unittest.main()
