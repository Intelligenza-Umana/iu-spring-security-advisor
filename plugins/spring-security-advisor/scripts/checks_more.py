"""Rules added after 0.2: configuration files, web, tokens, passwords, data and refresh tokens.

Each check has the signature `check(project, rules) -> Iterator[dict]`, like the rules in scan.py.
"""
from __future__ import annotations

import re

from core import find_matching, line_of, make_finding
from signals import PATTERNS

SECRET_KEY = re.compile(r"secret|password|passwd|token|api-?key|private-?key|credential")
NON_SECRET_SUFFIXES = (
    "-expiration", "-ttl", "-validity", "-length", "-policy", "-enabled", "-header", "-prefix",
    "-uri", "-url", "-name", "-type", "-endpoint", "-algorithm",
)
NOT_A_SECRET_VALUE = re.compile(r"^(true|false|\d+(\.\d+)?)$", re.I)
PLACEHOLDER = re.compile(r"^\$\{[^}:]*(?::(.*))?\}$", re.S)
DEV_PROFILE = re.compile(r"^application-(dev|development|local|test|h2|sample|example)\b", re.I)


def _last_segment(key: str) -> str:
    return re.sub(r"\[\d+\]$", "", key.rsplit(".", 1)[-1])


def check_sec008(project, rules):
    for path, entries in project.config:
        dev = bool(DEV_PROFILE.match(path.name))
        for key, (value, line) in entries.items():
            last = _last_segment(key)
            if not SECRET_KEY.search(last) or last.endswith(NON_SECRET_SUFFIXES):
                continue
            value = value.strip()
            if not value or NOT_A_SECRET_VALUE.match(value) or value.startswith("{cipher}"):
                continue
            placeholder = PLACEHOLDER.match(value)
            if placeholder and not (placeholder.group(1) or "").strip():
                continue
            embedded_default = bool(placeholder)
            low = dev or embedded_default
            detail = (
                f"{key} has a placeholder with a literal default value." if embedded_default
                else f"{key} is set to a literal value."
            )
            yield make_finding(
                rules, "SEC008", project, path, line, detail,
                confidence="medium" if low else "high", severity="low" if low else None,
            )


def _config_items(project, key_base):
    for path, entries in project.config:
        for key, (value, line) in entries.items():
            if key == key_base or key.startswith(key_base + "["):
                yield path, key, value, line


def check_sec009(project, rules):
    for path, key, value, line in _config_items(project, "management.endpoints.web.exposure.include"):
        items = [v.strip().strip("\"'") for v in value.split(",")]
        if "*" in items:
            yield make_finding(rules, "SEC009", project, path, line, "All actuator endpoints are exposed over HTTP.", confidence="high")


def check_sec010(project, rules):
    for base in ("server.error.include-stacktrace", "spring.web.error.include-stacktrace"):
        for path, key, value, line in _config_items(project, base):
            if value.strip().lower() == "always":
                yield make_finding(rules, "SEC010", project, path, line, f"{key} is set to always.")


COOKIE_KEYS = (
    "server.servlet.session.cookie.secure", "server.servlet.session.cookie.http-only",
    "server.reactive.session.cookie.secure", "server.reactive.session.cookie.http-only",
)
COOKIE_CODE = r"\.(?:setHttpOnly|setSecure|httpOnly|secure)\(\s*false\s*\)"


def check_sec011(project, rules):
    for base in COOKIE_KEYS:
        for path, key, value, line in _config_items(project, base):
            if value.strip().lower() == "false":
                yield make_finding(rules, "SEC011", project, path, line, f"{key} is false.")
    for path, _text, match, line in project.grep(COOKIE_CODE):
        yield make_finding(rules, "SEC011", project, path, line, f"{match.group(0)} turns a cookie protection off.")

# --------------------------------------------------------------------------- web rules

WILDCARD_ORIGIN_CALL = re.compile(
    r"\b(?:allowedOrigins|allowedOriginPatterns|addAllowedOrigin|addAllowedOriginPattern"
    r"|setAllowedOrigins|setAllowedOriginPatterns)\s*\("
)
CREDENTIALS_TRUE = re.compile(r"\b(?:allowCredentials|setAllowCredentials)\s*\(\s*true\s*\)")
CROSS_ORIGIN = re.compile(r"@CrossOrigin\b(?:\s*\(([^)]*)\))?")


def check_sec012_013(project, rules):
    """SEC012 (wildcard origin with credentials) and SEC013 (wildcard origin) share the detection."""
    for path, text in project.java:
        credentials = bool(CREDENTIALS_TRUE.search(text))
        for call in WILDCARD_ORIGIN_CALL.finditer(text):
            args = text[call.end() : find_matching(text, call.end() - 1)]
            if not re.search(r'"\*"', args):
                continue
            line = line_of(text, call.start())
            if credentials:
                yield make_finding(
                    rules, "SEC012", project, path, line,
                    "A wildcard origin is allowed and credentials are enabled in the same file.",
                )
            else:
                yield make_finding(rules, "SEC013", project, path, line, "A wildcard origin is allowed for CORS.")
    for path, text, match, line in project.grep(CROSS_ORIGIN.pattern):
        args = (match.group(1) or "").strip()
        specific = bool(re.search(r"\b(?:origins|originPatterns|value)\s*=|^\s*\"", args)) and '"*"' not in args
        if not specific:
            yield make_finding(rules, "SEC013", project, path, line, "@CrossOrigin allows every origin.")


def check_sec012(project, rules):
    return (f for f in check_sec012_013(project, rules) if f["id"] == "SEC012")


def check_sec013(project, rules):
    return (f for f in check_sec012_013(project, rules) if f["id"] == "SEC013")


CATCH_ALL_PERMIT = (
    r"\.anyRequest\s*\(\s*\)\s*\.permitAll\s*\(\s*\)"
    r'|\.(?:requestMatchers|antMatchers|mvcMatchers)\s*\(\s*"/\*\*"\s*\)\s*\.permitAll\s*\(\s*\)'
)


def check_sec014(project, rules):
    for path, _text, match, line in project.grep(CATCH_ALL_PERMIT):
        yield make_finding(rules, "SEC014", project, path, line, f"{' '.join(match.group(0).split())} permits every request without authentication.")


HEADERS_DISABLED = (
    r"\.headers\s*\(\s*(\w+)\s*->\s*\1\s*\.disable\s*\(\s*\)\s*\)"
    r"|\.headers\s*\(\s*\)\s*\.disable\s*\(\s*\)"
    r"|\.headers\s*\(\s*AbstractHttpConfigurer\s*::\s*disable\s*\)"
    r"|\.frameOptions\s*\(\s*(\w+)\s*->\s*\2\s*\.disable\s*\(\s*\)\s*\)"
    r"|\.frameOptions\s*\(\s*\)\s*\.disable\s*\(\s*\)"
)


def check_sec015(project, rules):
    for path, _text, match, line in project.grep(HEADERS_DISABLED):
        yield make_finding(
            rules, "SEC015", project, path, line,
            "Security response headers (or only X-Frame-Options) are disabled. This is sometimes needed for the H2 console in development.",
        )


# --------------------------------------------------------------------------- tokens and passwords

UNSECURED_JWT = r"\.(?:parseClaimsJwt|parseUnsecuredClaims|parseUnsecuredContent|unsecured)\s*\("


def check_sec016(project, rules):
    for path, _text, match, line in project.grep(UNSECURED_JWT):
        name = match.group(0).strip(" .(")
        yield make_finding(rules, "SEC016", project, path, line, f"{name}() accepts a JWT without verifying a signature.")


def check_sec017(project, rules):
    for path, text in project.java:
        builder = re.search(r"\bJwts\s*\.\s*builder\s*\(", text)
        if builder and not re.search(r"\.(?:expiration|setExpiration)\s*\(", text):
            yield make_finding(
                rules, "SEC017", project, path, line_of(text, builder.start()),
                "Jwts.builder() is used and no expiration claim is set anywhere in this file.",
                confidence="medium",
            )


DEPRECATED_ENCODER = r"\bnew\s+(?:StandardPasswordEncoder|Md4PasswordEncoder|MessageDigestPasswordEncoder|LdapShaPasswordEncoder)\s*\("


def check_sec018(project, rules):
    for path, _text, match, line in project.grep(DEPRECATED_ENCODER):
        name = match.group(0).replace("new", "").strip(" (")
        yield make_finding(rules, "SEC018", project, path, line, f"{name} is a deprecated digest-based encoder.")


WEAK_DIGEST = r'MessageDigest\s*\.\s*getInstance\(\s*"(?:MD5|SHA-?1|MD2)"\s*\)'


def check_sec019(project, rules):
    for path, text, match, line in project.grep(WEAK_DIGEST):
        if "password" in text.lower():
            yield make_finding(
                rules, "SEC019", project, path, line,
                "A weak digest (MD5/SHA-1) is used in a file that handles passwords.", confidence="medium",
            )


def check_sec020(project, rules):
    for path, text, match, line in project.grep(r"\bnew\s+BCryptPasswordEncoder\s*\(([^)]*)\)"):
        parts = [p.strip() for p in match.group(1).split(",")]
        cost = next((int(p) for p in parts if p.isdigit()), None)
        if cost is not None and cost < 10:
            yield make_finding(rules, "SEC020", project, path, line, f"BCryptPasswordEncoder strength {cost} is below the default of 10.")


SECRET_RELATED_PATH = re.compile(r"token|otp|reset|secret|session|password|verification")
INSECURE_RANDOM = r"\bnew\s+Random\s*\(|\bMath\s*\.\s*random\s*\(|\bThreadLocalRandom\b"


def check_sec021(project, rules):
    for path, _text, match, line in project.grep(INSECURE_RANDOM):
        if SECRET_RELATED_PATH.search(project.rel(path).lower()):
            yield make_finding(
                rules, "SEC021", project, path, line,
                f"{match.group(0).strip()} is not cryptographically secure and this class looks secret-related.",
                confidence="medium",
            )


# --------------------------------------------------------------------------- data

SQL_CALL = re.compile(
    r"\.(?:createNativeQuery|createQuery|query|queryForObject|queryForList|queryForMap|queryForRowSet"
    r"|update|batchUpdate|execute|executeQuery|executeUpdate)\s*\("
)
SQL_KEYWORD = re.compile(r"(?i)\b(?:select|insert|update|delete|from|where|call)\b")
STRING_LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"')


def _first_argument(args: str) -> str:
    depth, i = 0, 0
    while i < len(args):
        c = args[i]
        if c == '"':
            i += 1
            while i < len(args) and args[i] != '"':
                i += 2 if args[i] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            return args[:i]
        i += 1
    return args


def _is_dynamic_sql(first: str) -> bool:
    literals = STRING_LITERAL.findall(first)
    if not literals or not any(SQL_KEYWORD.search(lit) for lit in literals):
        return False
    rest = STRING_LITERAL.sub('""', first)
    if re.match(r"\s*String\s*\.\s*format\s*\(", rest) or ".formatted(" in rest:
        return True
    return "+" in rest and bool(re.search(r"[A-Za-z_]", rest.replace("String", "")))


def check_sec022(project, rules):
    for path, text in project.java:
        for call in SQL_CALL.finditer(text):
            args = text[call.end() : find_matching(text, call.end() - 1)]
            if _is_dynamic_sql(_first_argument(args)):
                yield make_finding(
                    rules, "SEC022", project, path, line_of(text, call.start()),
                    "The SQL text is built with string concatenation or formatting instead of bind parameters.",
                    confidence="medium",
                )


# --------------------------------------------------------------------------- refresh tokens

REFRESH_RE = re.compile(PATTERNS["refresh_token"])
LOCKING_RE = re.compile(PATTERNS["locking"])
LOOKUP_THEN_REVOKE = re.compile(
    r"\.(?:find|get|load|read)\w*\s*\(.*?\.(?:save|saveAndFlush|delete\w*|revoke\w*|setRevoked|remove\w*)\s*\(",
    re.S,
)


def check_sec023(project, rules):
    refresh_files = [(path, text) for path, text in project.java if REFRESH_RE.search(text)]
    if not refresh_files or any(LOCKING_RE.search(text) for _path, text in refresh_files):
        return
    for path, text in refresh_files:
        match = LOOKUP_THEN_REVOKE.search(text)
        if match:
            yield make_finding(
                rules, "SEC023", project, path, line_of(text, match.start()),
                "A refresh token is looked up and then revoked or replaced, and no lock, version column or "
                "atomic update was found on the refresh path: two concurrent requests could both succeed.",
                confidence="medium",
            )


CHECKS_MORE = {
    "SEC008": check_sec008,
    "SEC009": check_sec009,
    "SEC010": check_sec010,
    "SEC011": check_sec011,
    "SEC012": check_sec012,
    "SEC013": check_sec013,
    "SEC014": check_sec014,
    "SEC015": check_sec015,
    "SEC016": check_sec016,
    "SEC017": check_sec017,
    "SEC018": check_sec018,
    "SEC019": check_sec019,
    "SEC020": check_sec020,
    "SEC021": check_sec021,
    "SEC022": check_sec022,
    "SEC023": check_sec023,
}
