# spring-security-advisor 1.0.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the scanner into a repository audit with about 24 rules, mechanism signals, a guided checklist, a deterministic 0-100 score and a new `audit` skill.

**Architecture:** `scan.py` stays the CLI entry point and keeps exporting what the tests already import. Shared helpers move to `core.py` (mechanical extraction). New logic lives in focused modules: `config_reader.py`, `checks_more.py` (new rules), `signals.py`, `scoring.py`. The model's judgment enters only through an answers file that `scoring.py` validates and turns into a score.

**Tech Stack:** Python 3 standard library, JSON data files, markdown skills, `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-16-spring-security-advisor-1.0-design.md`

## Global Constraints

- Python 3 standard library only. No PyYAML, no network, no JDK/Maven. Source files are only read.
- Existing JSON output (`findings`, `scope`, `detected`, `notes`, `limits`) stays compatible; fields are only added.
- Every rule and every checklist item needs `"status": "V"` and a `"checked"` date, set **only after** the source was verified (for example with Context7 or the official page). A rule whose source cannot be verified is dropped, not released with a guess. The existing test `test_unverified_rules_are_not_released` enforces this for rules; Task 7 adds it for checklist items.
- Secret values are never printed in findings, signals or reports: only file and line.
- Skills are read-only on the project. The answers file is written to a temp or scratchpad directory, never into the project.
- Score constants (from the spec, approved): finding penalty high 20 / medium 10 / low 3, repeats of the same rule id weigh 25% after the first; item points yes = full weight, partial = half, no = 0; caps 69 (a high "certain bug" finding) and 79 (a weight-3 item answered `no`); grades A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below; coverage under 70% means *provisional*.
- Version `1.0.0` in `scan.py` (`VERSION`) and `plugin.json`.
- Work on branch `ccr-8058e74e-hy0f34`, never on `main`; commit after each task (Fabio's stop hook requires committed and pushed work).

## Review Focus

- Config values written as `${ENV_VAR}`, empty, or numeric/boolean must not be reported as secrets (Task 2).
- `application.yml` with nested keys, quoted values, `#` comments and list items: the key flattening must not crash and must not invent keys (Task 2).
- A project with no Java sources or no config: `score` must return a result with `coverage` 0 and `provisional` true, not divide by zero (Task 7).
- An answers file with an unknown item id, a duplicated id, an evidence path outside the project (`../x`, absolute) or a line past the end of the file: warnings and downgrade, never a crash or a silent `yes` (Task 7).
- Test sources must never produce findings or signals (Tasks 4, 6).
- Unicode and CRLF files: line numbers must stay correct (Task 2).

## File Structure

| File | Responsibility |
|---|---|
| `scripts/core.py` | `Project`, `strip_comments`, `find_matching`, `line_of`, `is_test_path`, `make_finding`, `load_rules`, `ScanError`, constants. Moved out of `scan.py`. |
| `scripts/config_reader.py` | `read_config(path: Path) -> dict[str, tuple[str, int]]`: flat key to (value, line) for `application*.properties` and `application*.yml`. |
| `scripts/checks_more.py` | `CHECKS_MORE: dict[str, Callable[[Project, dict], Iterator[dict]]]` for SEC008 to SEC024. |
| `scripts/signals.py` | `collect_signals(project) -> dict[str, list[dict]]`. |
| `scripts/scoring.py` | Pure functions: `validate_answers`, `compute_score`, `format_score_text`. |
| `scripts/scan.py` | CLI (`scan`, `map`, `checklist`, `score`), orchestration; re-exports the names tests use. |
| `rules/rules.json` | Rules; each gets a `category` field. |
| `checklists/checklist.json` | Category weights and checklist items. |
| `skills/audit/SKILL.md` | New main skill. `review` and `map` get small edits. |
| `tests/helpers.py` | `scan_files(files: dict[str, str]) -> list[dict]` (writes a temp project with those relative paths and returns findings) and `signals_for(files) -> dict`. |

Rule categories: `authentication`, `tokens`, `authorization`, `session_csrf_cors`, `passwords`, `rate_limiting`, `secrets_config`, `headers_actuator`, `data_logging`. (`data_logging` is the ninth category, added to hold SQL concatenation and sensitive logging; the spec listed eight.)

---

### Task 1: Extract `core.py` (no behavior change)

**Files:** Create `scripts/core.py`; Modify `scripts/scan.py`.

**Interfaces:**
- Produces: `core` exports exactly the names listed in File Structure, plus `SKIP_DIRS`, `SEVERITY_ORDER`, `LIMITS`, `RULES_FILE`. `scan.py` imports them by name so that `scan.strip_comments`, `scan.find_matching`, `scan.Project`, `scan.run_scan`, `scan.run_map`, `scan.CHECKS` keep working.

- [ ] **Step 1: Run** `python3 -m unittest discover -s tests -v` and keep the result as the baseline (all pass).
- [ ] **Step 2: Move** the helper section, `Project`, `make_finding`, `ScanError`, constants from `scan.py` into `core.py` without changing their bodies; import them back in `scan.py`.
- [ ] **Step 3: Run** the suite. Expected: identical to the baseline.
- [ ] **Step 4: Add** `tests/helpers.py` with `scan_files` and `signals_for`; `signals_for` is implemented in Task 6 (raise `NotImplementedError` for now).
- [ ] **Step 5: Commit** `git add -A && git commit -m "refactor: extract core helpers from scan.py"`.

---

### Task 2: Config reader and config rules (SEC008 to SEC011)

**Files:** Create `scripts/config_reader.py`, `tests/test_config_rules.py`; Modify `scripts/core.py` (`Project.config`), `scripts/checks_more.py` (create), `scripts/scan.py` (register `CHECKS_MORE`), `rules/rules.json`.

**Interfaces:**
- Produces: `read_config(path) -> dict[str, tuple[str, int]]` (keys lower-cased, dotted; yml nesting joined with `.`; list items get `key[0]`, `key[1]`; quotes stripped; trailing `# comment` removed outside quotes; CRLF tolerated). `Project.config: list[tuple[Path, dict[str, tuple[str, int]]]]` for each `application*.properties|yml|yaml` outside test dirs. `core.make_finding` accepts the same arguments as now and adds `"category"` from the rule.

- [ ] **Step 1: Write failing tests** (`tests/test_config_rules.py`, using `scan_files`):
  - reader: nested yml, quoted value, inline comment, `key: ${X}`, list item, CRLF, empty file, key with no value.
  - SEC008 (secret literal in config, category `secrets_config`): reported for `jwt.secret=abc123`, `spring.datasource.password: hunter2`, `app.api-key=k`; **not** reported for `${JWT_SECRET}`, `${DB_PASS:}`, empty value, `jwt.secret-expiration=3600`, key `password-policy.min-length=8`; in `application-dev.yml`/`-local`/`-test` the finding has severity `low` and confidence `medium`; the finding detail never contains the value.
  - SEC009 (`management.endpoints.web.exposure.include` containing `*`, medium, `headers_actuator`): positive for `*` and `"*"`; negative for `health,info`.
  - SEC010 (`server.error.include-stacktrace` equal to `always`, medium, `headers_actuator`): positive/negative.
  - SEC011 (cookies, medium, `session_csrf_cors`): positive for `server.servlet.session.cookie.secure=false`, `...http-only=false`, and Java `setHttpOnly(false)` / `setSecure(false)`; negative for `true`.
  - `fixed` fixture still has no findings.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_config_rules -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `read_config` (line-based, indentation stack for yml, no external parser), the `Project.config` loading, `check_sec008` to `check_sec011` in `checks_more.py`, and `CHECKS_MORE`. Secret key match: key's last segment matches `secret|password|passwd|token|api-?key|private-?key|credential` and value is non-empty, not `${...}`, not purely numeric/boolean, and the last segment does not end in `-expiration|-ttl|-validity|-length|-policy|-enabled`.
- [ ] **Step 4: Add** the four rules to `rules.json` with `category`, `risk`, `fix`, `source`, `status`, `checked`. Verify each source against the official docs first (Spring Boot reference: externalized configuration, actuator endpoints exposure, `server.error.include-stacktrace`, cookie properties; OWASP Secrets Management cheat sheet). Add `category` to SEC001 to SEC007 (SEC001 `passwords`; SEC002, SEC003, SEC004 `authorization`; SEC005 `session_csrf_cors`; SEC006, SEC007 `tokens`). Add a test `test_every_rule_has_known_category`.
- [ ] **Step 5: Run** the full suite. Expected: pass.
- [ ] **Step 6: Commit** `git commit -am "feat: config reader and rules SEC008-SEC011"`.

---

### Task 3: Web rules (SEC012 to SEC015)

**Files:** Modify `scripts/checks_more.py`, `rules/rules.json`; Create `tests/test_rules_web.py`.

- [ ] **Step 1: Write failing tests** (`scan_files` snippets):

  | Rule | Cat. | Sev. | Positive | Negative |
  |---|---|---|---|---|
  | SEC012 wildcard origin **with** credentials (type risk to evaluate) | session_csrf_cors | high | `allowedOriginPatterns("*")` or `allowedOrigins("*")` or `addAllowedOrigin("*")` and `allowCredentials(true)` / `setAllowCredentials(true)` in the same file | explicit origin with credentials; wildcard without credentials (that is SEC013) |
  | SEC013 wildcard origin without credentials | session_csrf_cors | low | `@CrossOrigin` with no args or `"*"`; wildcard origin with no credentials call | `@CrossOrigin("https://app.example")` |
  | SEC014 catch-all permit | authorization | high | `.anyRequest().permitAll()`; `.requestMatchers("/**").permitAll()` | `anyRequest().authenticated()`; `permitAll()` on `"/login"` |
  | SEC015 headers disabled | headers_actuator | medium | `.headers(h -> h.disable())`, `.frameOptions(f -> f.disable())`, `.frameOptions().disable()` | `frameOptions(f -> f.sameOrigin())` |

  Every rule: a test that the same code inside a `//` comment and inside `src/test` is not reported. SEC012 and SEC013 must not both fire on the same line.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** `check_sec012` to `check_sec015` with `project.grep`, reusing `find_matching` for argument text.
- [ ] **Step 4: Add rules** to `rules.json` after verifying sources (Spring Security reference: CORS, `CorsConfiguration` Javadoc, authorization, headers; OWASP CORS guidance).
- [ ] **Step 5: Run** full suite. Expected: pass; `fixed` and `stateless-api` fixtures unchanged.
- [ ] **Step 6: Commit** `git commit -am "feat: web rules SEC012-SEC015"`.

---

### Task 4: Token and password rules (SEC016 to SEC021)

**Files:** Modify `scripts/checks_more.py`, `rules/rules.json`; Create `tests/test_rules_crypto.py`.

- [ ] **Step 1: Write failing tests:**

  | Rule | Cat. | Sev. / type | Positive | Negative |
  |---|---|---|---|---|
  | SEC016 unsigned JWT parsing | tokens | high / certain bug | `parseClaimsJwt(`, `parseUnsecuredClaims(`, `parseUnsecuredContent(`, `.unsecured()` | `parseSignedClaims(` |
  | SEC017 JWT built without expiration (confidence medium) | tokens | medium / risk | file with `Jwts.builder()` and no `.expiration(`/`.setExpiration(`; file with `new JWTClaimsSet.Builder()` and no `.expirationTime(` | builder with expiration |
  | SEC018 deprecated or weak encoders | passwords | high / certain bug | `new StandardPasswordEncoder`, `Md4PasswordEncoder`, `MessageDigestPasswordEncoder`, `LdapShaPasswordEncoder` | `BCryptPasswordEncoder`, `Argon2PasswordEncoder`, `DelegatingPasswordEncoder` |
  | SEC019 MD5/SHA-1 near passwords (confidence medium) | passwords | medium / risk | `MessageDigest.getInstance("MD5")` or `"SHA-1"` in a file whose text contains `password` | same call in a file with no `password`; `"SHA-256"` |
  | SEC020 low bcrypt cost | passwords | low / improvement | `new BCryptPasswordEncoder(4)` (literal below 10) | `new BCryptPasswordEncoder()`, `(12)`, non-literal argument |
  | SEC021 non-secure randomness for secrets (confidence medium) | tokens | medium / risk | `new Random(` or `Math.random(` in a main source whose path or class name matches `token|otp|reset|secret|session|password|verification` | same in `ReportService.java`; `new SecureRandom()` |

  Tests must also pin comment and test-source exclusion, and that SEC016 does not fire on `parseSignedClaims`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** `check_sec016` to `check_sec021`. SEC017 checks the whole file text per builder occurrence.
- [ ] **Step 4: Add rules** to `rules.json` after verifying sources (jjwt documentation for the parser methods and expiration; RFC 7519 `exp`; Spring Security API reference for the encoder classes and `BCryptPasswordEncoder` default strength; OWASP Password Storage cheat sheet; Java `SecureRandom` Javadoc). Drop any rule whose source cannot be verified.
- [ ] **Step 5: Run** full suite. Expected: pass.
- [ ] **Step 6: Commit** `git commit -am "feat: token and password rules SEC016-SEC021"`.

---

### Task 5: Data and logging rules (SEC022, SEC023)

**Files:** Modify `scripts/checks_more.py`, `rules/rules.json`; Create `tests/test_rules_data.py`.

- [ ] **Step 1: Write failing tests:**
  - SEC022 SQL built by concatenation (`data_logging`, high, risk, confidence medium): positive for `createNativeQuery("select ... " + name)`, `createQuery("..." + x)`, `jdbcTemplate.query("..." + x, ...)`, `jdbcTemplate.update`, `stmt.executeQuery("..." + x)`; negative for a literal-only argument, for `?`/`:name` parameters, and for a concatenation of two string literals only.
  - SEC023 sensitive data in log calls (`data_logging`, medium, risk, confidence medium): positive for `log.info("login " + password)`, `log.debug("token={}", token)`, `logger.error(..., authorizationHeader)`; negative for `log.info("password reset requested")` (word only inside a string literal with no variable), `log.info("user {}", username)`.
  - The finding detail never includes the logged expression's value.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** `check_sec022`, `check_sec023`. SEC023: parse the call arguments with `find_matching`, remove string literals, then look for identifiers matching `(?i)password|passwd|secret|token|authorization|apikey`.
- [ ] **Step 4: Add rules** (sources: OWASP SQL Injection Prevention and Logging cheat sheets, Spring Framework `JdbcTemplate` reference). 
- [ ] **Step 5: Run** full suite. Expected: pass.
- [ ] **Step 6: Commit** `git commit -am "feat: data and logging rules SEC022-SEC023"`.

---

### Task 6: Signals and the refresh-token rule (SEC024)

**Files:** Create `scripts/signals.py`, `tests/test_signals.py`, fixtures `tests/fixtures/refresh-race/` and `tests/fixtures/refresh-safe/`; Modify `scripts/checks_more.py`, `scripts/scan.py` (`run_scan` adds `"signals"`), `tests/helpers.py` (`signals_for`), `rules/rules.json`.

**Interfaces:**
- Produces: `collect_signals(project) -> dict[str, list[dict]]`, each entry `{"file","line","text"}` (text is the matched token only, never a line of config values). Signal names (stable): `rate_limiting`, `login_throttling`, `refresh_token`, `token_revocation`, `locking`, `jwt_validation`, `password_reset`, `input_validation`, `logout`, `audit_events`. All keys always present, possibly empty lists.

Patterns: `rate_limiting` = `Bucket4j|Bucket\b|RateLimiter|RequestRateLimiter|\bRateLimit\w*|@RateLimit`; `login_throttling` = `LockedException|failedAttempts|failed_attempts|AuthenticationFailureBadCredentialsEvent|loginAttempt\w*`; `refresh_token` = `(?i)refresh[-_ ]?token` in class names, identifiers or JSON keys; `token_revocation` = `(?i)revoke\w*|blacklist\w*|denylist\w*|tokenFamily|jti`; `locking` = `@Lock\b|PESSIMISTIC_WRITE|PESSIMISTIC_READ|@Version\b|FOR UPDATE|OptimisticLock\w*|@Modifying|@Table\([^)]*uniqueConstraints|unique\s*=\s*true`; `jwt_validation` = `JwtDecoder|JwtValidators|JwtTimestampValidator|JwtIssuerValidator|OAuth2TokenValidator|parseSignedClaims|requireIssuer|requireAudience`; `password_reset` = `(?i)password[-_ ]?reset|reset[-_ ]?token|forgot[-_ ]?password`; `input_validation` = `@Valid\b|@Validated\b`; `logout` = `\.logout\s*\(|LogoutHandler|LogoutSuccessHandler|/logout`; `audit_events` = `AuthenticationSuccessEvent|AuthenticationFailure\w*Event|AuthorizationDeniedEvent|AuditEvent`. Only main sources are searched.

- [ ] **Step 1: Create fixtures.** `refresh-race`: `pom.xml` (Boot 3.5.0), `RefreshService.java` that does `repo.findByToken(t)`, checks `revoked`, then `repo.save` a new token and sets `revoked = true` with no lock or atomic update, `RefreshTokenRepository.java` without `@Lock`, `application.yml` with a literal `jwt.secret`. `refresh-safe`: same service using a repository method annotated `@Lock(LockModeType.PESSIMISTIC_WRITE)` and a `RateLimitFilter.java` that uses `Bucket`; `application.yml` with `jwt.secret: ${JWT_SECRET}`.
- [ ] **Step 2: Write failing tests:** every signal name is present in the output; `signals_for` on `refresh-race` has `refresh_token` non-empty and `locking` empty and `rate_limiting` empty; on `refresh-safe` `locking` and `rate_limiting` non-empty; signals in `src/test` are ignored; `run_scan(...)["signals"]` exists; SEC024 (`tokens`, medium, risk to evaluate, confidence medium) fires on `refresh-race` at the `findByToken`-then-revoke site and not on `refresh-safe`; SEC024 does not fire when the project has no `refresh_token` signal. Existing fixture tests (`vulnerable` exact id list, `fixed` empty) still pass.
- [ ] **Step 3: Run.** Expected: FAIL.
- [ ] **Step 4: Implement** `collect_signals`, wire into `run_scan`, implement `check_sec024`: in a main source whose text matches the `refresh_token` pattern, a `find*`/`get*`/`load*` call on a repository, followed in the same method by `save(`/`delete(`/`revoke`/`setRevoked`, and **no** `locking` pattern in the same file or in the repository interface it uses → one finding at the lookup line.
- [ ] **Step 5: Add SEC024** to `rules.json` after verifying sources (RFC 6819 section 5.2.2.3 on refresh token rotation; OAuth 2.0 Security Best Current Practice RFC 9700 on refresh token replay; Spring Data JPA locking reference). Update `map` to include the `signals` section.
- [ ] **Step 6: Run** full suite. Expected: pass.
- [ ] **Step 7: Commit** `git add -A && git commit -m "feat: signals and SEC024 refresh token race rule"`.

---

### Task 7: Checklist and scoring

**Files:** Create `checklists/checklist.json`, `scripts/scoring.py`, `tests/test_scoring.py`, `tests/fixtures/answers/` (small JSON files used by the tests); Modify `scripts/scan.py` (`checklist` and `score` subcommands).

**Interfaces:**
- `checklist.json`: `{"categories": {<id>: {"label": str, "weight": int}}, "items": [{"id","category","weight","question","look_for","signals": [str],"source","status","checked"}]}`.
- Category weights: tokens 20, authorization 20, authentication 15, rate_limiting 10, passwords 10, session_csrf_cors 10, secrets_config 8, headers_actuator 4, data_logging 3.
- Answers file: `{"answers": [{"id": str, "answer": "yes"|"partial"|"no"|"not_applicable"|"cannot_determine", "evidence": [str], "note": str}]}`, evidence entries are `relative/path.java:LINE`.
- `scoring.validate_answers(answers_doc: dict, items: list[dict], root: Path) -> tuple[dict[str, dict], list[str]]` returns the effective answer per item id (unanswered items become `cannot_determine`) and warnings (unknown ids, duplicates where the last one wins, downgrades with their reason). `yes` and `partial` need at least one evidence entry where the path stays inside `root`, the file exists, and `1 <= line <= number of lines`; otherwise the effective answer is `cannot_determine`.
- `scoring.compute_score(findings: list[dict], effective: dict[str, dict], checklist: dict, rules: dict) -> dict` returns `{"total": int|None, "grade": str|None, "provisional": bool, "coverage": float, "caps_applied": [str], "categories": {id: {"score": int|None, "basis": "checklist"|"rules_only"|"none", "earned","available","penalty"}}, "top_actions": [..up to 5, each {"kind","id","impact": int,"detail"}], "warnings": [...]}`. Category score = `round(100*earned/available) - penalty`, floored at 0, when `available > 0`; with `available == 0` and findings the score is `max(0, 100 - penalty)` with basis `rules_only`; with neither, `None` and excluded. Total = weight-average of included categories, rounded, then capped. `impact` = total with that item fixed minus current total.
- CLI: `scan.py checklist` prints the checklist JSON. `scan.py score <path> --answers <file> [--baseline <file>] [--save] [--format json|text]` (text format via `scoring.format_score_text(result) -> str`). `--baseline` adds `"delta": {"total": int, "categories": {id: int}}`. `--save` writes `<path>/.spring-security-advisor/last-audit.json`.

Checklist items to write (ids, category, weight; one `question` and one `look_for` each, with the signals in brackets):
TOK-01 access token lifetime at most 60 min, 2 [jwt_validation]; TOK-02 refresh token is single-use with rotation, 3 [refresh_token]; TOK-03 refresh token stored hashed, 2 [refresh_token]; TOK-04 reuse of a used refresh token revokes the family, 2 [refresh_token, token_revocation]; TOK-05 refresh check-and-revoke is atomic against concurrent requests, 3 [refresh_token, locking]; TOK-06 logout revokes refresh and session tokens, 2 [logout, token_revocation]; TOK-07 validation pins the algorithm and enforces `exp`, 3 [jwt_validation]; TOK-08 issuer and audience validated, 2 [jwt_validation]; TOK-09 signing key from configuration or a secret store, 3 []; TOK-10 tokens not accepted in query strings or logged, 1 []; AUTH-01 failed logins are throttled or locked out, 3 [login_throttling]; AUTH-02 login errors do not reveal whether the user exists, 2 []; AUTH-03 reset tokens are single-use, expiring and hashed, 3 [password_reset]; AUTH-04 password change requires the current password, 1 []; RATE-01 global API rate limit, 2 [rate_limiting]; RATE-02 login has its own stricter limit, 3 [rate_limiting]; RATE-03 refresh, reset and registration are limited, 2 [rate_limiting]; RATE-04 limit key cannot be spoofed through forwarded headers, 1 [rate_limiting]; AUTHZ-01 deny by default, 3 []; AUTHZ-02 ownership checked on endpoints that take an id (IDOR), 3 []; AUTHZ-03 sensitive service methods protected by method security, not only URLs, 2 []; AUTHZ-04 request binding uses DTOs, not entities (mass assignment), 2 []; AUTHZ-05 roles never come from client-controlled data, 3 []; SESS-01 cookies used for auth are Secure, HttpOnly, SameSite, 2 []; SESS-02 CSRF protection matches the authentication model, 2 []; SESS-03 CORS allows only real origins, 2 []; PWD-01 adaptive encoder with upgrade support, 3 []; PWD-02 minimum length and no silent truncation, 1 []; CFG-01 secrets come from the environment or a secret store, 3 []; CFG-02 production configuration is separate from development, 1 []; CFG-03 actuator endpoints limited and secured, 2 []; HDR-01 security headers present (HSTS, nosniff, frame options), 1 []; HDR-02 HTTPS enforced or terminated upstream, 1 []; INPUT-01 request bodies validated, 2 [input_validation]; INPUT-02 error responses do not leak internals, 2 []; LOG-01 security events logged without secrets, 1 [audit_events]. Categories: TOK→tokens, AUTH→authentication, RATE→rate_limiting, AUTHZ→authorization, SESS→session_csrf_cors, PWD→passwords, CFG→secrets_config, HDR→headers_actuator, INPUT and LOG→data_logging.

- [ ] **Step 1: Write failing tests** (`tests/test_scoring.py`, pure functions plus CLI):
  - checklist file: ids unique; every item has all fields; weight in 1..3; category exists; every `signals` name is one of the ten signal names; every item has `status == "V"` and a `checked` date; the weights sum is 100.
  - `validate_answers`: `yes` without evidence becomes `cannot_determine` with a warning naming the item; evidence `../etc/passwd`, an absolute path, a missing file and a line past the end each downgrade; unknown id gives a warning and is ignored; duplicate id: last one wins plus a warning; unanswered items become `cannot_determine`; `no` without evidence is accepted.
  - `compute_score`: with all items `yes` (valid evidence) and no findings, total 100, grade `A`, coverage 1.0, not provisional; one weight-3 item `no` caps the total at 79; one high certain-bug finding caps at 69 (a finding of type `risk to evaluate` with severity high does not); both caps: 69 wins and `caps_applied` lists both; `partial` earns half; `not_applicable` leaves available points unchanged; three findings of the same rule in one category cost `20 + 5 + 5` for severity high; a category with no determinable items and no findings is `None` and excluded; coverage below 0.70 sets `provisional` true; empty project gives `total` `None`, coverage 0.0 and provisional true without raising; `top_actions` has at most 5 entries sorted by impact then id; determinism: calling twice gives equal dicts.
  - CLI: `score` on the `refresh-race` fixture with `tests/fixtures/answers/refresh-race.json` (a hand-written answers file, `TOK-05` = `no`) exits 0, returns JSON with `findings_count` greater than 0 and a total at most 79; `--format text` output contains the grade letter and the word `provisional` when coverage is low; `--baseline` with a saved result adds `delta`; `--save` creates `.spring-security-advisor/last-audit.json` and nothing else under the project; an invalid answers file exits 2 with a JSON error on stderr.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Write `checklist.json`** from the list above. Verify each `source` (OWASP cheat sheets for authentication, session management, password storage, REST security, authorization (IDOR) and mass assignment; RFC 9700 and RFC 6819 for refresh token rotation and reuse; Spring Security reference for method security, CORS and CSRF; RFC 8725 for JWT best practices), then set `status` and `checked`. Drop an item rather than invent a source.
- [ ] **Step 4: Implement** `scoring.py` and the two subcommands.
- [ ] **Step 5: Run** the full suite. Expected: pass.
- [ ] **Step 6: Commit** `git add -A && git commit -m "feat: checklist and deterministic score"`.

---

### Task 8: Skills (`audit`, `review`, `map`) and structure tests

**Files:** Create `skills/audit/SKILL.md`, `tests/test_skills.py`; Modify `skills/review/SKILL.md`, `skills/map/SKILL.md`.

- [ ] **Step 1: Write failing tests** (`tests/test_skills.py`): each skill folder has `SKILL.md` with frontmatter `name` equal to the folder and a non-empty `description` up to 1024 characters; the set of skills is `{"audit","map","review"}`; `audit` body contains `scan.py`, `checklist`, `score`, `--answers`, `evidence`, `cannot_determine`, `provisional`, `never` + `secure`, `Not covered`, `Limits`, `answer in the user's language`, `${CLAUDE_PLUGIN_ROOT}`, and the phrase `temporary directory` (answers file location); `review` and `audit` both state that the project is not modified.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Write `skills/audit/SKILL.md`.** `description`: full security audit of a Spring Boot repository with a 0-100 score, per-category scores, prioritized actions; triggers: "audit", "how secure is my project", "give me a security score", "rate my Spring Security setup". Steps: (1) find the root, locate Python as the other skills do; (2) `scan.py scan <root>` and read `signals`; (3) `scan.py checklist`; (4) for each category read the code the signals and `look_for` point to, and answer **every** item with `yes`/`partial`/`no`/`not_applicable`/`cannot_determine` and `file:line` evidence; prefer `cannot_determine` to a guess; a missing mechanism is `no` without evidence; (5) write the answers file in a temporary directory, not in the project; (6) run `scan.py score <root> --answers <file>`, add `--baseline` when a previous `.spring-security-advisor/last-audit.json` exists and ask before using `--save`; (7) report in this order: total score and grade (say *provisional* when coverage is low), a table per category, the top actions with risk and fix, findings in the existing format (risk / fix / source / type / confidence; heuristic ones are "to verify"), items that stayed `cannot_determine` and why, then *Scope*, *Not covered*, *Limits*. Rules: never say the project is "secure"; never print secret values; do not edit the project; distinguish certain bug / risk / improvement / style; answer in the user's language; the score is a tool, not a certificate.
  `review`: add that it is the fast rules-only check, with no score, and points to `audit` for the full picture; remove nothing else. `map`: mention the `signals` section (which mechanisms exist and where).
- [ ] **Step 4: Run** the full suite. Expected: pass.
- [ ] **Step 5: Commit** `git add -A && git commit -m "feat: audit skill, review and map updates, skill structure tests"`.

---

### Task 9: Release 1.0.0 and verification on the fixtures

**Files:** Modify `scripts/scan.py` (`VERSION`), `.claude-plugin/plugin.json` under `plugins/spring-security-advisor/`, `README.md`, `CHANGELOG.md`, `.github/workflows/test.yml` (only if the new test files need it; default: no change); Create `tests/test_release.py`.

- [ ] **Step 1: Write failing tests** (`tests/test_release.py`): `scan.VERSION == "1.0.0"`; `plugin.json` version `1.0.0`; first `## ` heading of `CHANGELOG.md` is `## 1.0.0`; README contains the headings `## Score` and `## Rules` and every rule id present in `rules.json`; README states the score constants (`20`, `10`, `3`, `69`, `79`); the fixtures `fixed` and `stateless-api` still return no finding above `low`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Update** versions; README: new intro (audit with score), skills table (`audit`, `review`, `map`), the full rules table generated from `rules.json` (write it by running a small script, do not type it by hand), a `## Score` section explaining categories, weights, penalties, caps, coverage and the evidence check, a **real** example report (run `scan.py score` on `refresh-race` with its answers file in text format and paste the output), limits, and the roadmap (`advise`, `apply`, dependency checks, Gradle Kotlin, Java-based scanner after 1.0). CHANGELOG `## 1.0.0`.
- [ ] **Step 4: Verify end to end:** run the full suite; run `python3 plugins/spring-security-advisor/scripts/scan.py scan tests/fixtures/vulnerable --format text`; run `score` on `refresh-race` and on `refresh-safe` with their answers files and confirm the safe project scores higher. Report the real numbers. If `claude` CLI exists run `claude plugin validate .`; otherwise say it was not run.
- [ ] **Step 5: Commit** `git add -A && git commit -m "release: spring-security-advisor 1.0.0"`, then `git push -u origin ccr-8058e74e-hy0f34`.

---

## Self-review

- **Spec coverage:** rules (Tasks 2 to 6; 17 new rules, 24 total), config reader (2), signals (6), checklist and scoring with evidence validation, caps, coverage, baseline and save (7), skills (8), fixtures and tests (1, 6, 7, 8, 9), 1.0.0 docs (9). Non-goals respected: no dependency scan, no `apply`/`advise`.
- **Deviations from the spec (flagged):** a ninth category `data_logging`; rules with an unverifiable source are dropped rather than released, so the final count may be under 24.
- **Type consistency:** `make_finding` adds `category` in Task 2 and later tasks consume it; `collect_signals` (Task 6) names are the ones the checklist validates in Task 7; `validate_answers` returns what `compute_score` takes.
- **Proportion:** rule behavior is given as test tables; implementers write the regexes and bodies.
