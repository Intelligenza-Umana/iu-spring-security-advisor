# spring-security-advisor

**An [Intelligenza Umana](https://github.com/Intelligenza-Umana/intelligenza-umana) project.** See the [official project registry](https://github.com/Intelligenza-Umana/intelligenza-umana/blob/main/docs/PROJECT_REGISTRY.md).

[![tests](https://github.com/Intelligenza-Umana/iu-spring-security-advisor/actions/workflows/test.yml/badge.svg)](https://github.com/Intelligenza-Umana/iu-spring-security-advisor/actions/workflows/test.yml)

A security audit for Spring Boot projects, as a [Claude Code](https://claude.com/claude-code) plugin. It reads a whole repository, tells you what is missing and where the weak spots are, and gives a **score from 0 to 100** you can track over time.

Two parts do different jobs. A small, tested Python scanner finds known mistakes and prints reproducible results. The model reads the code the scanner points to and answers a checklist with evidence (`file:line`). A script validates that evidence and computes the score, so the model cannot raise the score by wording.

Ask Claude to "audit my project": the `audit` skill runs the whole flow below.

> It covers the servlet stack. It is not a dependency (CVE) scanner and it cannot prove that a project is secure. The score measures what was checked.

## Skills

| Skill | What it does |
|---|---|
| `/spring-security-advisor:audit` | The full audit: scanner, checklist, score, per-category scores and the top actions. Read-only. |
| `/spring-security-advisor:review` | The fast check: runs the rules only, verifies each finding in the code, no score. Read-only. |
| `/spring-security-advisor:map` | Maps the filter chains, custom filters, providers, encoders, method security, authorization rules and security mechanisms that exist, and how a request flows through them. Read-only. |

## Install

```bash
claude plugin marketplace add Intelligenza-Umana/iu-spring-security-advisor
claude plugin install spring-security-advisor@spring-security-advisor
```

For local development: `claude --plugin-dir ./plugins/spring-security-advisor`.

The skills need Python 3 on your `PATH`. They try `python3`, `python` and `py`. On Windows `python3` is often a Microsoft Store stub that does not run; install Python 3 from python.org or with `winget install Python.Python.3.12`.

## Rules

23 rules. Each was checked against its source (the official Spring documentation, the JJWT reference or the Java API); the source is printed in every finding. A finding has a type (certain bug, risk to evaluate, improvement) and a confidence (high, or medium for heuristics). Comments, imports and test sources are not reported.

| ID | Severity | Category | What it looks for |
|---|---|---|---|
| SEC001 | high | passwords | NoOpPasswordEncoder in production code |
| SEC002 | high | authorization | Authorization rule that can never be reached |
| SEC003 | medium | authorization | Method security annotations without method security enabled |
| SEC004 | low | authorization | Deprecated @EnableGlobalMethodSecurity |
| SEC005 | medium | session_csrf_cors | CSRF protection disabled |
| SEC006 | medium | tokens | Token authentication without an explicit stateless session policy |
| SEC007 | high | tokens | HMAC JWT signing key shorter than the algorithm minimum |
| SEC008 | high | secrets_config | Secret written as a literal in a configuration file |
| SEC009 | medium | headers_actuator | All actuator endpoints exposed over HTTP |
| SEC010 | medium | headers_actuator | Stack traces always included in error responses |
| SEC011 | medium | session_csrf_cors | Session or custom cookie without Secure or HttpOnly |
| SEC012 | high | session_csrf_cors | CORS allows any origin together with credentials |
| SEC013 | low | session_csrf_cors | CORS allows any origin |
| SEC014 | high | authorization | Every request is permitted without authentication |
| SEC015 | medium | headers_actuator | Security response headers disabled |
| SEC016 | high | tokens | JWT parsed without signature verification |
| SEC017 | medium | tokens | JWT created without an expiration claim |
| SEC018 | high | passwords | Deprecated digest-based password encoder |
| SEC019 | medium | passwords | MD5 or SHA-1 digest in code that handles passwords |
| SEC020 | low | passwords | BCrypt strength below the default |
| SEC021 | medium | tokens | Non-cryptographic random generator in secret-related code |
| SEC022 | high | data_logging | SQL built by concatenation instead of bind parameters |
| SEC023 | medium | tokens | Refresh token revoked or replaced without a lock |

## Checklist

Rules cannot see everything. 31 checklist items cover what needs reading: for example whether a refresh token is single-use, whether check-and-revoke is atomic (a race condition lets two concurrent requests both succeed), whether login has its own rate limit, whether endpoints that take an id check ownership. Each item has a verified source (OWASP cheat sheets, official Spring documentation, the JJWT reference). The scanner also prints **signals** (where rate limiting, refresh tokens, locks, JWT validation, logout and audit events appear in the code) so the audit knows where to read and what is missing.

## Score

`scan.py score` combines the findings and the checklist answers.

- **Answers:** `yes` (full weight), `partial` (half), `no` (zero), `not_applicable` (left out of the points) and `cannot_determine` (left out of the points). `yes` and `partial` need `file:line` evidence; the script checks that the file exists inside the project and the line is in it, and otherwise treats the answer as `cannot_determine`. `not_applicable` needs a note saying why, and counts as not assessed.
- **Category score** (0-100): points earned over points available for that category, minus the penalty of its findings: high / medium / low = 20 / 10 / 3 points, and repeats of the same rule weigh 25% after the first. A category with nothing assessed has no score and is left out.
- **Total:** the weighted average of the categories. Caps: a high certain-bug finding limits the total to 69; a critical checklist item (weight 3) answered `no` limits it to 79.
- **Grade:** A from 90, B from 80, C from 70, D from 60, F below. No grade is given when less than half of the checklist was assessed.
- **Coverage:** the share of all checklist items that were assessed (`not_applicable` and `cannot_determine` items are not assessed). The score is labeled *provisional*, with the reasons printed, when coverage is below 70%, when a critical item (weight 3) was not assessed, or when a whole category was not assessed. Skipping hard items does not raise the score; it makes it provisional.

| Category | Weight |
|---|---|
| Tokens | 20 |
| Authorization | 20 |
| Authentication | 15 |
| Rate limiting | 10 |
| Passwords | 10 |
| Session, CSRF and CORS | 10 |
| Secrets and configuration | 8 |
| Headers and actuator | 4 |
| Input, data and logs | 3 |

The result is deterministic: the same findings and answers give the same score. With `--baseline` it shows the change from a saved result (`--save` writes `.spring-security-advisor/last-audit.json` in the project; decide yourself whether to commit it).

Real output on the `refresh-race` test fixture, a project with a refresh endpoint that has no lock and no rate limiter (only four items were answered, hence provisional):

```text
Security score: 8/100 (provisional)
Grade: not assigned (less than half of the checklist was assessed)
Coverage: 13% (4 of 31 items assessed, 0 not applicable, 27 could not be determined)
Provisional because:
- only 4 of 31 checklist items were assessed (under 70%)
- critical items not assessed: AUTH-01, AUTH-03, AUTHZ-01, AUTHZ-02, PWD-01, RATE-02, TOK-07, TOK-09
- category Authorization was not assessed
- category Authentication was not assessed
- category Passwords was not assessed
- category Session, CSRF and CORS was not assessed
- category Headers and actuator was not assessed
- category Input, data and logs was not assessed
Cap: critical checklist item answered no (CFG-01, TOK-05): total capped at 79

Categories:
- Tokens (weight 20): 15/100 [checklist]
- Authorization (weight 20): n/a [none]
- Authentication (weight 15): n/a [none]
- Rate limiting (weight 10): 0/100 [checklist]
- Passwords (weight 10): n/a [none]
- Session, CSRF and CORS (weight 10): n/a [none]
- Secrets and configuration (weight 8): 0/100 [checklist]
- Headers and actuator (weight 4): n/a [none]
- Input, data and logs (weight 3): n/a [none]

Top actions (estimated points gained):
- +26 RATE-01: Is there a global rate limit on the API that answers 429 when exceeded? (answered no)
- +26 TOK-05: Are the check and the revocation of a refresh token atomic, so two concurrent requests with the same token cannot both succeed? (answered no)
- +17 CFG-01: Do secrets (database, keys, API tokens) come from the environment or a secret store? (answered no)
- +13 TOK-02: Is a refresh token single-use: every refresh issues a new refresh token and invalidates the old one? (answered partial)
- +5 SEC023: Refresh token revoked or replaced without a lock (src/main/java/demo/RefreshService.java:15)
```

## The scanner

`plugins/spring-security-advisor/scripts/scan.py` is a standalone CLI (Python 3, standard library only). From the repository root, first run `cd plugins/spring-security-advisor`. It reads source files only, works without Maven or a JDK and makes no network calls.

```bash
python3 scripts/scan.py scan path/to/project              # JSON, with findings and signals
python3 scripts/scan.py scan path/to/project --format text
python3 scripts/scan.py scan path/to/project --fail-on high   # exit 1 for CI
python3 scripts/scan.py map  path/to/project
python3 scripts/scan.py checklist
python3 scripts/scan.py score path/to/project --answers answers.json --format text
```

The JSON output of these commands is stable from 1.0: fields are only added.

## Limits

- Pattern matching on source text, not a full Java parser: unusual code styles can be missed or misread.
- It does not run your application, resolve dependencies, check CVEs or inspect infrastructure.
- No findings means "none of these rules matched", not "secure". A high score means the checked items looked fine, not that the project is safe.
- The checklist answers come from the model reading your code; the script limits what an answer can do to the score, it does not make the reading objective.
- Rules follow the Spring Security 7.0 reference; behavior in older versions can differ. The scanner warns when it detects Spring Boot 2.x.

## Roadmap

- `advise`: choosing between sessions, your own JWT, an OAuth2 resource server or an identity provider.
- `apply`: one change at a time, with a diff and your confirmation.
- Dependency checks, Gradle Kotlin support, a more precise Java-based scanner.

## Tests

From the repository root:

```bash
python3 -m unittest discover -s tests
```

The tests cover every rule with a positive and a negative case, the signals, the checklist file, the evidence validation and the score formula, and run the scanner on fixture projects (`vulnerable`, `fixed`, `stateless-api`, `refresh-race`, `refresh-safe`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and private security reporting guidance.

## License

MIT
