# Changelog

## 1.0.0
- `audit` skill and `scan.py score`: a deterministic 0-100 score with a grade, per-category scores, coverage, caps and the top actions. The model answers a checklist with `file:line` evidence; the script validates the evidence and computes the score.
- 16 new rules (SEC008 to SEC023), 23 in total: secrets in configuration files, actuator exposure, stack traces, cookie flags, CORS, catch-all `permitAll`, disabled headers, unsigned JWT parsing, JWT without expiration, deprecated or weak password encoders, BCrypt cost, insecure randomness, SQL by concatenation, refresh token revoked without a lock.
- Scanner signals: which mechanisms exist and where (rate limiting, refresh tokens, locking, JWT validation, logout, audit events). `scan` and `map` print them.
- Checklist of 31 items in 9 categories, each with a verified source.
- Config reader for `application*.properties` and `application*.yml` (no dependencies).
- Findings carry a `category`. `review` stays as the fast rules-only check; `map` includes the signals.
- Test source sets are recognised by their `src/<set>` directory, so main code in packages named `it` or `test` is scanned and `testFixtures`, `integration-test` or `e2e` are skipped.
- The score cannot be reached by skipping items: coverage counts all items, `not_applicable` needs a note, and unassessed critical items or categories make the score provisional (no grade below 50% coverage).
- Stable from this version: the JSON output of `scan`, `map`, `checklist` and `score`.

## 0.2.0
- Rule SEC007: HMAC JWT signing key built from a string literal shorter than the algorithm minimum (RFC 7518 section 3.2).
- README: example output and a Windows note about Python.

## 0.1.1
- Skills find a working Python 3 (`python3`, `python` or `py`) instead of assuming `python3`, which on Windows is often a non-working Store stub. They stop with a clear message if none is found.

## 0.1.0
- Scanner (`scan.py scan` and `scan.py map`), Python standard library only.
- Rules SEC001 to SEC006, each checked against the Spring Security 7.0 reference.
- Skills `review` and `map`.
- Fixtures, tests and CI.
