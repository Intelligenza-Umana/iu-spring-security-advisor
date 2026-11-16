"""Signals: which security mechanisms exist in the project, and where.

A signal is not a finding. It says "this mechanism appears in main sources at file:line" so that the
checklist knows where to read and what is missing. Only main Java sources are searched; matches inside
comments are already blanked by `Project`.
"""
from __future__ import annotations

import re

MAX_PER_SIGNAL = 50

PATTERNS: dict[str, str] = {
    "rate_limiting": r"Bucket4j|\bBucket\b|RateLimiter|RequestRateLimiter|\bRateLimit\w*|@RateLimit",
    "login_throttling": r"LockedException|failedAttempts|failed_attempts|AuthenticationFailureBadCredentialsEvent|loginAttempt\w*",
    "refresh_token": r"(?i)refresh[-_ ]?token",
    "token_revocation": r"(?i)revoke\w*|blacklist\w*|denylist\w*|tokenFamily|\bjti\b",
    "locking": (
        r"@Lock\b|PESSIMISTIC_WRITE|PESSIMISTIC_READ|@Version\b|FOR UPDATE|OptimisticLock\w*|@Modifying"
        r"|@Table\([^)]*uniqueConstraints|unique\s*=\s*true"
    ),
    "jwt_validation": (
        r"JwtDecoder|JwtValidators|JwtTimestampValidator|JwtIssuerValidator|OAuth2TokenValidator"
        r"|parseSignedClaims|requireIssuer|requireAudience"
    ),
    "password_reset": r"(?i)password[-_ ]?reset|reset[-_ ]?token|forgot[-_ ]?password",
    "input_validation": r"@Valid\b|@Validated\b",
    "logout": r"\.logout\s*\(|LogoutHandler|LogoutSuccessHandler|/logout",
    "audit_events": r"AuthenticationSuccessEvent|AuthenticationFailure\w*Event|AuthorizationDeniedEvent|AuditEvent",
}

SIGNAL_NAMES = tuple(PATTERNS)


def collect_signals(project) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for name, pattern in PATTERNS.items():
        found: list[dict] = []
        for path, _text, match, line in project.grep(pattern):
            if len(found) >= MAX_PER_SIGNAL:
                break
            found.append({"file": project.rel(path), "line": line, "text": match.group(0).strip()[:60]})
        out[name] = found
    return out
