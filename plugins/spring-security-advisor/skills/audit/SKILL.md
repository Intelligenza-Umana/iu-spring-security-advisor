---
name: audit
description: Full security audit of a Spring Boot repository with a 0-100 score, per-category scores and prioritized actions. Runs the rule scanner, reads the code the signals point to, answers a checklist with file:line evidence and computes the score with a deterministic script. Use when the user asks to audit the project, "how secure is my project", for a security score or grade, or what is missing in their Spring Security setup.
---

# audit

Read-only: this skill never edits the project. Answer in the user's language.

```
PY=$(for c in python3 python py; do "$c" -c "import sys; sys.exit(sys.version_info[0] != 3)" 2>/dev/null && { echo "$c"; break; }; done)
SCAN="$PY ${CLAUDE_PLUGIN_ROOT}/scripts/scan.py"
```

If `$PY` is empty, no working Python 3 was found (on Windows `python3` is often a Microsoft Store stub that does not run). Tell the user to install Python 3 and stop; do not work around it.

The score is computed by the script, not by you. Your job is to read the code honestly and report evidence. You cannot raise the score by wording: an answer of `yes` or `partial` without a valid `file:line` that exists is thrown away.

## Steps

1. **Find the project root** (the directory with `pom.xml` or `build.gradle`). If unclear, ask once.
2. **Scan:** `$SCAN scan <root>`. Note `findings`, `signals` (which mechanisms exist and where: rate limiting, refresh tokens, locks, JWT validation, logout and so on), `detected.spring_boot_version` and `notes`.
3. **Load the checklist:** `$SCAN checklist`. Each item has an `id`, a `question`, `look_for` (what to read) and `signals` (where to start).
4. **Read the code and answer every item.** Use the signals to open the right files; when a mechanism is missing, the answer is usually `no`. Values:
   - `yes`: the code does it. Needs `evidence`: a list of `path/relative/to/root:LINE`.
   - `partial`: done in some places or in part. Needs evidence too.
   - `no`: the mechanism is absent or wrong. Evidence is optional (a missing mechanism has no line).
   - `not_applicable`: the item does not apply (for example cookies when authentication is token-only). It needs a note saying why; without one the script discards it. Items marked `not_applicable` count as not assessed, so use it only when it is true.
   - `cannot_determine`: you could not decide from the code (logic in infrastructure, unreadable, too indirect). Prefer this to a guess.
   Add a short `note` for each answer. Verify framework facts with a documentation tool (for example Context7) when available and mark anything unchecked as **unverified** in the note.
5. **Write the answers file in a temporary directory, not in the project:** `{"answers": [{"id": "TOK-05", "answer": "no", "evidence": [], "note": "..."}, ...]}`.
6. **Score:** `$SCAN score <root> --answers <file>` (add `--format text` for a readable table, but keep the JSON for yourself). If `<root>/.spring-security-advisor/last-audit.json` exists, add `--baseline` with it to show the change. Ask the user before using `--save`, which writes that file inside their project.
7. **Report**, in this order:
   - the total score and grade. If `provisional` is true, say so first and list `provisional_reasons` (less than 70% of the checklist assessed, a critical item or a whole category not assessed): the number is a rough guide. If the grade is withheld (less than half of the checklist assessed), say that no grade is given and why; never invent one.
   - a table with the score of each category and its basis (`checklist`, `rules_only`, or no data).
   - the `caps_applied` if any, in one sentence each.
   - the top actions from `top_actions`, each with why it matters and a concrete fix.
   - the scanner findings in this format, most severe first: `[SEC0XX] severity: title`, Where, Risk, Suggested fix, Source, Type, Confidence. Findings with `confidence: medium` are "to verify", never "certain bug". Drop false positives after reading the code and say why in one line.
   - items left as `cannot_determine` and what would settle them; any `warnings` from the script (rejected evidence).
   - *Scope* (files analyzed, rules run), *Not covered* (dependencies and their CVEs, runtime behavior, infrastructure, secrets stored outside the repository) and *Limits* (from the scanner output).

## Rules

- Never say the project is "secure". The score measures what was checked, not what is safe.
- Never print secret values found in the code or configuration; point to file and line only.
- Distinguish certain bugs, risks to evaluate, optional improvements and style preferences.
- Do not edit files. To change anything the user must ask explicitly; make one small change at a time and run the audit again to show the effect.
- If the script returns an error, show the message and fix the input; do not work around it.
