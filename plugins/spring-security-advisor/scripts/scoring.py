"""Deterministic security score from scanner findings and checklist answers.

Pure functions, standard library only. The model's judgment enters only as an answers file; this
module validates that file (evidence must point to real lines) and computes the score. The same
findings and answers always give the same result.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from core import ScanError

ANSWER_VALUES = ("yes", "partial", "no", "not_applicable", "cannot_determine")
DETERMINABLE = ("yes", "partial", "no")
SEVERITY_PENALTY = {"high": 20, "medium": 10, "low": 3}
REPEAT_FACTOR = 0.25
CAP_CERTAIN_BUG = 69
CAP_CRITICAL_NO = 79
GRADE_STEPS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))
PROVISIONAL_BELOW = 0.70
MAX_ACTIONS = 5
EVIDENCE_RE = re.compile(r"^(.+):(\d+)(?:-(\d+))?$")


class ScoreError(ScanError):
    pass


def _half_up(value: float) -> int:
    return int(math.floor(value + 0.5))


def _evidence_ok(root: Path, entry: str) -> tuple[bool, str]:
    match = EVIDENCE_RE.match(str(entry).strip())
    if not match:
        return False, f"{entry!r} is not file:line"
    rel, first, last = match.group(1), int(match.group(2)), int(match.group(3) or match.group(2))
    candidate = Path(rel)
    if candidate.is_absolute() or rel.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", rel):
        return False, f"{entry!r} is an absolute path"
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root.resolve())
    except (ValueError, OSError):
        return False, f"{entry!r} is outside the project"
    if not resolved.is_file():
        return False, f"{entry!r}: file not found"
    try:
        count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return False, f"{entry!r}: file not readable"
    if first < 1 or last < first or last > count:
        return False, f"{entry!r}: line outside the file ({count} lines)"
    return True, ""


def validate_answers(doc, items: list[dict], root: Path) -> tuple[dict[str, dict], list[str]]:
    """Return (effective answer per item id, warnings). Unverifiable answers become cannot_determine."""
    if not isinstance(doc, dict) or not isinstance(doc.get("answers"), list):
        raise ScoreError('the answers file must be a JSON object with an "answers" list')
    known = {item["id"] for item in items}
    warnings: list[str] = []
    seen: dict[str, dict] = {}
    for raw in doc["answers"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise ScoreError("every answer must be an object with a string id")
        item_id = raw["id"]
        if item_id not in known:
            warnings.append(f"{item_id}: unknown checklist item, ignored")
            continue
        if item_id in seen:
            warnings.append(f"{item_id}: duplicate answer, the last one is used")
        seen[item_id] = raw
    effective: dict[str, dict] = {}
    for item in items:
        item_id = item["id"]
        raw = seen.get(item_id)
        if raw is None:
            effective[item_id] = {"answer": "cannot_determine", "evidence": [], "note": "", "reason": "no answer"}
            continue
        answer = raw.get("answer")
        note = str(raw.get("note", ""))
        evidence = raw.get("evidence") if isinstance(raw.get("evidence"), list) else []
        if answer not in ANSWER_VALUES:
            warnings.append(f"{item_id}: invalid answer {answer!r}, treated as cannot_determine")
            effective[item_id] = {"answer": "cannot_determine", "evidence": [], "note": note, "reason": "invalid answer"}
            continue
        if answer in ("yes", "partial"):
            valid, problems = [], []
            for entry in evidence:
                ok, why = _evidence_ok(root, entry)
                (valid if ok else problems).append(entry if ok else why)
            warnings.extend(f"{item_id}: evidence rejected: {why}" for why in problems)
            if not valid:
                warnings.append(f"{item_id}: answer {answer!r} has no valid file:line evidence, treated as cannot_determine")
                effective[item_id] = {"answer": "cannot_determine", "evidence": [], "note": note, "reason": "no valid evidence"}
                continue
            evidence = valid
        effective[item_id] = {"answer": answer, "evidence": [str(e) for e in evidence], "note": note}
    return effective, warnings


def _category_of(finding: dict, rules: dict) -> str | None:
    return finding.get("category") or (rules.get(finding.get("id"), {}) or {}).get("category")


def _compute(findings: list[dict], effective: dict[str, dict], checklist: dict, rules: dict) -> dict:
    categories = checklist["categories"]
    state = {cid: {"earned": 0.0, "available": 0.0, "penalty": 0.0} for cid in categories}
    applicable = determinable = 0
    critical_no: list[str] = []
    for item in checklist["items"]:
        answer = effective.get(item["id"], {}).get("answer", "cannot_determine")
        if answer == "not_applicable":
            continue
        applicable += 1
        if answer not in DETERMINABLE:
            continue
        determinable += 1
        weight = item["weight"]
        state[item["category"]]["available"] += weight
        if answer == "yes":
            state[item["category"]]["earned"] += weight
        elif answer == "partial":
            state[item["category"]]["earned"] += weight / 2
        elif weight == 3:
            critical_no.append(item["id"])
    repeats: dict[tuple[str, str], int] = {}
    certain_bugs: list[str] = []
    for f in findings:
        cid = _category_of(f, rules)
        if cid in state:
            key = (cid, f["id"])
            factor = 1.0 if repeats.get(key, 0) == 0 else REPEAT_FACTOR
            repeats[key] = repeats.get(key, 0) + 1
            state[cid]["penalty"] += SEVERITY_PENALTY[f["severity"]] * factor
        if f["severity"] == "high" and f.get("type") == "certain bug":
            certain_bugs.append(f["id"])
    out_categories: dict[str, dict] = {}
    weighted = weights = 0.0
    for cid, spec in categories.items():
        s = state[cid]
        if s["available"] > 0:
            score, basis = max(0.0, 100 * s["earned"] / s["available"] - s["penalty"]), "checklist"
        elif s["penalty"] > 0:
            score, basis = max(0.0, 100 - s["penalty"]), "rules_only"
        else:
            score, basis = None, "none"
        out_categories[cid] = {
            "label": spec["label"], "weight": spec["weight"],
            "score": None if score is None else _half_up(score), "basis": basis,
            "earned": s["earned"], "available": s["available"], "penalty": round(s["penalty"], 2),
        }
        if score is not None:
            weighted += spec["weight"] * score
            weights += spec["weight"]
    caps: list[str] = []
    total = None
    if weights > 0:
        total = _half_up(weighted / weights)
        if certain_bugs:
            caps.append(f"high certain-bug finding ({', '.join(sorted(set(certain_bugs)))}): total capped at {CAP_CERTAIN_BUG}")
            total = min(total, CAP_CERTAIN_BUG)
        if critical_no:
            caps.append(f"critical checklist item answered no ({', '.join(sorted(critical_no))}): total capped at {CAP_CRITICAL_NO}")
            total = min(total, CAP_CRITICAL_NO)
    coverage = round(determinable / applicable, 2) if applicable else 0.0
    grade = None
    if total is not None:
        grade = next((g for floor, g in GRADE_STEPS if total >= floor), "F")
    return {"total": total, "grade": grade, "provisional": coverage < PROVISIONAL_BELOW, "coverage": coverage,
            "caps_applied": caps, "categories": out_categories}


def compute_score(findings: list[dict], effective: dict[str, dict], checklist: dict, rules: dict) -> dict:
    result = _compute(findings, effective, checklist, rules)
    baseline = result["total"] if result["total"] is not None else 0
    candidates: list[dict] = []
    for index, f in enumerate(findings):
        after = _compute(findings[:index] + findings[index + 1 :], effective, checklist, rules)["total"]
        where = f"{f.get('file')}:{f.get('line')}" if f.get("file") else "project"
        candidates.append({"kind": "finding", "id": f["id"], "impact": max(0, (after or 0) - baseline),
                           "detail": f"{f.get('title', f['id'])} ({where})", "_order": f"{f['id']}:{where}"})
    for item in checklist["items"]:
        current = effective.get(item["id"], {}).get("answer", "cannot_determine")
        if current not in ("no", "partial"):
            continue
        fixed = dict(effective)
        fixed[item["id"]] = {"answer": "yes", "evidence": [], "note": ""}
        after = _compute(findings, fixed, checklist, rules)["total"]
        candidates.append({"kind": "checklist", "id": item["id"], "impact": max(0, (after or 0) - baseline),
                           "detail": f"{item['question']} (answered {current})", "_order": item["id"]})
    candidates.sort(key=lambda c: (-c["impact"], c["kind"], c["_order"]))
    result["top_actions"] = [{k: v for k, v in c.items() if k != "_order"} for c in candidates[:MAX_ACTIONS]]
    result["warnings"] = []
    return result


def format_score_text(result: dict) -> str:
    lines = []
    total = result["total"]
    head = "no score (nothing could be assessed)" if total is None else f"{total}/100"
    lines.append(f"Security score: {head}")
    if result["grade"]:
        lines.append(f"Grade: {result['grade']}")
    note = "provisional: less than 70% of the applicable checklist could be assessed" if result["provisional"] else "coverage is sufficient"
    lines.append(f"Coverage: {int(result['coverage'] * 100)}% ({note})")
    for cap in result["caps_applied"]:
        lines.append(f"Cap: {cap}")
    if "delta" in result:
        sign = "+" if result["delta"]["total"] >= 0 else ""
        lines.append(f"Change since the baseline: {sign}{result['delta']['total']}")
    lines.append("")
    lines.append("Categories:")
    for cid, c in result["categories"].items():
        value = "n/a" if c["score"] is None else f"{c['score']}/100"
        lines.append(f"- {c['label']} (weight {c['weight']}): {value} [{c['basis']}]")
    if result["top_actions"]:
        lines.append("")
        lines.append("Top actions (estimated points gained):")
        for a in result["top_actions"]:
            lines.append(f"- +{a['impact']} {a['id']}: {a['detail']}")
    if result["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"- {w}" for w in result["warnings"])
    return "\n".join(lines)
