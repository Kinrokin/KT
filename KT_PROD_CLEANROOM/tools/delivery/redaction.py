from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError


RULES_FILE_REL = "KT_PROD_CLEANROOM/tools/delivery/redaction_rules.v1.json"


@dataclass(frozen=True)
class RedactionRule:
    rule_id: str
    regex: re.Pattern[str]
    replacement: str


def load_redaction_rules(*, repo_root: Path) -> Tuple[str, List[RedactionRule]]:
    rules_path = (repo_root / RULES_FILE_REL).resolve()
    try:
        obj = json.loads(rules_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unreadable redaction rules file (fail-closed): {rules_path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError("Redaction rules file must be a JSON object (fail-closed)")

    version = str(obj.get("version", "")).strip()
    if not version:
        raise FL3ValidationError("Redaction rules file missing version (fail-closed)")

    raw = obj.get("rules", [])
    if not isinstance(raw, list) or not raw:
        raise FL3ValidationError("Redaction rules file must contain non-empty rules list (fail-closed)")

    compiled: List[RedactionRule] = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("rule_id", "")).strip()
        rx = str(r.get("regex", "")).strip()
        repl = str(r.get("replacement", "")).strip()
        if not rid or not rx:
            continue
        try:
            compiled_rx = re.compile(rx, flags=re.MULTILINE)
        except re.error as exc:
            raise FL3ValidationError(f"Invalid redaction regex rule_id={rid} (fail-closed): {exc}") from exc
        compiled.append(RedactionRule(rule_id=rid, regex=compiled_rx, replacement=repl))

    if not compiled:
        raise FL3ValidationError("No valid redaction rules loaded (fail-closed)")

    return version, compiled


def apply_redactions(*, text: str, rules: Iterable[RedactionRule]) -> Tuple[str, Dict[str, int]]:
    out = str(text)
    counts: Dict[str, int] = {}
    for r in rules:
        out2, n = r.regex.subn(r.replacement, out)
        if n:
            counts[r.rule_id] = counts.get(r.rule_id, 0) + int(n)
        out = out2
    return out, counts


def redaction_rules_version() -> str:
    repo_root = repo_root_from(Path(__file__))
    version, _rules = load_redaction_rules(repo_root=repo_root)
    return version

