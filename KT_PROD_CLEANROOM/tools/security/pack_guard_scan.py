from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.verification.fl3_canonical import repo_root_from, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import enforce_all_or_none_exist, write_text_worm


PATTERNS_FILE_REL = "KT_PROD_CLEANROOM/tools/security/secret_patterns.v1.json"


@dataclass(frozen=True)
class SecretPattern:
    pattern_id: str
    confidence: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class AllowPattern:
    allow_id: str
    regex: re.Pattern[str]


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    entropy = 0.0
    for c in freq.values():
        p = c / n
        entropy -= p * math.log(p, 2)
    return entropy


def _looks_like_base64(token: str) -> bool:
    if len(token) < 24:
        return False
    if len(token) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", token))


def _looks_like_hex(token: str) -> bool:
    return len(token) >= 32 and bool(re.fullmatch(r"[0-9a-fA-F]+", token))


def _redact_token(token: str, *, max_len: int = 120) -> str:
    t = token.strip()
    if len(t) <= 12:
        return "<redacted>"
    head = t[:4]
    tail = t[-4:]
    inner_len = max(0, len(t) - 8)
    preview = f"{head}...{tail} (len={len(t)})"
    return preview[:max_len]


def _load_patterns(*, repo_root: Path) -> Tuple[List[SecretPattern], List[AllowPattern], str]:
    path = (repo_root / PATTERNS_FILE_REL).resolve()
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable secret patterns file: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError("FAIL_CLOSED: secret patterns file must be a JSON object")
    version = str(obj.get("version", "")).strip() or "unknown"

    patterns_raw = obj.get("patterns", [])
    allow_raw = obj.get("allowlist", [])
    if not isinstance(patterns_raw, list) or not isinstance(allow_raw, list):
        raise FL3ValidationError("FAIL_CLOSED: secret patterns file invalid (patterns/allowlist must be lists)")

    patterns: List[SecretPattern] = []
    for p in patterns_raw:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("pattern_id", "")).strip()
        conf = str(p.get("confidence", "")).strip().upper() or "HIGH"
        rx = str(p.get("regex", "")).strip()
        if not pid or not rx:
            continue
        try:
            compiled = re.compile(rx)
        except re.error as exc:
            raise FL3ValidationError(f"FAIL_CLOSED: invalid secret regex pattern_id={pid}: {exc}") from exc
        patterns.append(SecretPattern(pattern_id=pid, confidence=conf, regex=compiled))

    allow: List[AllowPattern] = []
    for a in allow_raw:
        if not isinstance(a, dict):
            continue
        aid = str(a.get("allow_id", "")).strip()
        rx = str(a.get("regex", "")).strip()
        if not aid or not rx:
            continue
        try:
            compiled = re.compile(rx)
        except re.error as exc:
            raise FL3ValidationError(f"FAIL_CLOSED: invalid allowlist regex allow_id={aid}: {exc}") from exc
        allow.append(AllowPattern(allow_id=aid, regex=compiled))

    if not patterns:
        raise FL3ValidationError("FAIL_CLOSED: secret patterns list is empty")
    return patterns, allow, version


def _allowlisted(token: str, allow: List[AllowPattern]) -> bool:
    for a in allow:
        if a.regex.search(token):
            return True
    return False


def _iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if ".git" in p.parts:
            continue
        if "__pycache__" in p.parts:
            continue
        yield p


def _scan_text_line(
    *,
    line: str,
    patterns: List[SecretPattern],
    allow: List[AllowPattern],
    entropy_threshold: float,
) -> List[Tuple[str, str, str, str]]:
    """
    Returns list of tuples: (reason, confidence, pattern_id_or_empty, matched_token)
    """
    out: List[Tuple[str, str, str, str]] = []

    # Direct regex hits (high confidence).
    for pat in patterns:
        for m in pat.regex.finditer(line):
            token = m.group(0)
            if _allowlisted(token, allow):
                continue
            out.append(("REGEX", pat.confidence or "HIGH", pat.pattern_id, token))

    # Base64 substrings: decode and re-scan for known patterns (high confidence).
    for m in re.finditer(r"(?:[A-Za-z0-9+/]{24,}={0,2})", line):
        token = m.group(0)
        if not _looks_like_base64(token):
            continue
        if _allowlisted(token, allow):
            continue
        try:
            decoded = base64.b64decode(token, validate=True)
            decoded_text = decoded.decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = ""
        if not decoded_text:
            continue
        for pat in patterns:
            if pat.regex.search(decoded_text):
                out.append(("DECODED_REGEX", "HIGH", pat.pattern_id, token))
                break

    # Candidate tokenization for encoded/entropy checks.
    tokens = re.split(r"[^A-Za-z0-9+/=_-]+", line)
    for t in tokens:
        if len(t) < 24:
            continue
        if _allowlisted(t, allow):
            continue

        # Entropy-only signal (low confidence; advisory).
        # Avoid flagging pure-hex and allowlisted digests.
        if _looks_like_hex(t):
            continue
        ent = _shannon_entropy(t)
        if ent >= entropy_threshold:
            out.append(("HIGH_ENTROPY", "LOW", "", t))

    return out


def build_secret_scan_report(
    *,
    pack_root: Path,
    run_id: Optional[str] = None,
    lane_id: Optional[str] = None,
    entropy_threshold: float = 4.7,
) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))
    patterns, allow, patterns_version = _load_patterns(repo_root=repo_root)

    pack_root = pack_root.resolve()
    created_at = _utc_now_z()
    findings: List[Dict[str, Any]] = []
    read_errors = 0

    for path in sorted(_iter_files(pack_root), key=lambda p: p.as_posix()):
        rel = path.relative_to(pack_root).as_posix()
        try:
            # Text-only scan: strict UTF-8; binary files are ignored.
            with path.open("r", encoding="utf-8") as handle:
                for line_no, line in enumerate(handle, start=1):
                    hits = _scan_text_line(
                        line=line,
                        patterns=patterns,
                        allow=allow,
                        entropy_threshold=entropy_threshold,
                    )
                    for reason, confidence, pattern_id, token in hits:
                        finding: Dict[str, Any] = {
                            "finding_id": "0" * 64,
                            "path_rel": rel,
                            "line": line_no,
                            "reason": reason,
                            "confidence": confidence,
                            "pattern_id": pattern_id or None,
                            "snippet_redacted": _redact_token(token),
                            "snippet_sha256": sha256_text(token),
                        }
                        finding["finding_id"] = _sha256_bytes(
                            json.dumps(
                                {k: v for k, v in finding.items() if k != "finding_id"},
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=True,
                            ).encode("utf-8")
                        )
                        findings.append(finding)
        except UnicodeDecodeError:
            # Treat binary as out-of-scope for secret scanning (evidence packs may contain binary weights).
            continue
        except Exception:
            read_errors += 1
            findings.append(
                {
                    "finding_id": _sha256_bytes(f"{rel}:READ_ERROR".encode("utf-8")),
                    "path_rel": rel,
                    "reason": "READ_ERROR",
                    "confidence": "HIGH",
                    "pattern_id": None,
                    "snippet_redacted": "<read_error>",
                    "snippet_sha256": _sha256_bytes(b""),
                }
            )

    high = sum(1 for f in findings if str(f.get("confidence")) == "HIGH" and str(f.get("reason")) != "HIGH_ENTROPY")
    status = "PASS"
    if read_errors > 0:
        status = "ERROR"
    elif high > 0:
        status = "FAIL"

    report: Dict[str, Any] = {
        "schema_id": "kt.secret_scan_report.v1",
        "schema_version_hash": "",
        "report_id": "",
        "status": status,
        "scanner_version": "pack_guard_scan.v1",
        "patterns_version": patterns_version,
        "findings": findings,
        "report_hash": "",
        "created_at": created_at,
    }
    if run_id:
        report["run_id"] = str(run_id)
    if lane_id:
        report["lane_id"] = str(lane_id)

    # Bind to schema version hash from registry.
    from schemas.schema_files import schema_version_hash  # local import to keep tool import-light

    report["schema_version_hash"] = schema_version_hash("fl3/kt.secret_scan_report.v1.json")
    report["report_id"] = _sha256_bytes(
        json.dumps(
            {k: v for k, v in report.items() if k not in {"created_at", "report_id", "report_hash"}},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )
    report["report_hash"] = _sha256_bytes(
        json.dumps({k: v for k, v in report.items() if k != "report_hash"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )

    validate_schema_bound_object(report)
    return report


def build_secret_scan_summary(*, report: Dict[str, Any]) -> Dict[str, Any]:
    created_at = _utc_now_z()
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    high = sum(1 for f in findings if str(f.get("confidence")) == "HIGH" and str(f.get("reason")) != "HIGH_ENTROPY")

    summary: Dict[str, Any] = {
        "schema_id": "kt.secret_scan_summary.v1",
        "schema_version_hash": "",
        "summary_id": "",
        "report_hash": str(report.get("report_hash", "")),
        "status": str(report.get("status", "ERROR")),
        "total_findings": len(findings),
        "high_confidence_findings": high,
        "created_at": created_at,
    }
    if "run_id" in report:
        summary["run_id"] = str(report.get("run_id"))
    if "lane_id" in report:
        summary["lane_id"] = str(report.get("lane_id"))

    from schemas.schema_files import schema_version_hash  # local import

    summary["schema_version_hash"] = schema_version_hash("fl3/kt.secret_scan_summary.v1.json")
    summary["summary_id"] = _sha256_bytes(
        json.dumps({k: v for k, v in summary.items() if k not in {"created_at", "summary_id"}}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )
    validate_schema_bound_object(summary)
    return summary


def write_secret_scan_artifacts(*, out_dir: Path, report: Dict[str, Any], summary: Dict[str, Any]) -> Tuple[Path, Path]:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_path = out_dir / "secret_scan_report.json"
    summary_path = out_dir / "secret_scan_summary.json"

    report_text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    summary_text = json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n"

    enforce_all_or_none_exist([report_path, summary_path], label="secret scan artifacts")
    write_text_worm(path=report_path, text=report_text, label="secret_scan_report.json")
    write_text_worm(path=summary_path, text=summary_text, label="secret_scan_summary.json")
    return report_path, summary_path


def scan_pack_and_write(*, pack_root: Path, out_dir: Optional[Path] = None, run_id: Optional[str] = None, lane_id: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    report = build_secret_scan_report(pack_root=pack_root, run_id=run_id, lane_id=lane_id)
    summary = build_secret_scan_summary(report=report)
    write_secret_scan_artifacts(out_dir=out_dir or pack_root, report=report, summary=summary)
    return report, summary


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Scan an evidence/delivery pack for secrets and emit schema-bound reports (fail-closed).")
    ap.add_argument("--pack-root", required=True, help="Root directory to scan.")
    ap.add_argument("--out-dir", default=None, help="Output directory for secret_scan_report.json and secret_scan_summary.json (default: pack-root).")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--lane-id", default=None)
    ap.add_argument(
        "--no-exit-nonzero",
        action="store_true",
        help="Always exit 0 after writing artifacts; caller must inspect report status.",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _ = repo_root_from(Path(__file__))
    args = _parse_args(argv)
    pack_root = Path(args.pack_root)
    out_dir = Path(args.out_dir) if args.out_dir else None
    report, summary = scan_pack_and_write(pack_root=pack_root, out_dir=out_dir, run_id=args.run_id, lane_id=args.lane_id)
    status = str(report.get("status", "ERROR"))
    print(json.dumps({"status": status, "total_findings": summary.get("total_findings"), "high_confidence_findings": summary.get("high_confidence_findings")}, sort_keys=True))
    if args.no_exit_nonzero:
        return 0
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
