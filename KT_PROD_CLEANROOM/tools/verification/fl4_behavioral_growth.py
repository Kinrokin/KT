from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def _read_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    return obj


def _binom_p_ge(k: int, n: int, p: float) -> float:
    """
    One-sided binomial tail P[X >= k] for X~Binom(n,p).
    """
    if n <= 0:
        return 1.0
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    # Exact sum with math.comb, stable for small n (we keep n tiny).
    acc = 0.0
    for x in range(k, n + 1):
        acc += math.comb(n, x) * (p**x) * ((1.0 - p) ** (n - x))
    return float(min(1.0, max(0.0, acc)))


def _mk_linear_mod10_problem() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """
    Deterministic, high-signal behavioral growth task family.

    Hidden rule: y = (a*x + b) mod 10, with fixed (a,b).
    - H0: holdout items (baseline evaluation) with no state (predicts "?")
    - E: 2 examples that uniquely identify (a,b) in mod 10 space
    - H1: disjoint holdout items (post evaluation) that require applying learned (a,b)

    This proves "growth" as: learn parameters from E, write state, then improve on disjoint H1.
    """
    a = 3
    b = 1

    def f(x: int) -> int:
        return (a * x + b) % 10

    h0_items = [{"task_id": f"H0_{i}", "x": x, "y": f(x)} for i, x in enumerate([5, 6, 7, 8], start=1)]
    e_items = [{"task_id": f"E_{i}", "x": x, "y": f(x)} for i, x in enumerate([1, 2], start=1)]
    h1_items = [{"task_id": f"H1_{i}", "x": x, "y": f(x)} for i, x in enumerate([3, 4, 9, 0], start=1)]

    return (
        {"schema_id": "kt.growth_holdout.v1", "set_id": "H0", "items": h0_items},
        {"schema_id": "kt.growth_experience.v1", "experience_id": "E", "items": e_items},
        {"schema_id": "kt.growth_holdout.v1", "set_id": "H1", "items": h1_items},
    )


def _solve_linear_mod10(examples: Sequence[Dict[str, Any]]) -> Tuple[int, int]:
    # Brute force is deterministic, tiny, and avoids modular-inverse edge cases.
    # Fail-closed if there isn't exactly one solution.
    sols: List[Tuple[int, int]] = []
    for a in range(10):
        for b in range(10):
            ok = True
            for ex in examples:
                x = int(ex["x"])
                y = int(ex["y"])
                if (a * x + b) % 10 != y:
                    ok = False
                    break
            if ok:
                sols.append((a, b))
    if len(sols) != 1:
        raise RuntimeError(f"Ambiguous or missing solution for (a,b) in mod 10 (fail-closed): {sols!r}")
    return sols[0]


def _evaluate_linear(items: Sequence[Dict[str, Any]], params: Optional[Tuple[int, int]]) -> Tuple[int, int, List[Dict[str, Any]]]:
    correct = 0
    rows: List[Dict[str, Any]] = []
    for it in items:
        x = int(it["x"])
        expected = int(it["y"])
        if params is None:
            predicted: Optional[int] = None
        else:
            a, b = params
            predicted = (a * x + b) % 10
        ok = predicted is not None and predicted == expected
        correct += 1 if ok else 0
        rows.append(
            {
                "task_id": str(it["task_id"]),
                "x": x,
                "expected": expected,
                "predicted": predicted,
                "correct": bool(ok),
            }
        )
    return correct, len(items), rows


def _write_state_ledger_event(*, ledger_path: Path, event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic, append-only "state vault" local to this growth certificate.
    No wall-clock timestamps, no external dependencies.
    """
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    seq = 1
    parent_hash = "0" * 64
    if ledger_path.exists() and ledger_path.stat().st_size:
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        last = json.loads(lines[-1])
        seq = int(last["seq"]) + 1
        parent_hash = str(last["event_hash"])

    record = {
        "schema_id": "kt.state_ledger_record.v1",
        "seq": seq,
        "parent_hash": parent_hash,
        "event_type": str(event["event_type"]),
        "organ_id": str(event["organ_id"]),
        "inputs_hash": event.get("inputs_hash"),
        "outputs_hash": event.get("outputs_hash"),
        "created_logical": f"L{seq:06d}",
    }
    record["event_hash"] = _sha256_text(_canonical_json({k: v for k, v in record.items() if k != "event_hash"}))

    ledger_path.write_text("", encoding="utf-8") if not ledger_path.exists() else None
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(_canonical_json(record) + "\n")
    return record


def run_behavioral_growth(*, out_dir: Path, seed: int = 0, min_delta: float = 0.4, max_p_value: float = 0.01) -> Dict[str, Any]:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp_root = (out_dir / "_tmp").resolve()
    tmp_root.mkdir(parents=True, exist_ok=True)

    h0_obj, e_obj, h1_obj = _mk_linear_mod10_problem()
    h0_obj = dict(h0_obj)
    e_obj = dict(e_obj)
    h1_obj = dict(h1_obj)
    h0_obj["seed"] = int(seed)
    e_obj["seed"] = int(seed)
    h1_obj["seed"] = int(seed)

    h0_path = out_dir / "H0.json"
    e_path = out_dir / "E.json"
    h1_path = out_dir / "H1.json"

    _write_json(h0_path, h0_obj)
    _write_json(e_path, e_obj)
    _write_json(h1_path, h1_obj)

    protocol = {
        "schema_id": "kt.growth_protocol.v1",
        "seed": int(seed),
        "H0_hash": _sha256_file(h0_path),
        "E_hash": _sha256_file(e_path),
        "H1_hash": _sha256_file(h1_path),
        "acceptance_criteria": {"min_delta": float(min_delta), "max_p_value": float(max_p_value)},
    }
    protocol["protocol_hash"] = _sha256_text(_canonical_json({k: v for k, v in protocol.items() if k != "protocol_hash"}))
    _write_json(out_dir / "growth_protocol.json", protocol)

    # Phase 0: baseline (empty state)
    baseline_correct, baseline_total, rows_h0 = _evaluate_linear(h0_obj["items"], params=None)
    baseline_acc = baseline_correct / baseline_total if baseline_total else 0.0
    _write_json(
        out_dir / "scores_H0.json",
        {
            "schema_id": "kt.growth_scores.v1",
            "set_id": "H0",
            "correct": baseline_correct,
            "total": baseline_total,
            "accuracy": baseline_acc,
            "rows": rows_h0,
        },
    )

    # Phase 1: experience -> derive params, write payload + deterministic state-ledger events.
    a, b = _solve_linear_mod10(e_obj["items"])
    payload_dir = (tmp_root / "state_payloads").resolve()
    payload_dir.mkdir(parents=True, exist_ok=True)
    mapping_payload = {
        "schema_id": "kt.growth_state_payload.v1",
        "kind": "linear_mod10_params",
        "a": int(a),
        "b": int(b),
    }
    payload_hash = _sha256_text(_canonical_json(mapping_payload))
    payload_path = payload_dir / f"{payload_hash}.json"
    _write_json(payload_path, mapping_payload)

    ledger_path = (tmp_root / "state_ledger.jsonl").resolve()
    write_rec = _write_state_ledger_event(
        ledger_path=ledger_path,
        event={"event_type": "GROWTH_STATE_WRITE", "organ_id": "fl4_behavioral_growth", "outputs_hash": payload_hash},
    )

    state_event = {
        "schema_id": "kt.growth_state_event.v1",
        "event": {
            "state_ledger_seq": write_rec["seq"],
            "state_ledger_event_hash": write_rec["event_hash"],
            "payload_hash": payload_hash,
            "payload_path": payload_path.relative_to(out_dir).as_posix(),
        },
    }
    _write_json(out_dir / "state_event.json", state_event)

    # Phase 2: post (read payload + evaluate on H1)
    learned_payload = _read_json(payload_path)
    if learned_payload.get("kind") != "linear_mod10_params":
        raise RuntimeError("Growth payload wrong kind (fail-closed)")
    learned_a = int(learned_payload["a"])
    learned_b = int(learned_payload["b"])

    read_rec = _write_state_ledger_event(
        ledger_path=ledger_path,
        event={"event_type": "GROWTH_STATE_READ", "organ_id": "fl4_behavioral_growth", "inputs_hash": payload_hash},
    )

    post_correct, post_total, rows_h1 = _evaluate_linear(h1_obj["items"], params=(learned_a, learned_b))
    post_acc = post_correct / post_total if post_total else 0.0
    _write_json(
        out_dir / "scores_H1.json",
        {
            "schema_id": "kt.growth_scores.v1",
            "set_id": "H1",
            "correct": post_correct,
            "total": post_total,
            "accuracy": post_acc,
            "rows": rows_h1,
        },
    )

    delta = post_acc - baseline_acc
    # Conservative p-value: probability of >=post_correct if baseline guess rate were baseline_acc.
    p_value = _binom_p_ge(post_correct, post_total, max(1e-9, baseline_acc))

    claim = {
        "schema_id": "kt.growth_claim.v1",
        "baseline": {"set_id": "H0", "correct": baseline_correct, "total": baseline_total, "accuracy": baseline_acc},
        "post": {"set_id": "H1", "correct": post_correct, "total": post_total, "accuracy": post_acc},
        "delta": delta,
        "p_value": p_value,
        "protocol_hash": protocol["protocol_hash"],
        "state": {
            "payload_hash": payload_hash,
            "state_ledger_path": ledger_path.relative_to(out_dir).as_posix(),
            "state_ledger_head_hash": read_rec["event_hash"],
            "state_ledger_record_count": int(read_rec["seq"]),
            "state_write_event_hash": write_rec["event_hash"],
            "state_read_event_hash": read_rec["event_hash"],
        },
    }
    claim["claim_hash"] = _sha256_text(_canonical_json({k: v for k, v in claim.items() if k != "claim_hash"}))
    _write_json(out_dir / "growth_claim.json", claim)

    if delta < float(min_delta) or p_value > float(max_p_value):
        raise RuntimeError(
            f"Behavioral growth did not meet acceptance criteria (fail-closed): "
            f"delta={delta:.6f} p_value={p_value:.6g} min_delta={min_delta} max_p_value={max_p_value}"
        )

    return {
        "protocol_hash": protocol["protocol_hash"],
        "claim_hash": claim["claim_hash"],
        "baseline_accuracy": baseline_acc,
        "post_accuracy": post_acc,
        "delta": delta,
        "p_value": p_value,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="FL4 behavioral growth certificate (deterministic; fail-closed).")
    ap.add_argument("--out-dir", required=True, help="Output directory for growth artifacts.")
    ap.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0).")
    ap.add_argument("--min-delta", type=float, default=0.4, help="Minimum required delta in accuracy (default: 0.4).")
    ap.add_argument("--max-p-value", type=float, default=0.01, help="Maximum allowed p-value (default: 0.01).")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    out_dir = Path(args.out_dir)
    summary = run_behavioral_growth(out_dir=out_dir, seed=int(args.seed), min_delta=float(args.min_delta), max_p_value=float(args.max_p_value))
    print(json.dumps({"schema_id": "kt.fl4_behavioral_growth_summary.v1", **summary}, sort_keys=True, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
