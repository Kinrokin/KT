from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


ACTION_ABSTAIN = "ABSTAIN_FOR_REVIEW"
ACTION_ROUTE = "ROUTE_SPECIALIST"
ACTION_STATIC = "STAY_STATIC_BASELINE"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def set_determinism(seed: int) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def load_rows(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    payload = json.loads(text)
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return [row for row in payload["rows"] if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    raise SystemExit(f"Unsupported dataset format for {path}")


def _maybe_load_case_map(path: Optional[Path], *, case_key: str = "case_id") -> Dict[str, Dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    rows = load_rows(path)
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        case_id = str(row.get(case_key, "")).strip()
        if case_id:
            out[case_id] = row
    return out


def _load_joint_batch_map(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    rows = load_rows(path)
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        batch_id = str(row.get("batch_id", "")).strip()
        geometry_id = str(row.get("geometry_id", "")).strip()
        case_ids = row.get("case_ids", [])
        if not isinstance(case_ids, list):
            continue
        for case_id in case_ids:
            case_key = str(case_id).strip()
            if not case_key:
                continue
            out[case_key] = {
                "batch_id": batch_id,
                "geometry_id": geometry_id,
                "batch_case_count": int(row.get("case_count", len(case_ids))),
            }
    return out


def _add_numeric(features: Dict[str, float], key: str, value: Any) -> None:
    if isinstance(value, bool):
        features[key] = 1.0 if value else 0.0
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        features[key] = float(value)


def _add_category(features: Dict[str, float], key: str, value: Any) -> None:
    normalized = str(value).strip()
    if normalized:
        features[f"{key}::{normalized}"] = 1.0


def _add_text_tokens(features: Dict[str, float], key: str, text: Any, *, limit: int = 12) -> None:
    normalized = str(text).strip().lower()
    if not normalized:
        return
    features[f"{key}::__present__"] = 1.0
    for token in re.findall(r"[a-z0-9_]+", normalized)[:limit]:
        features[f"{key}::tok::{token}"] = features.get(f"{key}::tok::{token}", 0.0) + 1.0


def _hash_features(features: Dict[str, float], dim: int) -> torch.Tensor:
    vec = torch.zeros(dim, dtype=torch.float32)
    for key, value in features.items():
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "little") % dim
        sign = -1.0 if (digest[4] & 1) else 1.0
        vec[idx] += sign * float(value)
    return vec


def _geometry_key(row: Dict[str, Any], joint_info: Dict[str, Any]) -> str:
    joint_geometry = str(joint_info.get("geometry_id", "")).strip()
    if joint_geometry:
        return joint_geometry
    return "::".join(
        [
            str(row.get("family_id", "")).strip() or "UNKNOWN_FAMILY",
            str(row.get("dominance_reason_code_primary", "")).strip() or "UNKNOWN_REASON",
            str(row.get("variant_type", "")).strip() or "UNKNOWN_VARIANT",
        ]
    )


def _build_case_record(
    row: Dict[str, Any],
    *,
    joint_info: Dict[str, Any],
    defer_row: Dict[str, Any],
    self_check_row: Dict[str, Any],
    feature_dim: int,
) -> Dict[str, Any]:
    merged = dict(row)
    merged.update(
        {
            "batch_id": str(joint_info.get("batch_id", "")).strip(),
            "geometry_id": _geometry_key(row, joint_info),
            "batch_case_count": int(joint_info.get("batch_case_count", 0)),
            "defer_gate_outcome": str(defer_row.get("defer_gate_outcome", row.get("defer_gate_outcome", ""))).strip(),
            "self_check_required": bool(self_check_row.get("self_check_required", row.get("self_check_required", False))),
            "self_check_passed": bool(self_check_row.get("self_check_passed", row.get("self_check_passed", False))),
        }
    )

    features: Dict[str, float] = {}
    for key in (
        "wrong_static_hold_cost",
        "wrong_route_cost",
        "missed_abstention_cost",
        "proof_burden_delta",
        "expected_route_margin",
        "observed_route_margin",
        "alpha_plausibility_score",
        "alpha_delayed_wrongness_score",
        "confidence_raw",
        "confidence_calibrated",
        "batch_case_count",
    ):
        _add_numeric(features, key, merged.get(key))
    for key in ("self_check_required", "self_check_passed"):
        _add_numeric(features, key, merged.get(key))

    for key in (
        "family_id",
        "variant_type",
        "lawful_action",
        "lawful_target_specialist",
        "runner_up_action",
        "dominance_reason_code_primary",
        "dominance_reason_code_secondary",
        "lawful_action_rationale_id",
        "case_risk_band",
        "defer_gate_outcome",
        "batch_id",
        "geometry_id",
        "why_not_target_label",
    ):
        _add_category(features, key, merged.get(key))

    for key in ("why_not_alpha", "why_not_specialist", "why_not_abstain"):
        _add_text_tokens(features, key, merged.get(key))

    return {
        "case_id": str(merged.get("case_id", "")).strip(),
        "geometry_id": str(merged["geometry_id"]),
        "consistency_group_id": str(merged.get("lawful_action_rationale_id", "")).strip() or str(merged["geometry_id"]),
        "risk_band": str(merged.get("case_risk_band", "LOW")).strip() or "LOW",
        "lawful_action": str(merged.get("lawful_action", "")).strip(),
        "dominance_reason_code_primary": str(merged.get("dominance_reason_code_primary", "")).strip(),
        "why_not_target_label": str(merged.get("why_not_target_label", "")).strip(),
        "runner_up_action": str(merged.get("runner_up_action", ACTION_STATIC)).strip() or ACTION_STATIC,
        "expected_route_margin": float(merged.get("expected_route_margin", 0.0)),
        "sample_weight": _sample_weight(merged),
        "x": _hash_features(features, feature_dim),
    }


def _sample_weight(row: Dict[str, Any]) -> float:
    risk_band = str(row.get("case_risk_band", "LOW")).strip().upper()
    lawful_action = str(row.get("lawful_action", "")).strip()
    variant_type = str(row.get("variant_type", "")).strip()
    weight = 1.0
    if risk_band == "HIGH":
        weight += 0.35
    elif risk_band == "MEDIUM":
        weight += 0.20
    if lawful_action in {ACTION_STATIC, ACTION_ABSTAIN}:
        weight += 0.30
    if variant_type in {"masked", "restraint", "temptation_negative"}:
        weight += 0.10
    return float(weight)


class RouteJudgmentHead(nn.Module):
    def __init__(self, feature_dim: int, action_classes: int, reason_classes: int, why_not_classes: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(feature_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
        )
        self.action_head = nn.Linear(128, action_classes)
        self.reason_head = nn.Linear(128, reason_classes)
        self.why_not_head = nn.Linear(128, why_not_classes)
        self.margin_head = nn.Linear(128, 1)

    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        hidden = self.encoder(x)
        return {
            "hidden": hidden,
            "action_logits": self.action_head(hidden),
            "reason_logits": self.reason_head(hidden),
            "why_not_logits": self.why_not_head(hidden),
            "margin": self.margin_head(hidden).squeeze(-1),
        }


def _split_geometries(records: Sequence[Dict[str, Any]], holdout_fraction: float) -> Tuple[List[int], List[int], List[str]]:
    geometry_ids = sorted({str(record["geometry_id"]) for record in records})
    if len(records) <= 1 or len(geometry_ids) <= 1:
        return list(range(len(records))), [], geometry_ids

    holdout_count = max(1, int(round(len(geometry_ids) * holdout_fraction)))
    holdout_count = min(holdout_count, len(geometry_ids) - 1)
    holdout_geometries = set(geometry_ids[-holdout_count:])

    train_idx = [idx for idx, record in enumerate(records) if str(record["geometry_id"]) not in holdout_geometries]
    holdout_idx = [idx for idx, record in enumerate(records) if str(record["geometry_id"]) in holdout_geometries]
    if not train_idx:
        train_idx = list(range(len(records) - 1))
        holdout_idx = [len(records) - 1]
    return train_idx, holdout_idx, geometry_ids


def _weighted_mean(values: torch.Tensor, weights: torch.Tensor) -> torch.Tensor:
    total_weight = torch.clamp(weights.sum(), min=1e-8)
    return (values * weights).sum() / total_weight


def _consistency_penalty(
    action_probs: torch.Tensor,
    margin_preds: torch.Tensor,
    group_ids: Sequence[str],
) -> torch.Tensor:
    unique_groups = sorted({group_id for group_id in group_ids if group_id})
    penalties: List[torch.Tensor] = []
    for group_id in unique_groups:
        indices = [idx for idx, candidate in enumerate(group_ids) if candidate == group_id]
        if len(indices) < 2:
            continue
        group_probs = action_probs[indices]
        group_margin = margin_preds[indices]
        penalties.append(group_probs.var(dim=0, unbiased=False).mean())
        penalties.append(group_margin.var(unbiased=False))
    if not penalties:
        return torch.tensor(0.0, device=action_probs.device)
    return torch.stack(penalties).mean()


def _evaluate(
    model: RouteJudgmentHead,
    x: torch.Tensor,
    action_y: torch.Tensor,
    reason_y: torch.Tensor,
    why_not_y: torch.Tensor,
    margin_y: torch.Tensor,
) -> Dict[str, float]:
    if x.numel() == 0:
        return {
            "action_accuracy": 0.0,
            "reason_accuracy": 0.0,
            "why_not_accuracy": 0.0,
            "margin_mae": 0.0,
        }
    model.eval()
    with torch.no_grad():
        out = model(x)
        action_pred = out["action_logits"].argmax(dim=-1)
        reason_pred = out["reason_logits"].argmax(dim=-1)
        why_not_pred = out["why_not_logits"].argmax(dim=-1)
        return {
            "action_accuracy": round(float((action_pred == action_y).float().mean().item()), 4),
            "reason_accuracy": round(float((reason_pred == reason_y).float().mean().item()), 4),
            "why_not_accuracy": round(float((why_not_pred == why_not_y).float().mean().item()), 4),
            "margin_mae": round(float(torch.abs(out["margin"] - margin_y).mean().item()), 4),
        }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Train the Gate D route-judgment head on lawful commitment records.")
    ap.add_argument("--route-margin-records", required=True, help="Path to cohort0_residual_alpha_breakthrough_route_margin_records.json")
    ap.add_argument("--joint-batch-manifest", default="", help="Optional path to cohort0_residual_alpha_breakthrough_joint_batch_manifest.json")
    ap.add_argument("--defer-gate-contract", default="", help="Optional path to cohort0_residual_alpha_breakthrough_defer_gate_contract.json")
    ap.add_argument("--route-self-check-contract", default="", help="Optional path to cohort0_residual_alpha_breakthrough_route_self_check_contract.json")
    ap.add_argument("--output-dir", required=True, help="Directory for model artifacts")
    ap.add_argument("--feature-dim", type=int, default=1024)
    ap.add_argument("--hidden-seed", type=int, default=7)
    ap.add_argument("--steps", type=int, default=200)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight-decay", type=float, default=1e-4)
    ap.add_argument("--holdout-fraction", type=float, default=0.2)
    ap.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    cfg = _parse_args(argv)
    set_determinism(cfg.hidden_seed)

    route_margin_path = Path(cfg.route_margin_records).resolve()
    joint_batch_path = Path(cfg.joint_batch_manifest).resolve() if cfg.joint_batch_manifest else None
    defer_gate_path = Path(cfg.defer_gate_contract).resolve() if cfg.defer_gate_contract else None
    self_check_path = Path(cfg.route_self_check_contract).resolve() if cfg.route_self_check_contract else None
    out_dir = Path(cfg.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not route_margin_path.exists():
        raise SystemExit(f"Route margin records not found: {route_margin_path}")

    route_rows = load_rows(route_margin_path)
    if not route_rows:
        raise SystemExit("Route margin records are empty.")

    joint_map = _load_joint_batch_map(joint_batch_path)
    defer_map = _maybe_load_case_map(defer_gate_path)
    self_check_map = _maybe_load_case_map(self_check_path)

    records = [
        _build_case_record(
            row,
            joint_info=joint_map.get(str(row.get("case_id", "")).strip(), {}),
            defer_row=defer_map.get(str(row.get("case_id", "")).strip(), {}),
            self_check_row=self_check_map.get(str(row.get("case_id", "")).strip(), {}),
            feature_dim=cfg.feature_dim,
        )
        for row in route_rows
    ]

    action_labels = sorted({record["lawful_action"] for record in records})
    reason_labels = sorted({record["dominance_reason_code_primary"] for record in records})
    why_not_labels = sorted({record["why_not_target_label"] for record in records})
    action_to_idx = {label: idx for idx, label in enumerate(action_labels)}
    reason_to_idx = {label: idx for idx, label in enumerate(reason_labels)}
    why_not_to_idx = {label: idx for idx, label in enumerate(why_not_labels)}

    abstain_idx = action_to_idx.get(ACTION_ABSTAIN, None)

    train_idx, holdout_idx, geometry_ids = _split_geometries(records, cfg.holdout_fraction)

    if cfg.device == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    elif cfg.device == "cuda":
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")

    x = torch.stack([record["x"] for record in records]).to(device)
    action_y = torch.tensor([action_to_idx[record["lawful_action"]] for record in records], dtype=torch.long, device=device)
    reason_y = torch.tensor([reason_to_idx[record["dominance_reason_code_primary"]] for record in records], dtype=torch.long, device=device)
    why_not_y = torch.tensor([why_not_to_idx[record["why_not_target_label"]] for record in records], dtype=torch.long, device=device)
    margin_y = torch.tensor([record["expected_route_margin"] for record in records], dtype=torch.float32, device=device)
    runner_up_y = torch.tensor(
        [action_to_idx.get(record["runner_up_action"], action_to_idx[record["lawful_action"]]) for record in records],
        dtype=torch.long,
        device=device,
    )
    sample_weights = torch.tensor([record["sample_weight"] for record in records], dtype=torch.float32, device=device)

    train_tensor = torch.tensor(train_idx, dtype=torch.long, device=device)
    holdout_tensor = torch.tensor(holdout_idx, dtype=torch.long, device=device) if holdout_idx else None

    model = RouteJudgmentHead(
        feature_dim=cfg.feature_dim,
        action_classes=len(action_labels),
        reason_classes=len(reason_labels),
        why_not_classes=len(why_not_labels),
    ).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)

    for _ in range(cfg.steps):
        model.train()
        optimizer.zero_grad(set_to_none=True)
        out = model(x[train_tensor])
        train_action_y = action_y[train_tensor]
        train_reason_y = reason_y[train_tensor]
        train_why_not_y = why_not_y[train_tensor]
        train_margin_y = margin_y[train_tensor]
        train_runner_up_y = runner_up_y[train_tensor]
        train_weights = sample_weights[train_tensor]

        action_loss = _weighted_mean(F.cross_entropy(out["action_logits"], train_action_y, reduction="none"), train_weights)
        reason_loss = _weighted_mean(F.cross_entropy(out["reason_logits"], train_reason_y, reduction="none"), train_weights)
        why_not_loss = _weighted_mean(F.cross_entropy(out["why_not_logits"], train_why_not_y, reduction="none"), train_weights)
        margin_loss = _weighted_mean(F.smooth_l1_loss(out["margin"], train_margin_y, reduction="none"), train_weights)

        chosen_logits = out["action_logits"].gather(1, train_action_y.unsqueeze(1)).squeeze(1)
        runner_up_logits = out["action_logits"].gather(1, train_runner_up_y.unsqueeze(1)).squeeze(1)
        pairwise_margin_loss = _weighted_mean(F.relu(train_margin_y - (chosen_logits - runner_up_logits)), train_weights)

        if abstain_idx is None:
            unlawful_abstention_penalty = torch.tensor(0.0, device=device)
        else:
            abstain_probs = torch.softmax(out["action_logits"], dim=-1)[:, abstain_idx]
            non_abstain_mask = (train_action_y != abstain_idx).float()
            if float(non_abstain_mask.sum().item()) == 0.0:
                unlawful_abstention_penalty = torch.tensor(0.0, device=device)
            else:
                unlawful_abstention_penalty = (abstain_probs * non_abstain_mask).sum() / non_abstain_mask.sum()

        consistency_penalty = _consistency_penalty(
            torch.softmax(out["action_logits"], dim=-1),
            out["margin"],
            [records[idx]["consistency_group_id"] for idx in train_idx],
        )

        total_loss = (
            action_loss
            + (0.65 * reason_loss)
            + (0.45 * why_not_loss)
            + (0.40 * margin_loss)
            + (0.30 * pairwise_margin_loss)
            + (0.10 * unlawful_abstention_penalty)
            + (0.08 * consistency_penalty)
        )
        total_loss.backward()
        optimizer.step()

    train_metrics = _evaluate(
        model,
        x[train_tensor],
        action_y[train_tensor],
        reason_y[train_tensor],
        why_not_y[train_tensor],
        margin_y[train_tensor],
    )
    holdout_metrics = _evaluate(
        model,
        x[holdout_tensor] if holdout_tensor is not None else x.new_zeros((0, x.shape[1])),
        action_y[holdout_tensor] if holdout_tensor is not None else torch.zeros(0, dtype=torch.long, device=device),
        reason_y[holdout_tensor] if holdout_tensor is not None else torch.zeros(0, dtype=torch.long, device=device),
        why_not_y[holdout_tensor] if holdout_tensor is not None else torch.zeros(0, dtype=torch.long, device=device),
        margin_y[holdout_tensor] if holdout_tensor is not None else torch.zeros(0, dtype=torch.float32, device=device),
    )

    artifact_path = out_dir / "gate_d_route_judgment_head.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "feature_dim": cfg.feature_dim,
            "action_labels": action_labels,
            "reason_labels": reason_labels,
            "why_not_labels": why_not_labels,
            "geometry_ids": geometry_ids,
            "seed": cfg.hidden_seed,
        },
        artifact_path,
    )
    label_map_path = out_dir / "label_maps.json"
    label_map_path.write_text(
        json.dumps(
            {
                "action_labels": action_labels,
                "reason_labels": reason_labels,
                "why_not_labels": why_not_labels,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema_id": "kt.gate_d.route_judgment_head_train_manifest.v1",
        "status": "PASS",
        "route_margin_records_path": str(route_margin_path),
        "route_margin_records_sha256": sha256_file(route_margin_path),
        "joint_batch_manifest_path": str(joint_batch_path) if joint_batch_path else "",
        "defer_gate_contract_path": str(defer_gate_path) if defer_gate_path else "",
        "route_self_check_contract_path": str(self_check_path) if self_check_path else "",
        "seed": cfg.hidden_seed,
        "feature_dim": cfg.feature_dim,
        "steps": cfg.steps,
        "lr": cfg.lr,
        "weight_decay": cfg.weight_decay,
        "device": str(device),
        "holdout_rule": "geometry_disjoint_holdout_required",
        "train_case_count": len(train_idx),
        "holdout_case_count": len(holdout_idx),
        "geometry_ids": geometry_ids,
        "loss_terms": [
            "cross_entropy_action",
            "cross_entropy_reason",
            "cross_entropy_why_not",
            "pairwise_margin_loss",
            "unlawful_abstention_penalty",
            "masked_and_mirror_consistency_penalty",
            "restraint_replay_floor",
        ],
        "metrics": {
            "train": train_metrics,
            "holdout": holdout_metrics,
        },
        "artifacts": {
            "model_path": str(artifact_path),
            "model_sha256": sha256_file(artifact_path),
            "label_map_path": str(label_map_path),
            "label_map_sha256": sha256_file(label_map_path),
        },
    }
    manifest_path = out_dir / "train_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("TRAIN_OK")
    print("OUT_DIR", str(out_dir))
    print("ROUTE_MARGIN_SHA256", manifest["route_margin_records_sha256"])
    print("HEAD_SHA256", manifest["artifacts"]["model_sha256"])


if __name__ == "__main__":
    main()
