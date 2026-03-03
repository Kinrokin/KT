from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from tools.operator.serious_layer.common import canonical_json, require_list, require_str, sha256_obj, sha256_text
from tools.verification.fl3_validators import FL3ValidationError


@dataclass(frozen=True)
class Probe:
    probe_id: str
    family: str
    profile: str
    root_layer: str
    notes: str

    def as_declared_case(self) -> Dict[str, Any]:
        gated_ref = "sha256:" + sha256_text("gated:" + self.probe_id)
        return {
            "case_id": f"PROBE_{self.probe_id}",
            "attack_id": f"PROBE/{self.probe_id}",
            "root_layer": self.root_layer,
            "description": f"Hash-ref-only probe ({self.family}, {self.profile}).",
            "prompt": "[GATED] probe payload (hash-ref only; supplied out-of-repo).",
            "expected_behavior": "EXECUTE_GATED_PROBE",
            "replay_required": True,
            "sensitive_payload_hash_ref": gated_ref,
            "gated": True,
        }


@dataclass(frozen=True)
class ProbePack:
    probe_pack_id: str
    domain: str
    version: str
    probes: List[Probe]
    source_path: str


def load_probe_pack_descriptor(path: Path) -> ProbePack:
    p = path.resolve()
    if not p.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: probe pack descriptor missing: {p.as_posix()}")
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable probe pack descriptor JSON: {p.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError("FAIL_CLOSED: probe pack descriptor must be a JSON object")

    schema_id = str(obj.get("schema_id", "")).strip()
    if schema_id != "kt.operator.serious_layer.probe_pack_descriptor.unbound.v1":
        raise FL3ValidationError("FAIL_CLOSED: probe pack descriptor schema_id mismatch")

    pack_id = require_str(obj, "probe_pack_id")
    domain = require_str(obj, "domain")
    version = require_str(obj, "version")
    probes_raw = require_list(obj, "probes")

    probes: List[Probe] = []
    seen: set[str] = set()
    for item in probes_raw:
        if not isinstance(item, dict):
            raise FL3ValidationError("FAIL_CLOSED: probe entry must be an object")
        probe_id = require_str(item, "probe_id")
        if probe_id in seen:
            raise FL3ValidationError("FAIL_CLOSED: duplicate probe_id in probe pack descriptor")
        seen.add(probe_id)
        probes.append(
            Probe(
                probe_id=probe_id,
                family=str(item.get("family", "")).strip(),
                profile=require_str(item, "profile"),
                root_layer=str(item.get("root_layer", "")).strip() or "behavior_plane",
                notes=str(item.get("notes", "")).strip(),
            )
        )

    probes = sorted(probes, key=lambda pr: pr.probe_id)
    return ProbePack(probe_pack_id=pack_id, domain=domain, version=version, probes=probes, source_path=p.as_posix())


def load_probe_payloads_jsonl(path: Path) -> Dict[str, str]:
    p = path.resolve()
    if not p.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: probe payloads file missing: {p.as_posix()}")
    rows: Dict[str, str] = {}
    for line in p.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError("FAIL_CLOSED: probe payloads JSONL contains invalid JSON line") from exc
        if not isinstance(obj, dict):
            raise FL3ValidationError("FAIL_CLOSED: probe payloads JSONL line must be an object")
        probe_id = str(obj.get("probe_id", "")).strip()
        payload = obj.get("payload")
        if not probe_id or not isinstance(payload, str):
            raise FL3ValidationError("FAIL_CLOSED: probe payload entry must include probe_id (str) and payload (str)")
        if probe_id in rows:
            raise FL3ValidationError("FAIL_CLOSED: duplicate probe_id in probe payloads JSONL")
        rows[probe_id] = payload
    if not rows:
        raise FL3ValidationError("FAIL_CLOSED: probe payloads JSONL is empty")
    return rows


def payload_sha256(payload: str) -> str:
    h = hashlib.sha256()
    h.update(str(payload).encode("utf-8"))
    return h.hexdigest()


def payload_bundle_sha256(payload_sha_by_probe: Mapping[str, str]) -> str:
    rows = [{"probe_id": k, "payload_sha256": payload_sha_by_probe[k]} for k in sorted(payload_sha_by_probe.keys())]
    return sha256_obj({"schema_id": "kt.operator.probe_payload_bundle_hash.unbound.v1", "rows": rows})


def select_probes_to_execute(*, pack: ProbePack, seed: int, case_budget: int) -> List[Probe]:
    if case_budget <= 0:
        return []

    def score(p: Probe) -> str:
        return sha256_text(p.probe_id + "|" + str(int(seed)))

    probes = sorted(pack.probes, key=lambda pr: (score(pr), pr.probe_id))
    return probes[: min(int(case_budget), len(probes))]


def safe_payload_fingerprint(*, payload: str) -> Dict[str, Any]:
    """
    Return a safe fingerprint without returning the payload text.
    """
    txt = str(payload)
    return {
        "bytes_len": len(txt.encode("utf-8")),
        "sha256": payload_sha256(txt),
    }


def probe_pack_descriptor_default_fintech(repo_root: Path) -> Path:
    return (repo_root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "serious_layer" / "probe_packs" / "FINTECH_PROBE_PACK_HASHREF_V1.json").resolve()

