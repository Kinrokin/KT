"""
KT Coverage Validator
Fail-closed enforcement of ROTATION_RULESET_V1.json

Scope:
- Tooling-only
- Deterministic
- No kernel / governance mutation
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List


class CoverageValidationError(Exception):
    """Raised on hard validation failures (missing fields, invalid IDs, etc.)."""


class CoverageValidator:
    def __init__(self, ruleset_path: Path):
        self.ruleset_path = ruleset_path
        self.ruleset = self._load_ruleset()
        self.codes = self.ruleset["verdict_codes"]

    # -------------------------
    # Public API
    # -------------------------

    def validate_crucible(self, coverage: Dict[str, Any]) -> Dict[str, Any]:
        return self._validate(
            level="crucible",
            coverage=coverage,
            constraints=self.ruleset["crucible_constraints"],
            required_fields=self.ruleset["required_coverage_fields"],
        )

    def validate_epoch(self, coverage: Dict[str, Any]) -> Dict[str, Any]:
        return self._validate(
            level="epoch",
            coverage=coverage,
            constraints=self.ruleset["epoch_constraints"],
            required_fields=None,
        )

    def validate_cycle(self, coverage: Dict[str, Any]) -> Dict[str, Any]:
        return self._validate(
            level="cycle",
            coverage=coverage,
            constraints=self.ruleset["cycle_constraints"],
            required_fields=None,
        )

    # -------------------------
    # Core validation pipeline
    # -------------------------

    def _validate(
        self,
        *,
        level: str,
        coverage: Dict[str, Any],
        constraints: Dict[str, Any],
        required_fields: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        failures: List[str] = []

        # 1) Required fields (fail immediately)
        if required_fields:
            self._check_required_fields(coverage, required_fields)

        # 2) Canonical ID regex enforcement
        self._check_canonical_ids(coverage)

        # 3) Receipts enforcement
        self._check_receipts(coverage)

        # 4) Forbidden / required tags
        self._check_required_and_forbidden_tags(coverage, constraints)

        # 5) Numeric thresholds
        failures += self._check_thresholds(coverage, constraints)

        # 6) Sequence rotation
        failures += self._check_sequence_rotation(coverage, constraints)

        # 7) Bundles
        failures += self._check_bundles(coverage, constraints)

        if failures:
            return self._fail(self.codes["FAIL_THRESHOLD"], failures)

        return {"verdict": self.codes["PASS"], "failures": []}

    # -------------------------
    # Load & helpers
    # -------------------------

    def _load_ruleset(self) -> Dict[str, Any]:
        data = json.loads(self.ruleset_path.read_text())
        if not data.get("fail_closed", False):
            raise CoverageValidationError("Ruleset must be fail_closed=true")
        return data

    def _fail(self, code: str, failures: List[str]) -> Dict[str, Any]:
        return {"verdict": code, "failures": failures}

    # -------------------------
    # Checks
    # -------------------------

    def _check_required_fields(self, coverage: Dict[str, Any], required: Dict[str, Any]):
        for field in required["crucible_coverage_required"]:
            if field not in coverage:
                raise CoverageValidationError(f"{self.codes['FAIL_MISSING_FIELD']}: {field}")

        observed = coverage.get("observed", {})
        for field in required["observed_required"]:
            if field not in observed:
                raise CoverageValidationError(f"{self.codes['FAIL_MISSING_FIELD']}: observed.{field}")

        counts = observed.get("counts", {})
        for field in required["counts_required"]:
            if field not in counts:
                raise CoverageValidationError(f"{self.codes['FAIL_MISSING_FIELD']}: counts.{field}")

        dominance = observed.get("dominance", {})
        for field in required["dominance_required"]:
            if field not in dominance:
                raise CoverageValidationError(f"{self.codes['FAIL_MISSING_FIELD']}: dominance.{field}")

    def _check_canonical_ids(self, coverage: Dict[str, Any]):
        patterns = self.ruleset["canonical_ids"]["id_format"]

        def check_list(values: List[str], pattern: str, label: str):
            rx = re.compile(pattern)
            for v in values:
                if not rx.match(v):
                    raise CoverageValidationError(f"{self.codes['FAIL_INVALID_ID']}: {label}={v}")

        obs = coverage.get("observed", {})
        check_list(obs.get("domains", []), patterns["domain"], "domain")
        check_list(obs.get("subdomains", []), patterns["subdomain"], "subdomain")
        check_list(obs.get("microdomains", []), patterns["microdomain"], "microdomain")
        check_list(obs.get("reasoning_modes", []), patterns["reasoning"], "reasoning")
        check_list(obs.get("modalities", []), patterns["modality"], "modality")
        check_list(obs.get("tools", []), patterns["tool"], "tool")

    def _check_receipts(self, coverage: Dict[str, Any]):
        proof = coverage.get("proof", {})
        receipts = proof.get("receipts", [])
        required = set(self.ruleset["receipts_policy"]["required_receipt_types"])
        present = set(r["type"] for r in receipts if "type" in r)

        if not required.issubset(present):
            raise CoverageValidationError(self.codes["FAIL_RECEIPT_MISSING"])

        sha_rx = re.compile(self.ruleset["receipts_policy"]["sha256_format"])
        for r in receipts:
            if "sha256" not in r or not sha_rx.match(r["sha256"]):
                raise CoverageValidationError(self.codes["FAIL_RECEIPT_MISSING"])

    def _check_required_and_forbidden_tags(
        self, coverage: Dict[str, Any], constraints: Dict[str, Any]
    ):
        obs = coverage.get("observed", {})

        req = constraints.get("required_tags", {})
        forb = constraints.get("forbidden_tags", {})

        for k, vals in req.items():
            for v in vals:
                if v not in obs.get(k, []):
                    raise CoverageValidationError(f"{self.codes['FAIL_REQUIRED_TAG']}: {k}:{v}")

        for k, vals in forb.items():
            for v in vals:
                if v in obs.get(k, []):
                    raise CoverageValidationError(f"{self.codes['FAIL_FORBIDDEN_TAG']}: {k}:{v}")

    def _check_thresholds(self, coverage: Dict[str, Any], constraints: Dict[str, Any]) -> List[str]:
        failures: List[str] = []
        obs = coverage.get("observed", {})
        counts = obs.get("counts", {})
        dom = obs.get("dominance", {})
        thresholds = constraints.get("thresholds", {})

        def check_min(key, actual):
            if actual < thresholds[key]:
                failures.append(f"{key}<{thresholds[key]}")

        def check_max(key, actual):
            if actual > thresholds[key]:
                failures.append(f"{key}>{thresholds[key]}")

        for key in thresholds:
            if key.startswith("min_"):
                field = key.replace("min_", "")
                actual = counts.get(field) if field in counts else dom.get(field)
                check_min(key, actual)
            if key.startswith("max_"):
                field = key.replace("max_", "")
                actual = dom.get(field)
                check_max(key, actual)

        return failures

    def _check_sequence_rotation(
        self, coverage: Dict[str, Any], constraints: Dict[str, Any]
    ) -> List[str]:
        failures: List[str] = []
        if not constraints.get("sequence_rotation", {}).get("enabled", False):
            return failures

        seq = coverage.get("sequence")
        if seq is None:
            failures.append("sequence_missing")
            return failures

        max_dom = constraints["sequence_rotation"].get("max_consecutive_same_domain", 1)
        count = 1
        last = None
        for d in seq:
            if d == last:
                count += 1
                if count > max_dom:
                    failures.append("max_consecutive_same_domain")
                    break
            else:
                count = 1
            last = d

        return failures

    def _check_bundles(
        self, coverage: Dict[str, Any], constraints: Dict[str, Any]
    ) -> List[str]:
        failures: List[str] = []
        required_bundles = constraints.get("required_bundles", [])
        if not required_bundles:
            return failures

        obs = coverage.get("observed", {})
        bundles = {b["bundle_id"]: b for b in self.ruleset["bundle_library"]}

        for bid in required_bundles:
            b = bundles.get(bid)
            if not b:
                failures.append(f"bundle_missing:{bid}")
                continue

            for k, vals in b["required_tags"].items():
                for v in vals:
                    if v not in obs.get(k, []):
                        failures.append(f"bundle_tag_missing:{bid}:{v}")

        return failures
