from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

import jsonschema

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.verification.strict_json import load_no_dupes


AUTHORITY_BUNDLE_SCHEMA_ID = "kt.authority.bundle.v1"
AUTHORITY_SUBJECT_SCHEMA_ID = "kt.authority.subject.v1"
AUTHORITY_ENVELOPE_SCHEMA_ID = "kt.authority.envelope.v1"


def _iter_dict_items(value: Any) -> Iterable[Any]:
    # NOTE: We only treat dictionary keys as forbidden. Values may legitimately
    # contain strings like "generated_utc" in narratives or references.
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _iter_dict_items(v)
    if isinstance(value, list):
        for item in value:
            yield from _iter_dict_items(item)


def assert_subject_is_deterministic(subject: Dict[str, Any], *, forbidden_keys: Iterable[str]) -> None:
    forbid = {str(k) for k in forbidden_keys}
    # Fail closed on volatile keys anywhere in the subject.
    for item in _iter_dict_items(subject):
        if isinstance(item, str) and item in forbid:
            raise RuntimeError(f"FAIL_CLOSED: forbidden key present in authority subject: {item!r}")


def subject_sha256(subject: Dict[str, Any]) -> str:
    if str(subject.get("schema_id", "")).strip() != AUTHORITY_SUBJECT_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: authority subject schema_id mismatch")
    assert_subject_is_deterministic(
        subject,
        forbidden_keys=(
            "created_utc",
            "generated_utc",
            "signature",
            "signatures",
            "certificate",
            "certificates",
            "rekor",
            "transparency",
            "envelope",
            "bundle",
            "bundle_id",
        ),
    )
    return sha256_hex(canonicalize_bytes(subject))


def mint_envelope(
    *,
    subject_sha256_hex: str,
    attestation_mode: str = "NONE",
    generated_utc: str = "",
    signatures: Optional[list[dict]] = None,
    transparency: Optional[dict] = None,
) -> Dict[str, Any]:
    return {
        "schema_id": AUTHORITY_ENVELOPE_SCHEMA_ID,
        "subject_sha256": str(subject_sha256_hex).strip(),
        "generated_utc": str(generated_utc).strip() or utc_now_iso_z(),
        "attestation_mode": str(attestation_mode).strip() or "NONE",
        "signatures": list(signatures or []),
        "transparency": dict(transparency or {}),
    }


def mint_authority_bundle(*, subject: Dict[str, Any], envelope: Dict[str, Any], bundle_id: str = "") -> Dict[str, Any]:
    subj_sha = subject_sha256(subject)
    if str(envelope.get("schema_id", "")).strip() != AUTHORITY_ENVELOPE_SCHEMA_ID:
        raise RuntimeError("FAIL_CLOSED: authority envelope schema_id mismatch")
    if str(envelope.get("subject_sha256", "")).strip() != subj_sha:
        raise RuntimeError("FAIL_CLOSED: envelope.subject_sha256 does not bind to computed subject_sha256")
    if not str(bundle_id).strip():
        bundle_id = f"KT_AUTHORITY_BUNDLE_{subj_sha[:16]}"
    return {
        "schema_id": AUTHORITY_BUNDLE_SCHEMA_ID,
        "bundle_id": str(bundle_id).strip(),
        "subject_sha256": subj_sha,
        "subject": subject,
        "envelope": envelope,
    }


def load_authority_bundle_schema(*, root: Optional[Path] = None) -> Dict[str, Any]:
    base = root or repo_root()
    schema_path = (base / "KT_PROD_CLEANROOM" / "governance" / "authority_bundle.schema.json").resolve()
    schema = load_no_dupes(schema_path)
    if not isinstance(schema, dict):
        raise RuntimeError("FAIL_CLOSED: authority bundle schema must be a JSON object")
    return schema


def validate_authority_bundle(bundle: Dict[str, Any], *, schema: Dict[str, Any]) -> None:
    jsonschema.validate(instance=bundle, schema=schema)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Mint and validate KT authority subject+envelope bundles (WS5 boundary tooling).")
    ap.add_argument("--subject", required=True, help="Path to authority subject JSON.")
    ap.add_argument("--out", required=True, help="Path to write authority bundle JSON.")
    ap.add_argument("--bundle-id", default="", help="Optional explicit bundle_id; default is derived from subject hash.")
    ap.add_argument("--attestation-mode", default="NONE", help="Attestation mode label to embed in the envelope.")
    ap.add_argument("--generated-utc", default="", help="Optional envelope generated_utc; defaults to current UTC.")
    ap.add_argument("--validate", action="store_true", help="Validate bundle against governance schema.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    subject_path = Path(str(args.subject)).expanduser()
    if not subject_path.is_absolute():
        subject_path = (root / subject_path).resolve()
    subject_obj = load_no_dupes(subject_path)
    if not isinstance(subject_obj, dict):
        raise SystemExit("FAIL_CLOSED: subject must be a JSON object")

    subj_sha = subject_sha256(subject_obj)
    envelope_obj = mint_envelope(
        subject_sha256_hex=subj_sha,
        attestation_mode=str(args.attestation_mode),
        generated_utc=str(args.generated_utc),
    )
    bundle_obj = mint_authority_bundle(subject=subject_obj, envelope=envelope_obj, bundle_id=str(args.bundle_id))

    if bool(args.validate):
        schema = load_authority_bundle_schema(root=root)
        validate_authority_bundle(bundle_obj, schema=schema)

    out_path = Path(str(args.out)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, bundle_obj)
    print(json.dumps({"status": "PASS", "subject_sha256": subj_sha, "bundle_id": bundle_obj["bundle_id"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
