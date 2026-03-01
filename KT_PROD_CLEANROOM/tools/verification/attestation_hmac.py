from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Dict, Optional, Tuple


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hmac_key_fingerprint_hex(key_bytes: bytes) -> str:
    return hashlib.sha256(key_bytes).hexdigest()


def hmac_signature_hex(*, key_bytes: bytes, key_id: str, payload_hash: str) -> str:
    msg = _canonical_json({"key_id": key_id, "payload_hash": payload_hash}).encode("utf-8")
    return hmac.new(key_bytes, msg, digestmod=hashlib.sha256).hexdigest()


def env_key_name_for_key_id(key_id: str) -> str:
    safe = re.sub(r"[^A-Z0-9_]", "_", str(key_id).strip().upper())
    return f"KT_HMAC_KEY_{safe}"


def sign_hmac(*, key_bytes: bytes, key_id: str, payload_hash: str) -> Tuple[str, str]:
    """
    Returns (hmac_signature_hex, hmac_key_fingerprint_hex).
    """
    return (
        hmac_signature_hex(key_bytes=key_bytes, key_id=key_id, payload_hash=payload_hash),
        hmac_key_fingerprint_hex(key_bytes),
    )


def verify_hmac_signoff(*, signoff: Dict[str, Any], key_bytes: bytes) -> Tuple[bool, Optional[str]]:
    """
    Returns (ok, error_message_if_any).
    Expects signoff to contain:
      - key_id
      - payload_hash
      - hmac_signature
      - hmac_key_fingerprint
    """
    key_id = str(signoff.get("key_id", "")).strip()
    payload_hash = str(signoff.get("payload_hash", "")).strip()
    got_sig = str(signoff.get("hmac_signature", "")).strip()
    got_fp = str(signoff.get("hmac_key_fingerprint", "")).strip()
    if not key_id or not payload_hash or not got_sig or not got_fp:
        return False, "missing required signoff fields"

    exp_sig, exp_fp = sign_hmac(key_bytes=key_bytes, key_id=key_id, payload_hash=payload_hash)
    if got_fp != exp_fp:
        return False, "hmac_key_fingerprint mismatch"
    if got_sig != exp_sig:
        return False, "hmac_signature mismatch"
    return True, None

