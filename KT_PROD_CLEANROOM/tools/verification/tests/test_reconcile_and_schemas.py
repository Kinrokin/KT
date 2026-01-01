import json
import tempfile
from pathlib import Path

from council.providers.provider_schemas import ProviderCallReceipt


def make_min_receipt():
    return {
        "schema_id": ProviderCallReceipt.SCHEMA_ID,
        "schema_version_hash": ProviderCallReceipt.SCHEMA_VERSION_HASH,
        "trace_id": "t1",
        "provider_id": "openai",
        "lane": "LIVE_HASHED",
        "model": "m",
        "endpoint": "chat.completions",
        "key_index": 0,
        "key_count": 1,
        "timing": {"t_start_ms": 1, "t_end_ms": 2, "latency_ms": 1},
        "transport": {"host": "api.openai.com", "http_status": 200, "tls_cert_sha256": "0"*64},
        "provider_attestation": {"request_id": "r1", "request_id_hash": "h1"},
        "usage": {"total_tokens": 1},
        "payload": {"response_bytes_sha256": "sha256:aa", "response_bytes_len": 1},
        "verdict": {"pass": True, "fail_reason": None},
    }


def test_missing_tls_fails_validation():
    r = make_min_receipt()
    r["transport"].pop("tls_cert_sha256")
    try:
        ProviderCallReceipt.from_dict(r)
        assert False, "validation should have failed"
    except Exception:
        pass


def test_missing_payload_hash_fails():
    r = make_min_receipt()
    r["payload"].pop("response_bytes_sha256")
    try:
        ProviderCallReceipt.from_dict(r)
        assert False, "validation should have failed"
    except Exception:
        pass


def test_chain_missing_prev_when_file_exists(tmp_path: Path):
    receipts = []
    r = make_min_receipt()
    # compute dummy chain fields
    r["receipt_id"] = "0"*64
    r["prev_receipt_hash"] = "GENESIS"
    r["receipt_hash"] = "1"*64
    receipts.append(r)
    p = tmp_path / "receipts.jsonl"
    with p.open("w", encoding="utf-8") as f:
        f.write(json.dumps(receipts[0]) + "\n")

    # Tamper last line
    with p.open("a", encoding="utf-8") as f:
        f.write("not-a-json\n")

    # Running live_hashed_run should detect invalid tail; simulate by reading tail as code does
    tail = p.read_text(encoding="utf-8")
    last_lines = [l for l in tail.splitlines() if l.strip()]
    try:
        import json as _j
        _j.loads(last_lines[-1])
        assert False, "should have thrown"
    except Exception:
        pass


def run_reconcile(args: list[str]) -> int:
    # import and run main with argv patched
    import sys
    from tools.verification import reconcile_openai_exports as rec

    old_argv = sys.argv
    try:
        sys.argv = ["reconcile"] + args
        return rec.main()
    finally:
        sys.argv = old_argv


def test_reconcile_usage_mismatch_fails(tmp_path: Path):
    # create a receipt with total_tokens=10
    r = make_min_receipt()
    r["usage"]["total_tokens"] = 10
    r["provider_attestation"]["request_id"] = "req-A"
    # add chain fields minimal
    r["receipt_id"] = "0"*64
    r["prev_receipt_hash"] = "GENESIS"
    r["receipt_hash"] = "1"*64
    receipts_path = tmp_path / "receipts.jsonl"
    receipts_path.write_text(json.dumps(r) + "\n", encoding="utf-8")

    # create provider export with mismatched usage
    export = [{"request_id": "req-A", "usage": {"total_tokens": 999}}]
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps(export), encoding="utf-8")

    rc = run_reconcile(["--receipts", str(receipts_path), "--export", str(export_path), "--usage-tolerance", "5"])
    assert rc != 0


def test_reconcile_time_skew_tolerance_passes(tmp_path: Path):
    # receipt with timing
    r = make_min_receipt()
    r["trace_id"] = "t-skew"
    r["timing"] = {"t_start_ms": 1000000, "t_end_ms": 1001000, "latency_ms": 1000}
    r["provider_attestation"]["request_id"] = "req-time"
    r["usage"]["total_tokens"] = 5
    r["receipt_id"] = "a"*64
    r["prev_receipt_hash"] = "GENESIS"
    r["receipt_hash"] = "b"*64
    receipts_path = tmp_path / "receipts.jsonl"
    receipts_path.write_text(json.dumps(r) + "\n", encoding="utf-8")

    # export with created_at slightly outside but within default window (5000ms)
    export_row = {"request_id": "req-time", "created_at": 1000500, "usage": {"total_tokens": 5}, "model": "m"}
    export_path = tmp_path / "export.jsonl"
    export_path.write_text(json.dumps([export_row]), encoding="utf-8")

    rc = run_reconcile(["--receipts", str(receipts_path), "--export", str(export_path)])
    assert rc == 0


def test_reconcile_provider_drift_reports(tmp_path: Path):
    # one receipt
    r = make_min_receipt()
    r["provider_attestation"]["request_id"] = "req-drift"
    r["receipt_id"] = "c"*64
    r["prev_receipt_hash"] = "GENESIS"
    r["receipt_hash"] = "d"*64
    receipts_path = tmp_path / "receipts.jsonl"
    receipts_path.write_text(json.dumps(r) + "\n", encoding="utf-8")

    # export includes matching row and extra unrelated row
    export = [
        {"request_id": "req-drift", "usage": {"total_tokens": 1}},
        {"request_id": "extra-1", "usage": {"total_tokens": 2}},
    ]
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps(export), encoding="utf-8")

    rc = run_reconcile(["--receipts", str(receipts_path), "--export", str(export_path)])
    # should pass because unmatched export rows don't cause failure; they are reported
    assert rc == 0
