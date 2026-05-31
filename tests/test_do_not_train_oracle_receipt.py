import json
from pathlib import Path

ROOT = Path.cwd()


def test_do_not_train_oracle_receipt_blocks_adapter_training():
    obj = json.loads((ROOT / "reports/do_not_train_oracle_receipt.json").read_text(encoding="utf-8"))
    assert obj["status"] == "PASS"
    assert obj["adapter_training_authorized"] is False
    assert obj["oracle_rows_authorize_adapter_training"] is False
    assert obj["route_value_distillation_authorized"] is True
