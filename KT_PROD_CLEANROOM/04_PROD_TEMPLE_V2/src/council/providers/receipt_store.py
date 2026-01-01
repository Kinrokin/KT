from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from council.providers.provider_schemas import ProviderCallReceipt


class ReceiptStoreError(RuntimeError):
    pass


def append_receipt_chained(*, receipt: Union[ProviderCallReceipt, dict], receipts_path: Path) -> None:
    receipts_path.parent.mkdir(parents=True, exist_ok=True)
    obj = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
    # Append-only write
    with receipts_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=True) + "\n")
