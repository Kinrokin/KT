from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.v17_6_oracle_autopsy_common import json_safe, load_v17_5_evidence, nonselected_diagnosis


if __name__ == "__main__":
    evidence = load_v17_5_evidence()
    payload = {
        "hat": nonselected_diagnosis(evidence["rows"], "base_kt_hat_compact"),
        "math_act": nonselected_diagnosis(evidence["rows"], "math_act_adapter_global"),
    }
    print(json.dumps(json_safe(payload), indent=2, sort_keys=True))
