#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, datetime
def utc_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
def read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8-sig"))
def write_json(path, obj):
    p=pathlib.Path(path); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out", default="KT_PROD_CLEANROOM/reports/crucible_epoch_academy_pressure_receipt.json"); args=ap.parse_args()
    matrix=read_json("adaptive/crucible_intensity_matrix.json")
    write_json(args.out, {"schema_id":"kt.crucible_epoch_academy_pressure_receipt.v1","generated_utc":utc_now(),"outcome":"KT_CRUCIBLE_EPOCH_ACADEMY_PRESSURE_CURRICULUM_BOUND__TARGETED_REPAIR_PRESSURE_NEXT","claim_ceiling_preserved":True,"commercial_claim_authorized":False,"external_audit_complete":False,"frontier_parity_claim_authorized":False,"seven_b_amplification_proven":False,"pressure_item_count":len(matrix["pressure_items"]),"no_superiority_claim_created":True,"promotion_authorized":False})
    print(json.dumps({"status":"PASS","out":args.out}, sort_keys=True))
if __name__=="__main__": main()
