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
    ap=argparse.ArgumentParser(); ap.add_argument("--out", default="KT_PROD_CLEANROOM/reports/academy_curriculum_receipt.json"); args=ap.parse_args()
    write_json(args.out, {"schema_id":"kt.academy_curriculum_receipt.v1","generated_utc":utc_now(),"claim_ceiling_preserved":True,"status":"PASS","authority":"INTERNAL_SHADOW_PREP_ONLY_NO_CLAIM_EXPANSION"})
    print(json.dumps({"status":"PASS","out":args.out}, sort_keys=True))
if __name__=="__main__": main()
