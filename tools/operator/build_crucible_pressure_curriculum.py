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
    ap=argparse.ArgumentParser(); ap.add_argument("--matrix", default="adaptive/crucible_intensity_matrix.json"); ap.add_argument("--out", default="KT_PROD_CLEANROOM/reports/crucible_pressure_curriculum.jsonl"); args=ap.parse_args()
    matrix=read_json(args.matrix); out=pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for item in matrix["pressure_items"]:
            row = {
                **item,
                "schema_id": "kt.crucible_pressure_curriculum.row.v1",
                "generated_utc": utc_now(),
            }
            f.write(json.dumps(row, sort_keys=True)+"\n")
    print(json.dumps({"status":"PASS","rows":len(matrix["pressure_items"]),"out":str(out)}, sort_keys=True))
if __name__=="__main__": main()
