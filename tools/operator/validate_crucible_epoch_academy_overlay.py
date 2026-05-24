#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
LOBES = {
 'strategic_synthesis_lobe','audit_reasoning_lobe','formal_proof_reasoning_lobe','contradiction_paradox_lobe','temporal_chronology_lobe','cross_domain_patterncraft_lobe','grounded_evidence_lobe','regulated_domain_lobe','commercial_operator_lobe','execution_tool_lobe','context_memory_compression_lobe','learning_delta_lobe','adversarial_red_assault_lobe'
}
FORBIDDEN = {'claim_boundary','proof_validator','truth_engine','bio_med_firewall','evaluator_integrity','primitive_invariance','router_control','router_controller','adapter_forge','lobe_trainer','benchmark_evaluator','external_attestation','commercial_boundary'}

def load(rel):
    return json.loads((ROOT/rel).read_text(encoding='utf-8-sig'))

def main():
    failures=[]
    matrix=load('adaptive/crucible_intensity_matrix.json')
    required=set(load('adaptive/crucible_intensity_matrix.schema.json')['required_pressure_item_fields'])
    if matrix.get('claim_ceiling_preserved') is not True:
        failures.append('claim ceiling not preserved in matrix')
    for item in matrix.get('pressure_items',[]):
        missing=required-set(item)
        if missing: failures.append(f"{item.get('id')} missing {sorted(missing)}")
        bad=FORBIDDEN & set(item.get('target_lobes',[]))
        if bad: failures.append(f"{item.get('id')} has forbidden lobe targets {sorted(bad)}")
        if not set(item.get('target_lobes',[])).issubset(LOBES):
            failures.append(f"{item.get('id')} has unknown lobe targets {sorted(set(item.get('target_lobes',[]))-LOBES)}")
        if not item.get('scoring_contract') or not item.get('receipt_contract'):
            failures.append(f"{item.get('id')} missing scoring/receipt contract")
    for rel in ['adaptive/epoch_pressure_schedule.json','adaptive/academy_curriculum_registry.json','registry/artifact_authority_registry_crucible_epoch_academy_pressure_delta_receipt.json']:
        obj=load(rel)
        if obj.get('claim_ceiling_preserved') is not True:
            failures.append(f'{rel} does not preserve claim ceiling')
    print(json.dumps({'status':'FAIL' if failures else 'PASS','failure_count':len(failures),'failures':failures}, indent=2, sort_keys=True))
    return 1 if failures else 0
if __name__ == '__main__':
    sys.exit(main())
