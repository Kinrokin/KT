#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = {
    'claim_boundary','proof_validator','truth_engine','bio_med_firewall',
    'evaluator_integrity','primitive_invariance','metacognitive_admission',
    'runtime_execution_chain','delta_to_primitive','router_control',
    'router_controller','adapter_forge','lobe_trainer','benchmark_evaluator',
    'external_attestation','commercial_boundary','truth_grounding',
    'claim_compiler','detached_verifier','supply_chain_gate'
}
CLAIM_AUTHORITY_FLAGS = {
    'commercial_claim_authorized',
    'external_audit_complete',
    'external_audit_accepted',
    's_tier_claim_authorized',
    'beyond_sota_claim_authorized',
    'category_leadership_claim_authorized',
    'frontier_parity_claim_authorized',
    'seven_b_amplification_proven',
    'router_superiority_claim_authorized',
    'multi_lobe_superiority_claim_authorized',
    'full_adaptive_orchestration_production_ready',
}

def load(rel):
    return json.loads((ROOT/rel).read_text(encoding='utf-8-sig'))

def canonical_lobes():
    registry = load('adaptive/cognitive_lobe_registry.json')
    return {
        row['lobe_id']
        for row in registry.get('lobes', [])
        if row.get('canonical_lobe') is True and row.get('training_target') is True
    }

def check_claim_boundary(rel, obj, failures):
    if obj.get('claim_ceiling_preserved') is not True:
        failures.append(f'{rel} does not preserve claim ceiling')
    for key in sorted(CLAIM_AUTHORITY_FLAGS):
        if obj.get(key) is True:
            failures.append(f'{rel} authorizes forbidden claim flag {key}')

def main():
    failures=[]
    lobes = canonical_lobes()
    if len(lobes) != 13:
        failures.append(f'canonical lobe registry expected 13 trainable lobes, found {len(lobes)}')
    matrix=load('adaptive/crucible_intensity_matrix.json')
    required=set(load('adaptive/crucible_intensity_matrix.schema.json')['required_pressure_item_fields'])
    check_claim_boundary('adaptive/crucible_intensity_matrix.json', matrix, failures)
    for item in matrix.get('pressure_items',[]):
        missing=required-set(item)
        if missing: failures.append(f"{item.get('id')} missing {sorted(missing)}")
        bad=FORBIDDEN & set(item.get('target_lobes',[]))
        if bad: failures.append(f"{item.get('id')} has forbidden lobe targets {sorted(bad)}")
        if not set(item.get('target_lobes',[])).issubset(lobes):
            failures.append(f"{item.get('id')} has unknown lobe targets {sorted(set(item.get('target_lobes',[]))-lobes)}")
        if not item.get('scoring_contract') or not item.get('receipt_contract'):
            failures.append(f"{item.get('id')} missing scoring/receipt contract")
    for rel in ['adaptive/epoch_pressure_schedule.json','adaptive/academy_curriculum_registry.json','registry/artifact_authority_registry_crucible_epoch_academy_pressure_delta_receipt.json']:
        obj=load(rel)
        check_claim_boundary(rel, obj, failures)
    print(json.dumps({'status':'FAIL' if failures else 'PASS','failure_count':len(failures),'failures':failures}, indent=2, sort_keys=True))
    return 1 if failures else 0
if __name__ == '__main__':
    sys.exit(main())
