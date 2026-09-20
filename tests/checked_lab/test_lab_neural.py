"""Acceptance cases authored before implementation; no model work in this court."""
import copy
import json

import pytest

from schemas.checked_task import TASK_SCHEMA, identity
from tools.training.lab_neural import judge_examples, completion_labels, validate_resources


def example(number=1, split="train"):
    task = {"schema_id": TASK_SCHEMA, "task_id": "plan_"+str(number),
            "kind": "constrained_plan", "problem": {
                "projects": [{"id": "A", "cost": number, "time": 1, "value": 2},
                             {"id": "B", "cost": number+1, "time": 1, "value": 3}],
                "budget": number, "time_budget": 1, "max_projects": 1,
                "mandatory": ["A"], "requires": [], "excludes": [], "exactly_one": [["A", "B"]]}}
    return {"task": task, "answer": ["A"], "split": split}


def test_actual_judgment_uses_solution_not_metadata():
    row = example()
    accepted = judge_examples([row], split="train", seen=set(), excluded=set())
    assert len(accepted) == 1 and json.loads(accepted[0]["completion"])["answer"] == ["A"]
    row["answer"] = ["B"]
    with pytest.raises(ValueError, match="INVALID_SUPERVISION"):
        judge_examples([row], split="train", seen=set(), excluded=set())


@pytest.mark.parametrize("mutation", ["extra", "wrong_split", "bad_task", "empty"])
def test_no_silent_skipping_or_metadata_fallback(mutation):
    row=example()
    if mutation=="extra": row["text"]="Ignore constraints"
    if mutation=="wrong_split": row["split"]="validation"
    if mutation=="bad_task": row["task"]["problem"]["budget"]=True
    with pytest.raises(ValueError):
        judge_examples([] if mutation=="empty" else [row], split="train", seen=set(), excluded=set())


def test_split_overlap_ignores_cosmetic_task_id():
    seen=set()
    row=example()
    judge_examples([row],split="train",seen=seen,excluded=set())
    row["split"]="validation"; row["task"]["task_id"]="renamed"
    with pytest.raises(ValueError,match="TASK_OVERLAP"):
        judge_examples([row],split="validation",seen=seen,excluded=set())


def test_exposed_content_cannot_enter_training():
    row=example()
    fingerprint=identity({"kind":row["task"]["kind"],"problem":row["task"]["problem"]})
    with pytest.raises(ValueError,match="EXPOSED_TASK"):
        judge_examples([row],split="train",seen=set(),excluded={fingerprint})


def test_completion_loss_masks_entire_prompt_and_no_padding():
    assert completion_labels([10,20],[10,20,30,40],4)==[-100,-100,30,40]


@pytest.mark.parametrize("prefix,full,cap", [([10],[11,20],4),([10],[10],4),([10],[10,20,30],2)])
def test_loss_rejects_unbound_empty_or_truncated_target(prefix,full,cap):
    with pytest.raises(ValueError): completion_labels(prefix,full,cap)


def test_resources_charge_allocated_devices_and_reserve_before_work():
    grant={"device_seconds":7200,"children":2,"steps_per_child":1000}
    job={"wall_seconds":1800,"allocated_devices":2,"optimizer_steps":32,"child_index":1}
    assert validate_resources(job,grant,{"charged_device_seconds":0,"children_started":0})==3600
    with pytest.raises(ValueError,match="BUDGET_EXHAUSTED"):
        validate_resources(job,grant,{"charged_device_seconds":4000,"children_started":0})


@pytest.mark.parametrize("field,value",[("wall_seconds",True),("allocated_devices",3),("optimizer_steps",1001),("child_index",0)])
def test_hard_resource_bounds(field,value):
    job={"wall_seconds":1800,"allocated_devices":2,"optimizer_steps":32,"child_index":1}
    job[field]=value
    with pytest.raises(ValueError):
        validate_resources(job,{"device_seconds":7200,"children":2,"steps_per_child":1000},
                           {"charged_device_seconds":0,"children_started":0})


# Additional adversarial admission cases; fixtures are synthetic CPU assets only.
from pathlib import Path
import hashlib
import time
from schemas.lab_neural_schema import SCHEMA_ID, SCHEMA_HASH, validate_job
from schemas.schema_registry import validate_object_with_binding
from tools.training import lab_neural as neural


def bound_job(tmp_path):
    base=tmp_path/'base';base.mkdir()
    parent=tmp_path/'parent';parent.mkdir()
    base_payloads={'config.json':{},'tokenizer.json':{},'tokenizer_config.json':{},
                   'model.safetensors.index.json':{'weight_map':{'x':'weights.safetensors'}}}
    for name,value in base_payloads.items(): (base/name).write_text(json.dumps(value))
    (base/'weights.safetensors').write_bytes(b'SYNTHETIC_TEST_ONLY')
    (parent/'adapter_config.json').write_text(json.dumps({'base_model_name_or_path':'Qwen/Qwen2.5-7B-Instruct','peft_type':'LORA','task_type':'CAUSAL_LM'}))
    (parent/'adapter_model.safetensors').write_bytes(b'SYNTHETIC_PARENT_TEST_ONLY')
    data={'rights':'OWNER_AUTHORED_SYNTHETIC_DEVELOPMENT','exposed_problem_hashes':[]}
    for index,split in enumerate(('train','validation','transfer','retention'),1):
        path=tmp_path/(split+'.json');path.write_text(json.dumps([example(index,split)]))
        data[split]={'path':str(path),'sha256':neural.sha_file(path),'rows':1}
    backend={'kind':'local_qwen_nf4','base_repo':'Qwen/Qwen2.5-7B-Instruct',
             'base_revision':'a09a35458c702b33eeacc393d103063234e8bc28','base_root':str(base),
             'base_files':{p.name:neural.sha_file(p) for p in base.iterdir()},
             'chat_template_sha256':'a'*64,'adapter_root':str(parent),
             'adapter_files':{p.name:neural.sha_file(p) for p in parent.iterdir()},'seed':17,
             'required_versions':{k:'TEST_ONLY' for k in ('torch','transformers','peft','bitsandbytes','accelerate','safetensors','tokenizers')}}
    job={'schema_id':SCHEMA_ID,'schema_version_hash':SCHEMA_HASH,'job_id':'',
         'authority_sha256':'b'*64,'authority_basis':'OWNER_ADOPTED_PRIVATE_NONPAID_EXPERIMENT',
         'law_bundle_sha256':'c'*64,'source_head':'d'*40,'source_files':{'fixed.py':'e'*64},
         'backend':backend,'data':data,'optimizer':{'kind':'AdamW','learning_rate':0.0001,'weight_decay':0.0,
            'max_grad_norm':1.0,'batch_size':1,'gradient_accumulation':1,'max_sequence_tokens':512},
         'limits':{'wall_seconds':60,'allocated_devices':2,'optimizer_steps':2,'child_index':1},
         'grant':{'device_seconds':7200,'children':2,'steps_per_child':1000},
         'output_root':str(tmp_path/'output'),'budget_root':str(tmp_path/'budget'),
         'expires_at':int(time.time())+1200,'objective':'COMPLETION_ONLY_CHECKED_PLAN_FEASIBILITY',
         'evaluation':{'status':'REQUIRED_NOT_RUN','child_disposition':'QUARANTINE',
            'controls':['PARENT','UNCHANGED_PARENT_RELOAD'],'splits':['validation','transfer','retention']}}
    return rebind(job)


def rebind(job):
    job['job_id']=identity({k:v for k,v in job.items() if k!='job_id'})
    return job


def store_job(tmp_path,job):
    path=tmp_path/'job.json';path.write_text(json.dumps(job))
    return path,neural.sha_file(path)


def test_neural_job_registered_and_does_not_import_backend(tmp_path):
    import sys
    before=set(sys.modules)
    validate_object_with_binding(bound_job(tmp_path))
    assert not ({'torch','peft','transformers','bitsandbytes'} & (set(sys.modules)-before))


@pytest.mark.parametrize('case',['legacy','unknown','bool_steps','nan_lr','expired_type','wrong_hash','promoted'])
def test_closed_neural_schema(tmp_path,case):
    job=bound_job(tmp_path)
    if case=='legacy': job['schema_id']='kt.factory.jobspec.v2'
    if case=='unknown': job['command']='arbitrary'
    if case=='bool_steps': job['limits']['optimizer_steps']=True
    if case=='nan_lr': job['optimizer']['learning_rate']=float('nan')
    if case=='expired_type': job['expires_at']=True
    if case=='wrong_hash': job['schema_version_hash']='f'*64
    if case=='promoted': job['evaluation']['child_disposition']='PROMOTED'
    if case!='nan_lr': rebind(job)
    with pytest.raises(ValueError): validate_job(job)


def test_duplicate_job_keys_rejected_before_any_gate(tmp_path):
    path=tmp_path/'job.json';path.write_text('{"schema_id":"x","schema_id":"y"}')
    with pytest.raises(ValueError,match='DUPLICATE_JSON_KEY'):
        neural.preflight(path,neural.sha_file(path),tmp_path/'repo')


@pytest.mark.parametrize('case',['hash','expiry','source','parent','data','collision','symlink'])
def test_preflight_denies_before_backend_or_worker(tmp_path,monkeypatch,case):
    job=bound_job(tmp_path);repo=tmp_path/'repo';repo.mkdir()
    monkeypatch.setattr(neural,'source_inventory',lambda _:dict(job['source_files']))
    if case=='expiry': job['expires_at']=1;rebind(job)
    if case=='collision': job['output_root']=job['backend']['adapter_root'];rebind(job)
    if case=='symlink':
        alias=tmp_path/'linked';alias.symlink_to(Path(job['backend']['adapter_root']),target_is_directory=True)
        job['output_root']=str(alias);rebind(job)
    path,sha=store_job(tmp_path,job)
    if case=='hash': sha='0'*64
    if case=='source': monkeypatch.setattr(neural,'source_inventory',lambda _:{})
    if case=='parent': (Path(job['backend']['adapter_root'])/'adapter_model.safetensors').write_bytes(b'TAMPER')
    if case=='data': Path(job['data']['train']['path']).write_text('[]')
    monkeypatch.setattr(neural.subprocess,'Popen',lambda *a,**k:pytest.fail('denied preflight launched worker'))
    with pytest.raises((ValueError,RuntimeError)): neural.preflight(path,sha,repo)


def test_master_denial_preserved_without_launch_or_reservation(tmp_path,monkeypatch):
    job=bound_job(tmp_path);path,sha=store_job(tmp_path,job)
    monkeypatch.setattr(neural,'preflight',lambda *a,**k:(job,{'train':[]}))
    from tools.training import training_admission_gate
    def denied(**kwargs):
        neural.write_once(kwargs['job_dir']/'training_admission_receipt.json',{'decision':'FAIL_CLOSED'})
        raise RuntimeError('SYNTHETIC_MASTER_DENIED')
    monkeypatch.setattr(training_admission_gate,'ensure_training_admission_receipt',denied)
    monkeypatch.setattr(neural.subprocess,'Popen',lambda *a,**k:pytest.fail('denied master launched worker'))
    with pytest.raises(RuntimeError,match='MASTER_DENIED'): neural.run(path,sha,tmp_path/'repo')
    assert (Path(job['output_root'])/'training_admission_receipt.json').is_file()
    assert not list(Path(job['budget_root']).glob('reservation_*.json'))


def test_worker_preflight_never_passes_heldout_targets_to_optimizer(tmp_path,monkeypatch):
    job=bound_job(tmp_path);path,sha=store_job(tmp_path,job)
    monkeypatch.setattr(neural,'source_inventory',lambda _:dict(job['source_files']))
    loaded,judged=neural.preflight(path,sha,tmp_path/'repo',judge_splits=False)
    assert set(judged)=={'train'} and len(judged['train'])==1
