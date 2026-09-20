"""Bounded private neural laboratory entry, separate from canonical inference.

Reuses the existing training master valve and strict task checker. Neither a
generic admission receipt nor optimizer completion grants deployment or benefit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from schemas.checked_task import (PROPOSAL_SCHEMA, canonical_bytes, identity, strict_json,
                                  validate_task, check_proposal, build_prompt)
from schemas.lab_neural_schema import validate_job, require, integer, fields, digest, absolute
from schemas.trusted_local_path import assert_no_link_or_reparse_path


def sha_file(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): value.update(block)
    return value.hexdigest()


def write_once(path, value):
    assert_no_link_or_reparse_path(path,label='neural output')
    with path.open('xb') as stream:
        stream.write(canonical_bytes(value)+b'\n');stream.flush();os.fsync(stream.fileno())


def read_pinned(path, sha, limit=16*1024*1024):
    assert_no_link_or_reparse_path(path,label='neural input')
    require(path.is_file() and path.stat().st_size <= limit,'INPUT_SIZE')
    raw=path.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==sha,'INPUT_PIN')
    return strict_json(raw,max_bytes=limit)


def problem_identity(task):
    problem=strict_json(canonical_bytes(task['problem']))
    if task['kind']=='constrained_plan':
        problem['projects']=sorted(problem['projects'],key=lambda p:p['id'])
        problem['mandatory']=sorted(problem['mandatory'])
        # Requires is directed; excludes/exactly_one are unordered sets.
        problem['requires']=sorted(problem['requires'])
        for name in ('excludes','exactly_one'):
            problem[name]=sorted(sorted(group) for group in problem[name])
    return identity({'kind':task['kind'],'problem':problem})


def judge_examples(rows, *, split, seen, excluded):
    require(type(rows) is list and 0 < len(rows) <= 2048,'EXAMPLES')
    accepted=[]
    for row in rows:
        require(type(row) is dict and set(row)=={'task','answer','split'},'EXAMPLE_FIELDS')
        require(row['split']==split,'EXAMPLE_SPLIT')
        task=validate_task(row['task'])
        require(split!='train' or task['kind']=='constrained_plan','TRAIN_TASK_KIND')
        fingerprint=problem_identity(task)
        require(fingerprint not in seen,'TASK_OVERLAP')
        require(fingerprint not in excluded,'EXPOSED_TASK')
        nonce=identity(row)[:32]
        proposal={'schema_id':PROPOSAL_SCHEMA,'task_hash':identity(task),'nonce':nonce,'answer':row['answer']}
        checked=check_proposal(task,proposal,nonce=nonce)
        require(checked['satisfied'],'INVALID_SUPERVISION')
        seen.add(fingerprint)
        accepted.append({'problem_hash':fingerprint,'example_hash':identity(row),
                         'prompt':build_prompt(task,nonce=nonce,history=[]),
                         'completion':canonical_bytes(proposal).decode('utf-8'),
                         'check':checked})
    return accepted


def completion_labels(prefix, full, cap):
    require(type(prefix) is list and type(full) is list and bool(prefix)
            and all(type(x) is int and x >= 0 for x in prefix+full),'TOKEN_IDS')
    require(full[:len(prefix)]==prefix,'TOKEN_BOUNDARY')
    require(len(prefix)<len(full)<=cap,'TARGET_EMPTY_OR_TRUNCATED')
    return [-100]*len(prefix)+full[len(prefix):]


def validate_resources(limits, grant, state):
    for key,low,high in (('wall_seconds',1,7200),('allocated_devices',1,2),('optimizer_steps',1,1000),('child_index',1,2)):
        integer(limits[key],low,high,key)
    for key,high in (('device_seconds',43200),('children',2),('steps_per_child',1000)):
        integer(grant[key],1,high,key)
    for key in ('charged_device_seconds','children_started'):
        integer(state[key],0,43200,key)
    charge=limits['wall_seconds']*limits['allocated_devices']
    require(state['charged_device_seconds']+charge<=grant['device_seconds']
            and state['children_started']+1==limits['child_index']<=grant['children']
            and limits['optimizer_steps']<=grant['steps_per_child'],'BUDGET_EXHAUSTED')
    return charge


def source_inventory(repo):
    roots=[repo/'KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src',repo/'KT_PROD_CLEANROOM/tools',
           repo/'KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas']
    paths=set()
    for root in roots:
        assert_no_link_or_reparse_path(root,label='neural source root')
        require(root.is_dir(),'SOURCE_ROOT')
        for path in root.rglob('*'):
            assert_no_link_or_reparse_path(path,label='neural source')
            if path.is_file() and path.suffix in {'.py','.json'} and 'tests' not in path.parts:
                paths.add(path)
    for rel in ('KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256',
                'KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json',
                'KT_PROD_CLEANROOM/AUDITS/FL4_TIME_CONTRACT.json',
                'KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json'):
        paths.add(repo/rel)
    result={}
    for path in paths:
        assert_no_link_or_reparse_path(path,label='neural source file')
        result[path.relative_to(repo).as_posix()]=sha_file(path)
    return result


def preflight(job_path, expected_sha, repo, *, judge_splits=True):
    job=read_pinned(job_path,expected_sha)
    validate_job(job)
    require(time.time()<job['expires_at'],'EXPIRED')
    require(source_inventory(repo)==job['source_files'],'SOURCE_CLOSURE')
    output,budget=Path(job['output_root']),Path(job['budget_root'])
    input_paths=[job_path,repo,Path(job['backend']['base_root']),Path(job['backend']['adapter_root'])]
    input_paths += [Path(job['data'][s]['path']) for s in ('train','validation','transfer','retention')]
    for path in input_paths+[output,budget]:
        assert_no_link_or_reparse_path(path,label='neural isolated paths')
        require(path.resolve()==path,'NONCANONICAL_PATH')
    for out in (output,budget):
        require(all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in input_paths),'OUTPUT_INPUT_OVERLAP')
    require(not output.is_relative_to(budget) and not budget.is_relative_to(output),'OUTPUT_BUDGET_OVERLAP')
    backend=job['backend']
    for label in ('base','adapter'):
        root=Path(backend[label+'_root'])
        runtime=set()
        for path in root.rglob('*'):
            assert_no_link_or_reparse_path(path,label='immutable parent assets')
            if path.is_file() and path.suffix in {'.json','.safetensors','.model','.txt','.bin','.py'} and path.name not in {'README.txt','LICENSE.txt'}:
                runtime.add(path.relative_to(root).as_posix())
        require(runtime==set(backend[label+'_files']),'ASSET_COVERAGE')
        for rel,sha in backend[label+'_files'].items():
            require(sha_file(root/rel)==sha,'ASSET_PIN')
    index=json.loads((Path(backend['base_root'])/'model.safetensors.index.json').read_bytes())
    require(set(index['weight_map'].values())<=set(backend['base_files']),'BASE_SHARDS')
    seen=set(); judged={}
    for split in ('train','validation','transfer','retention'):
        spec=job['data'][split]
        if not judge_splits and split!='train':
            require(sha_file(Path(spec['path']))==spec['sha256'],'HELDOUT_INPUT_PIN')
            continue
        rows=read_pinned(Path(spec['path']),spec['sha256'])
        require(type(rows) is list and len(rows)==spec['rows'],'ROW_COVERAGE')
        judged[split]=judge_examples(rows,split=split,seen=seen,excluded=set(job['data']['exposed_problem_hashes']))
    return job,judged


def validate_campaign(context):
    fields(context,{'schema_id','authority_sha256','authority_basis','budget_root','grant','expires_at'},'CAMPAIGN')
    require(context['schema_id']=='kt.lab.neural_campaign.v1','CAMPAIGN_SCHEMA')
    digest(context['authority_sha256'],'CAMPAIGN_AUTHORITY')
    require(context['authority_basis']=='OWNER_ADOPTED_PRIVATE_NONPAID_EXPERIMENT','CAMPAIGN_AUTHORITY_BASIS')
    absolute(context['budget_root'],'CAMPAIGN_ROOT')
    integer(context['expires_at'],1,10**11,'CAMPAIGN_EXPIRY')
    require(time.time()<context['expires_at'],'CAMPAIGN_EXPIRED')
    fields(context['grant'],{'device_seconds','children','steps_per_child'},'CAMPAIGN_GRANT')
    for name,maximum in (('device_seconds',43200),('children',2),('steps_per_child',1000)):
        integer(context['grant'][name],1,maximum,name)


def bind_campaign(job,context,context_sha):
    validate_campaign(context)
    require(job['campaign_sha256']==context_sha and job['authority_sha256']==context['authority_sha256']
            and job['grant']==context['grant'] and job['budget_root']==context['budget_root']
            and job['expires_at']<=context['expires_at'],'CAMPAIGN_BINDING')


def validate_reservations(records,context,context_sha):
    state={'charged_device_seconds':0,'children_started':0};seen=set()
    for index,record in enumerate(records,1):
        fields(record,{'job','job_id','job_sha256','job_content_sha256','authority_sha256','campaign_sha256',
                       'device_seconds','child_index'},'RESERVATION')
        job=record['job'];validate_job(job);bind_campaign(job,context,context_sha)
        digest(record['job_sha256'],'RESERVED_JOB_SHA')
        require(record['job_id']==job['job_id'] and record['job_content_sha256']==identity(job)
                and record['authority_sha256']==context['authority_sha256']
                and record['campaign_sha256']==context_sha and record['child_index']==index
                and record['job_id'] not in seen,'RESERVATION_BINDING')
        charge=validate_resources(job['limits'],context['grant'],state)
        require(type(record['device_seconds']) is int and record['device_seconds']==charge,'RESERVATION_CHARGE')
        state['charged_device_seconds']+=charge;state['children_started']+=1;seen.add(record['job_id'])
    return state


def verify_child_output(job, expected_sha, output):
    """Optimizer evidence only; this never upgrades a child to evaluated/promoted."""
    import math
    start=strict_json((output/'optimizer_start.json').read_bytes(),max_bytes=2*1024*1024)
    child=strict_json((output/'child_lineage.json').read_bytes(),max_bytes=2*1024*1024)
    judgment=strict_json((output/'judgment.json').read_bytes(),max_bytes=2*1024*1024)
    steps=[strict_json(line) for line in (output/'optimizer_steps.jsonl').read_bytes().splitlines()]
    require(start['job_sha256']==child['job_sha256']==expected_sha
            and child['status']=='QUARANTINED_UNEVALUATED' and child['evaluation_status']=='NOT_RUN'
            and child['promotion_authority'] is False,'CHILD_SCOPE')
    require(start['parent_files']==child['parent_files']==job['backend']['adapter_files']
            and start['versions']==job['backend']['required_versions'] and start['real_nf4'] is True,'CHILD_LINEAGE')
    require(type(child['optimizer_steps']) is int and child['optimizer_steps']==len(steps)==job['limits']['optimizer_steps'],'STEP_COVERAGE')
    allowed=set(judgment['train']['example_hashes'])
    for number,step in enumerate(steps,1):
        require(step['optimizer_step']==number and step['example_hash'] in allowed,'STEP_BINDING')
        for key in ('loss','gradient_norm_before_clip','elapsed_seconds'):
            require(type(step[key]) in (int,float) and math.isfinite(step[key]) and step[key]>=0,'FINITE_OPTIMIZER_OBSERVATION')
        require(type(step['supervised_tokens']) is int and 0<step['supervised_tokens']<step['sequence_tokens']
                <=job['optimizer']['max_sequence_tokens'],'LOSS_TOKEN_COVERAGE')
    before,after=start['parameter_hashes'],child['parameter_hashes_after']
    require(type(before) is dict and bool(before) and set(before)==set(after),'PARAMETER_COVERAGE')
    for name in before:
        require('.lora_A.default.' in name or '.lora_B.default.' in name,'PARAMETER_SCOPE')
        digest(before[name],'PARAMETER_SHA');digest(after[name],'PARAMETER_SHA')
    changed=sum(before[name]!=after[name] for name in before)
    require(type(child['parameters_changed']) is int and child['parameters_changed']==changed>0,'NO_ACTUAL_UPDATE')
    root=output/'quarantined_child';assert_no_link_or_reparse_path(root,label='quarantined child')
    actual={}
    for path in root.rglob('*'):
        assert_no_link_or_reparse_path(path,label='quarantined child artifact')
        if path.is_file():actual[path.relative_to(root).as_posix()]=sha_file(path)
    require(actual==child['child_files'] and {'adapter_config.json','adapter_model.safetensors'}<=set(actual)
            and not any(name.endswith(('.bin','.py','.pkl')) for name in actual),'CHILD_BYTES')
    for label in ('base','adapter'):
        for rel,sha in job['backend'][label+'_files'].items():
            require(sha_file(Path(job['backend'][label+'_root'])/rel)==sha,'IMMUTABLE_PARENT_CHANGED')
    return {'status':'OPTIMIZER_EVIDENCE_RECONCILED_CHILD_UNEVALUATED','steps':len(steps),
            'parameters_changed':changed,'child_files':actual,'promotion_authority':False}


def run(job_path,expected_sha,repo,campaign_path,campaign_sha):
    # Hash, schema, live authority, source, model and judgment BEFORE backend load.
    import fcntl
    import secrets
    require(os.name=='posix' and os.getpgrp()==os.getpid(),'OWNED_PROCESS_GROUP_REQUIRED')
    started=time.monotonic()
    context=read_pinned(campaign_path,campaign_sha);validate_campaign(context)
    job,judged=preflight(job_path,expected_sha,repo)
    bind_campaign(job,context,campaign_sha)
    output,budget=Path(job['output_root']),Path(job['budget_root'])
    require(not output.exists(),'OUTPUT_ALREADY_EXISTS')
    budget.mkdir(parents=True,exist_ok=True)
    assert_no_link_or_reparse_path(budget/'campaign.lock',label='neural campaign lock')
    with (budget/'campaign.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        grant={'campaign_sha256':campaign_sha,'context':context}
        grant_path=budget/'grant.json'
        if grant_path.exists():
            require(strict_json(grant_path.read_bytes())==grant,'GRANT_CHANGED')
        else: write_once(grant_path,grant)
        reservations=[]
        for path in sorted(budget.glob('reservation_*.json')):
            assert_no_link_or_reparse_path(path,label='neural reservation')
            reservations.append(strict_json(path.read_bytes(),max_bytes=16*1024*1024))
        require([p.name for p in sorted(budget.glob('reservation_*.json'))]==['reservation_'+str(i)+'.json' for i in range(1,len(reservations)+1)],'RESERVATION_SEQUENCE')
        require(job['job_id'] not in {x['job_id'] for x in reservations},'JOB_ALREADY_RESERVED')
        state=validate_reservations(reservations,context,campaign_sha)
        charge=validate_resources(job['limits'],job['grant'],state)
        output.mkdir(parents=True,exist_ok=False)
        write_once(output/'job.json',job)
        # The generic master remains mandatory and unchanged. A denied receipt is retained.
        from tools.training.training_admission_gate import ensure_training_admission_receipt
        receipt=ensure_training_admission_receipt(repo_root=repo,job_path=job_path,job_dir=output,
                    lane_id='PRIVATE_NEURAL_LAB',expected_law_bundle_hash=job['law_bundle_sha256'])
        require(receipt['decision']=='PASS','MASTER_ADMISSION_DENIED')
        reservation={'job':job,'job_content_sha256':identity(job),'campaign_sha256':campaign_sha,
                     'job_id':job['job_id'],'job_sha256':expected_sha,'authority_sha256':job['authority_sha256'],
                     'device_seconds':charge,'child_index':job['limits']['child_index']}
        write_once(budget/('reservation_'+str(job['limits']['child_index'])+'.json'),reservation)
        write_once(output/'reservation.json',reservation)
        write_once(output/'judgment.json',{s:{'accepted':len(rows),'excluded':0,'example_hashes':[x['example_hash'] for x in rows],
                                               'problem_hashes':[x['problem_hash'] for x in rows]} for s,rows in judged.items()})
        # Only judged train rows cross the optimizer interface.
        write_once(output/'judged_train.json',judged['train'])
        nonce=secrets.token_hex(32)
        permit={'job_sha256':expected_sha,'nonce':nonce,'parent_pid':os.getpid(),
                'owned_process_group':os.getpgrp(),'campaign_path':str(campaign_path),'campaign_sha256':campaign_sha,
                'reservation_sha256':sha_file(output/'reservation.json'),
                'master_receipt_sha256':sha_file(output/'training_admission_receipt.json')}
        write_once(output/'activation.json',permit)
        read_fd,write_fd=os.pipe()
        worker=repo/'KT_PROD_CLEANROOM/tools/training/lab_neural_worker.py'
        environment={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LD_LIBRARY_PATH','CUDA_VISIBLE_DEVICES','CUDA_HOME','TMPDIR'}}
        environment.update(PYTHONDONTWRITEBYTECODE='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',TOKENIZERS_PARALLELISM='false')
        timed_out=False
        timeout=min(job['limits']['wall_seconds']-(time.monotonic()-started),job['expires_at']-time.time())
        require(timeout>0,'EXPIRED_BEFORE_LOAD')
        with (output/'worker.stdout.jsonl').open('xb') as stdout,(output/'worker.stderr.log').open('xb') as stderr:
            try:
                process=subprocess.Popen([sys.executable,'-I','-B',str(worker),str(job_path),expected_sha,str(read_fd)],
                                         stdout=stdout,stderr=stderr,env=environment,pass_fds=(read_fd,))
                os.close(read_fd);read_fd=None
                with os.fdopen(write_fd,'wb') as pipe: pipe.write(canonical_bytes(permit)+b'\n')
                write_fd=None
                try: code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out=True
                    write_once(output/'internal_timeout.json',{'status':'QUARANTINED_WHOLE_GROUP_TIMEOUT','observed_seconds':time.monotonic()-started,'promotion_authority':False})
                    os.killpg(os.getpgrp(),signal.SIGKILL)
                    raise RuntimeError('NEURAL_OWNED_GROUP_TERMINATION_FAILED')
            finally:
                if read_fd is not None: os.close(read_fd)
                if write_fd is not None: os.close(write_fd)
        child_valid=False
        if code==0 and not timed_out:
            try:
                checked=verify_child_output(job,expected_sha,output)
                require(source_inventory(repo)==job['source_files'],'SOURCE_CHANGED_AFTER_TRAINING')
                write_once(output/'child_verification.json',checked);child_valid=True
            except Exception as exc:
                write_once(output/'child_verification_failure.json',{'status':'QUARANTINED_INVALID_CHILD_EVIDENCE','error_type':type(exc).__name__,'evaluation_status':'NOT_RUN','promotion_authority':False})
        write_once(output/'execution_result.json',{'status':'QUARANTINED_OPTIMIZER_COMPLETED' if code==0 and not timed_out and child_valid else 'QUARANTINED_EXECUTION_FAILURE',
                   'exit_code':code,'timed_out':timed_out,'observed_seconds':time.monotonic()-started,
                   'charged_device_seconds':charge,'evaluation_status':'NOT_RUN','promotion_authority':False})
        require(code==0 and not timed_out and child_valid,'EXECUTION_FAILED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job',required=True,type=Path)
    parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--campaign',required=True,type=Path)
    parser.add_argument('--campaign-sha256',required=True)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[3]
    run(args.job,args.expected_sha256,repo,args.campaign,args.campaign_sha256)


if __name__=='__main__': main()
