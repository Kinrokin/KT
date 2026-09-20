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
from schemas.lab_neural_schema import validate_job, require, integer
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
    return identity({'kind':task['kind'],'problem':task['problem']})


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


def run(job_path,expected_sha,repo):
    # Hash, schema, live authority, source, model and judgment BEFORE backend load.
    import fcntl
    import secrets
    job,judged=preflight(job_path,expected_sha,repo)
    output,budget=Path(job['output_root']),Path(job['budget_root'])
    require(not output.exists(),'OUTPUT_ALREADY_EXISTS')
    budget.mkdir(parents=True,exist_ok=True)
    assert_no_link_or_reparse_path(budget/'campaign.lock',label='neural campaign lock')
    with (budget/'campaign.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        grant={'authority_sha256':job['authority_sha256'],'grant':job['grant']}
        grant_path=budget/'grant.json'
        if grant_path.exists():
            require(strict_json(grant_path.read_bytes())==grant,'GRANT_CHANGED')
        else: write_once(grant_path,grant)
        reservations=[]
        for path in sorted(budget.glob('reservation_*.json')):
            assert_no_link_or_reparse_path(path,label='neural reservation')
            reservations.append(strict_json(path.read_bytes()))
        require(all(x['authority_sha256']==job['authority_sha256'] for x in reservations),'RESERVATION_AUTHORITY')
        require(job['job_id'] not in {x['job_id'] for x in reservations},'JOB_ALREADY_RESERVED')
        state={'charged_device_seconds':sum(x['device_seconds'] for x in reservations),'children_started':len(reservations)}
        charge=validate_resources(job['limits'],job['grant'],state)
        output.mkdir(parents=True,exist_ok=False)
        write_once(output/'job.json',job)
        # The generic master remains mandatory and unchanged. A denied receipt is retained.
        from tools.training.training_admission_gate import ensure_training_admission_receipt
        receipt=ensure_training_admission_receipt(repo_root=repo,job_path=job_path,job_dir=output,
                    lane_id='PRIVATE_NEURAL_LAB',expected_law_bundle_hash=job['law_bundle_sha256'])
        require(receipt['decision']=='PASS','MASTER_ADMISSION_DENIED')
        reservation={'job_id':job['job_id'],'job_sha256':expected_sha,'authority_sha256':job['authority_sha256'],
                     'device_seconds':charge,'child_index':job['limits']['child_index']}
        write_once(budget/('reservation_'+str(job['limits']['child_index'])+'.json'),reservation)
        write_once(output/'reservation.json',reservation)
        write_once(output/'judgment.json',{s:{'accepted':len(rows),'excluded':0,'example_hashes':[x['example_hash'] for x in rows],
                                               'problem_hashes':[x['problem_hash'] for x in rows]} for s,rows in judged.items()})
        # Only judged train rows cross the optimizer interface.
        write_once(output/'judged_train.json',judged['train'])
        nonce=secrets.token_hex(32)
        permit={'job_sha256':expected_sha,'nonce':nonce,'parent_pid':os.getpid(),
                'reservation_sha256':sha_file(output/'reservation.json'),
                'master_receipt_sha256':sha_file(output/'training_admission_receipt.json')}
        write_once(output/'activation.json',permit)
        read_fd,write_fd=os.pipe()
        worker=repo/'KT_PROD_CLEANROOM/tools/training/lab_neural_worker.py'
        environment={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LD_LIBRARY_PATH','CUDA_VISIBLE_DEVICES','CUDA_HOME','TMPDIR'}}
        environment.update(PYTHONDONTWRITEBYTECODE='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',TOKENIZERS_PARALLELISM='false')
        started=time.monotonic(); timed_out=False
        timeout=min(job['limits']['wall_seconds'],job['expires_at']-time.time())
        require(timeout>0,'EXPIRED_BEFORE_LOAD')
        with (output/'worker.stdout.jsonl').open('xb') as stdout,(output/'worker.stderr.log').open('xb') as stderr:
            try:
                process=subprocess.Popen([sys.executable,'-I','-B',str(worker),str(job_path),expected_sha,str(read_fd)],
                                         stdout=stdout,stderr=stderr,env=environment,pass_fds=(read_fd,),start_new_session=True)
                os.close(read_fd);read_fd=None
                with os.fdopen(write_fd,'wb') as pipe: pipe.write(canonical_bytes(permit)+b'\n')
                write_fd=None
                try: code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out=True;os.killpg(process.pid,signal.SIGKILL);code=process.wait()
            finally:
                if read_fd is not None: os.close(read_fd)
                if write_fd is not None: os.close(write_fd)
        write_once(output/'execution_result.json',{'status':'QUARANTINED_OPTIMIZER_COMPLETED' if code==0 and not timed_out else 'QUARANTINED_EXECUTION_FAILURE',
                   'exit_code':code,'timed_out':timed_out,'observed_seconds':time.monotonic()-started,
                   'charged_device_seconds':charge,'evaluation_status':'NOT_RUN','promotion_authority':False})
        require(code==0 and not timed_out,'EXECUTION_FAILED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job',required=True,type=Path)
    parser.add_argument('--expected-sha256',required=True)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[3]
    run(args.job,args.expected_sha256,repo)


if __name__=='__main__': main()
