"""Fixed offline optimizer worker; receives one inherited controller activation pipe.

Qualified NF4 loading follows local_qwen_worker; PEFT text optimization follows
the real phase2 trainer. No inference-runtime imports of model/training libraries.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import random
import stat
import sys
import time


def main():
    if len(sys.argv)!=4:
        raise RuntimeError('NEURAL_CONTROLLER_ACTIVATION_REQUIRED')
    repo=Path(__file__).resolve().parents[3]
    sys.path[:0]=[str(repo/'KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src'),str(repo/'KT_PROD_CLEANROOM')]
    from tools.training.lab_neural import preflight,read_pinned,sha_file,write_once,completion_labels,bind_campaign,validate_reservations
    from schemas.checked_task import canonical_bytes,strict_json
    from schemas.lab_neural_schema import require,fields,digest,integer
    path,expected=Path(sys.argv[1]),sys.argv[2]
    fd=int(sys.argv[3])
    require(fd>=3 and stat.S_ISFIFO(os.fstat(fd).st_mode),'ACTIVATION_PIPE_REQUIRED')
    with os.fdopen(fd,'rb') as pipe:
        permit=strict_json(pipe.read(8193),max_bytes=8192)
    fields(permit,{'job_sha256','nonce','parent_pid','owned_process_group','campaign_path','campaign_sha256',
                   'reservation_sha256','master_receipt_sha256'},'ACTIVATION')
    for key in ('job_sha256','nonce','campaign_sha256','reservation_sha256','master_receipt_sha256'):digest(permit[key],key)
    integer(permit['parent_pid'],1,2**31,'PARENT_PID')
    integer(permit['owned_process_group'],1,2**31,'PROCESS_GROUP')
    require(permit['parent_pid']==os.getppid()==os.getpgrp()==permit['owned_process_group'],'OWNED_GROUP_PARENT')
    context=read_pinned(Path(permit['campaign_path']),permit['campaign_sha256'])
    job,judged=preflight(path,expected,repo,judge_splits=False)
    bind_campaign(job,context,permit['campaign_sha256'])
    output=Path(job['output_root'])
    require(permit==strict_json((output/'activation.json').read_bytes())
            and permit['job_sha256']==expected and permit['parent_pid']==os.getppid(),'ACTIVE_PARENT')
    require(sha_file(output/'reservation.json')==permit['reservation_sha256']
            and sha_file(output/'training_admission_receipt.json')==permit['master_receipt_sha256'],'ACTIVATION_PIN')
    receipt=strict_json((output/'training_admission_receipt.json').read_bytes())
    from tools.training.training_admission_gate import build_training_admission_receipt
    require(receipt==build_training_admission_receipt(repo_root=repo,job_path=path,lane_id='PRIVATE_NEURAL_LAB',
                expected_law_bundle_hash=job['law_bundle_sha256']) and receipt['decision']=='PASS','MASTER_BINDING')
    records=[strict_json(p.read_bytes(),max_bytes=16*1024*1024) for p in sorted(Path(job['budget_root']).glob('reservation_*.json'))]
    validate_reservations(records,context,permit['campaign_sha256'])
    require(records and records[-1]['job']==job and records[-1]['job_sha256']==expected
            and records[-1]==strict_json((output/'reservation.json').read_bytes(),max_bytes=16*1024*1024),'CURRENT_RESERVATION')
    require(judged['train']==strict_json((output/'judged_train.json').read_bytes(),max_bytes=16*1024*1024),'JUDGED_TRAIN_PIN')
    backend=job['backend'];versions={name:importlib.metadata.version(name) for name in backend['required_versions']}
    require(versions==backend['required_versions'],'ENVIRONMENT_PIN')
    # No backend import or model load occurs before the gates above.
    import torch
    import bitsandbytes
    from transformers import AutoModelForCausalLM,AutoTokenizer,BitsAndBytesConfig
    from peft import PeftModel,prepare_model_for_kbit_training
    require(torch.cuda.device_count()==job['limits']['allocated_devices'],'ALLOCATED_GPU_COUNT')
    require(all(torch.cuda.get_device_name(i)=='Tesla T4' for i in range(torch.cuda.device_count())),'GPU_QUALIFICATION')
    seed=backend['seed'];random.seed(seed);torch.manual_seed(seed);torch.cuda.manual_seed_all(seed)
    torch.backends.cuda.matmul.allow_tf32=False;torch.backends.cudnn.allow_tf32=False;torch.backends.cudnn.benchmark=False
    base=Path(backend['base_root']);parent=Path(backend['adapter_root'])
    cfg=strict_json((parent/'adapter_config.json').read_bytes())
    require(cfg.get('base_model_name_or_path')==backend['base_repo'] and cfg.get('peft_type')=='LORA'
            and cfg.get('task_type')=='CAUSAL_LM','PARENT_COMPATIBILITY')
    tokenizer=AutoTokenizer.from_pretrained(str(base),local_files_only=True,trust_remote_code=False)
    require(hashlib.sha256(tokenizer.chat_template.encode()).hexdigest()==backend['chat_template_sha256'],'TOKENIZER_TEMPLATE')
    training=[]
    for row in judged['train']:
        messages=[{'role':'user','content':row['prompt']}]
        prefix=tokenizer.apply_chat_template(messages,tokenize=True,add_generation_prompt=True)
        full=tokenizer.apply_chat_template(messages+[{'role':'assistant','content':row['completion']}],tokenize=True,add_generation_prompt=False)
        labels=completion_labels(prefix,full,job['optimizer']['max_sequence_tokens'])
        require(tokenizer.eos_token_id in full[len(prefix):],'TARGET_EOS')
        training.append((row['example_hash'],full,labels))
    quant=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.float16)
    model=AutoModelForCausalLM.from_pretrained(str(base),quantization_config=quant,device_map={'':0},
                                            torch_dtype=torch.float16,local_files_only=True,trust_remote_code=False)
    require(model.is_loaded_in_4bit and any(isinstance(x,bitsandbytes.nn.Linear4bit) for x in model.modules()),'REAL_NF4')
    model=prepare_model_for_kbit_training(model,use_gradient_checkpointing=True)
    model=PeftModel.from_pretrained(model,str(parent),is_trainable=True,local_files_only=True)
    status=model.get_model_status()
    require(status.enabled is True and status.active_adapters==['default'] and status.merged_adapters==[],'PARENT_ACTIVE')
    parameters={name:p for name,p in model.named_parameters() if p.requires_grad}
    require(bool(parameters) and all('.lora_A.default.' in n or '.lora_B.default.' in n for n in parameters),'ONLY_PARENT_LORA_TRAINABLE')
    require(all(p.device.type=='cuda' for p in model.parameters()),'NO_CPU_FALLBACK')
    def hashes():
        return {n:hashlib.sha256(p.detach().float().cpu().numpy().tobytes()).hexdigest() for n,p in parameters.items()}
    before=hashes()
    write_once(output/'optimizer_start.json',{'job_sha256':expected,'versions':versions,'parent_files':backend['adapter_files'],
               'parameter_hashes':before,'trainable_parameters':sum(p.numel() for p in parameters.values()),
               'examples':len(training),'real_nf4':True,'training_objective':job['objective'],
               'actual_device':0,'allocated_devices':torch.cuda.device_count()})
    model.config.use_cache=False;model.train()
    opt=job['optimizer']
    optimizer=torch.optim.AdamW(list(parameters.values()),lr=opt['learning_rate'],weight_decay=opt['weight_decay'])
    order=list(range(len(training)));random.Random(seed).shuffle(order)
    started=time.monotonic();steps=0
    with (output/'optimizer_steps.jsonl').open('xb') as stream:
        for step in range(job['limits']['optimizer_steps']):
            require(time.time()<job['expires_at'] and os.getppid()==permit['parent_pid'],'EXPIRED_OR_PARENT_EXITED')
            require(time.monotonic()-started<job['limits']['wall_seconds'],'STEP_WALL_LIMIT')
            require(sha_file(path)==expected,'JOB_CHANGED')
            example_hash,ids,labels=training[order[step%len(order)]]
            optimizer.zero_grad(set_to_none=True)
            tokens=torch.tensor([ids],device='cuda:0',dtype=torch.long)
            target=torch.tensor([labels],device='cuda:0',dtype=torch.long)
            result=model(input_ids=tokens,attention_mask=torch.ones_like(tokens),labels=target)
            loss=result.loss
            require(torch.isfinite(loss).item(),'NONFINITE_LOSS')
            loss.backward()
            grads=[p.grad for p in parameters.values() if p.grad is not None]
            require(bool(grads) and all(torch.isfinite(g).all().item() for g in grads),'NONFINITE_OR_EMPTY_GRADIENT')
            norm=torch.nn.utils.clip_grad_norm_(list(parameters.values()),opt['max_grad_norm'],error_if_nonfinite=True)
            optimizer.step();torch.cuda.synchronize(0);steps+=1
            row={'optimizer_step':steps,'example_hash':example_hash,'loss':float(loss.detach().item()),
                 'gradient_norm_before_clip':float(norm.item()),'sequence_tokens':len(ids),
                 'supervised_tokens':sum(x!=-100 for x in labels),'elapsed_seconds':time.monotonic()-started}
            stream.write(canonical_bytes(row)+b'\n');stream.flush();os.fsync(stream.fileno())
    after=hashes()
    require(steps==job['limits']['optimizer_steps'] and before!=after,'NO_ACTUAL_PARAMETER_UPDATE')
    child=output/'quarantined_child';child.mkdir(exist_ok=False)
    model.save_pretrained(str(child),safe_serialization=True)
    require((child/'adapter_model.safetensors').is_file(),'SAFE_CHILD_REQUIRED')
    for rel,sha in backend['adapter_files'].items():require(sha_file(parent/rel)==sha,'PARENT_MUTATED')
    child_files={p.relative_to(child).as_posix():sha_file(p) for p in child.rglob('*') if p.is_file()}
    write_once(output/'child_lineage.json',{'status':'QUARANTINED_UNEVALUATED','job_sha256':expected,
               'parent_files':backend['adapter_files'],'child_files':child_files,'optimizer_steps':steps,
               'parameter_hashes_after':after,'parameters_changed':sum(before[n]!=after[n] for n in before),
               'loss_is_not_benefit':True,'evaluation_status':'NOT_RUN','promotion_authority':False})


if __name__=='__main__': main()
