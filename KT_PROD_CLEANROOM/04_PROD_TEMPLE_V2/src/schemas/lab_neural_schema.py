"""Pure, closed schema for a separately admitted neural laboratory job."""
from __future__ import annotations

import math
from pathlib import Path
import re

from schemas.checked_task import identity
from schemas.schema_files import schema_version_hash

SCHEMA_ID = "kt.lab.neural_job.v1"
SCHEMA_FILE = "lab/kt.lab.neural_job.v1.json"
SCHEMA_HASH = schema_version_hash(SCHEMA_FILE)


def require(ok, reason):
    if not ok:
        raise ValueError("NEURAL_" + reason)


def integer(value, low, high, name):
    require(type(value) is int and low <= value <= high, name)


def fields(value, expected, name):
    require(type(value) is dict and set(value) == set(expected), name + "_FIELDS")


def digest(value, name):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, name)


def absolute(value, name):
    require(type(value) is str and Path(value).is_absolute() and ".." not in Path(value).parts, name)


def validate_job(job):
    fields(job, {"schema_id", "schema_version_hash", "job_id", "authority_sha256", "authority_basis",
                 "law_bundle_sha256", "source_head", "source_files", "backend", "data", "optimizer",
                 "limits", "grant", "output_root", "budget_root", "expires_at", "objective", "evaluation"}, "JOB")
    require(job["schema_id"] == SCHEMA_ID and job["schema_version_hash"] == SCHEMA_HASH, "SCHEMA")
    for key in ("job_id", "authority_sha256", "law_bundle_sha256"):
        digest(job[key], key)
    require(job["authority_basis"] == "OWNER_ADOPTED_PRIVATE_NONPAID_EXPERIMENT", "AUTHORITY")
    require(type(job["source_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", job["source_head"]) is not None, "SOURCE_HEAD")
    require(job["objective"] == "COMPLETION_ONLY_CHECKED_PLAN_FEASIBILITY", "OBJECTIVE")
    require(job["evaluation"] == {"status": "REQUIRED_NOT_RUN", "child_disposition": "QUARANTINE",
                                 "controls": ["PARENT", "UNCHANGED_PARENT_RELOAD"],
                                 "splits": ["validation", "transfer", "retention"]}, "EVALUATION")
    absolute(job["output_root"], "OUTPUT_ROOT"); absolute(job["budget_root"], "BUDGET_ROOT")
    integer(job["expires_at"], 1, 10**11, "EXPIRY")
    pins = job["source_files"]
    require(type(pins) is dict and 1 <= len(pins) <= 30000, "SOURCE_FILES")
    for rel, sha in pins.items():
        require(type(rel) is str and rel and not Path(rel).is_absolute() and "\\" not in rel and ":" not in rel
                and all(x not in ("", ".", "..") for x in rel.split("/")), "SOURCE_PATH")
        digest(sha, "SOURCE_SHA")
    # Fixed qualified substrate contract; no dynamic model or optimizer classes.
    from council.providers.local_qwen import validate_backend
    validate_backend(job["backend"])
    require(job["backend"]["adapter_root"] is not None, "EXACT_PARENT_REQUIRED")
    data = job["data"]
    fields(data, {"rights", "exposed_problem_hashes", "train", "validation", "transfer", "retention"}, "DATA")
    require(data["rights"] == "OWNER_AUTHORED_SYNTHETIC_DEVELOPMENT", "DATA_RIGHTS")
    excluded = data["exposed_problem_hashes"]
    require(type(excluded) is list and len(excluded) == len(set(excluded)) and len(excluded) <= 10000, "EXCLUSIONS")
    for sha in excluded: digest(sha, "EXCLUDED_SHA")
    for split in ("train", "validation", "transfer", "retention"):
        fields(data[split], {"path", "sha256", "rows"}, "SPLIT")
        absolute(data[split]["path"], "DATA_PATH"); digest(data[split]["sha256"], "DATA_SHA")
        integer(data[split]["rows"], 1, 2048, "DATA_ROWS")
    opt = job["optimizer"]
    fields(opt, {"kind", "learning_rate", "weight_decay", "max_grad_norm", "batch_size", "gradient_accumulation", "max_sequence_tokens"}, "OPTIMIZER")
    require(opt["kind"] == "AdamW" and type(opt["learning_rate"]) is float and math.isfinite(opt["learning_rate"])
            and 0 < opt["learning_rate"] <= 0.001, "LEARNING_RATE")
    require(type(opt["weight_decay"]) is float and opt["weight_decay"] == 0.0, "WEIGHT_DECAY")
    require(type(opt["max_grad_norm"]) is float and 0 < opt["max_grad_norm"] <= 1.0, "GRADIENT_LIMIT")
    require(type(opt["batch_size"]) is int and opt["batch_size"] == 1
            and type(opt["gradient_accumulation"]) is int and opt["gradient_accumulation"] == 1, "BATCH")
    integer(opt["max_sequence_tokens"], 32, 4096, "SEQUENCE_LIMIT")
    limits = job["limits"]
    fields(limits, {"wall_seconds", "allocated_devices", "optimizer_steps", "child_index"}, "LIMITS")
    for key, low, high in (("wall_seconds",1,7200),("allocated_devices",1,2),("optimizer_steps",1,1000),("child_index",1,2)):
        integer(limits[key],low,high,key)
    grant=job["grant"]
    fields(grant,{"device_seconds","children","steps_per_child"},"GRANT")
    for key,high in (("device_seconds",43200),("children",2),("steps_per_child",1000)):
        integer(grant[key],1,high,key)
    require(limits["wall_seconds"]*limits["allocated_devices"] <= grant["device_seconds"]
            and limits["optimizer_steps"] <= grant["steps_per_child"] and limits["child_index"] <= grant["children"], "GRANT_LIMIT")
    require(job["job_id"] == identity({k:v for k,v in job.items() if k != "job_id"}), "JOB_ID")
