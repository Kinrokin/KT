#!/usr/bin/env python3
"""Compile the next Livewire tranche from merged-main graph truth.

This is a reference compiler, not authorization to execute PR B during V2.2.
It emits a head-bound prompt only after the parent tranche is merged and replayed.
"""
from __future__ import annotations

import argparse
import json
import hashlib
from pathlib import Path
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--graph", required=True)
    p.add_argument("--current-truth", required=True)
    p.add_argument("--claim-ceiling", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--out-dir", required=True)
    args = p.parse_args()
    graph = load(Path(args.graph))
    truth = load(Path(args.current_truth))
    ceiling = load(Path(args.claim_ceiling))
    head = args.head
    if len(head) != 40 or any(c not in "0123456789abcdef" for c in head):
        raise SystemExit("invalid_head")
    if graph["generated_from_head"] != head or truth["generated_from_head"] != head:
        raise SystemExit("mixed_or_stale_head")
    graph_sha = sha(graph)
    if truth["generated_from_graph_sha256"] != graph_sha:
        raise SystemExit("current_truth_graph_digest_mismatch")
    if truth["open_contradiction_count"] != 0 or truth["critical_blockers"]:
        decision = "BLOCK_NEXT_TRANCHE"
        blocker = "OPEN_CONTRADICTION_OR_CRITICAL_BLOCKER"
        next_tranche = None
    else:
        nodes = {n["node_id"]: n for n in graph["nodes"]}
        needed = {"fact:stop300_v41_completed", "fact:stop300_v41_official_block", "fact:stop300_v41_cleanroom_recomputed"}
        if not needed.issubset(nodes):
            decision = "BLOCK_NEXT_TRANCHE"
            blocker = "PR_A_FACT_SET_INCOMPLETE"
            next_tranche = None
        else:
            decision = "AUTHOR_PR_B"
            blocker = None
            next_tranche = "KT_CORE_LIVEWIRE_V2_2_PR_B_PROOF_CARRYING_RUNTIME_VERTICAL"
    payload = {
        "schema_id": "kt.livewire.next_tranche_compilation.v1",
        "decision": decision,
        "blocker": blocker,
        "next_tranche": next_tranche,
        "compiled_from_head": head,
        "graph_sha256": graph_sha,
        "current_truth_sha256": sha(truth),
        "claim_ceiling_sha256": sha(ceiling),
        "claim_ceiling_status": "PRESERVED",
        "forbidden_carryover": [
            "pre-merge branch assumptions",
            "unresolved PR A contradictions",
            "unregistered generated authority",
            "claim expansion",
        ],
    }
    payload_sha = sha(payload)
    envelope_body = {
        "schema_id": "kt.derivation_envelope.v1",
        "payload_schema_id": payload["schema_id"],
        "payload_path": "NEXT_TRANCHE_DECISION.json",
        "payload_sha256": payload_sha,
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_set_sha256": graph["source_set_sha256"],
        "generated_from_head": head,
        "generated_at": "2026-06-23T00:00:00Z",
        "build_execution_id": "next-tranche-compiler",
        "build_host_fingerprint_sha256": hashlib.sha256(b"repo-agent").hexdigest(),
    }
    envelope = {**envelope_body, "envelope_sha256": sha(envelope_body)}
    out = Path(args.out_dir)
    write(out / "NEXT_TRANCHE_DECISION.json", payload)
    write(out / "NEXT_TRANCHE_DECISION.envelope.json", envelope)
    if decision == "AUTHOR_PR_B":
        prompt = f"""Execute {next_tranche} from merged main {head}.\n\nRead the current evidence graph and truth projection bound below:\n- graph SHA256: {graph_sha}\n- current truth SHA256: {sha(truth)}\n- claim ceiling SHA256: {sha(ceiling)}\n\nStart read-only. Select the smallest canonical runtime path. Prove actual caller, configuration, invocation, mandatory code-owned gates, output consumer, measured effect, rollback, event-chain integrity, static reachability, dynamic invocation, and mutation kill rate. Do not claim global runtime coverage. Do not train, promote, deploy selectors, expand claims, or execute PR C/D. Return only the tranche return contract.\n"""
    else:
        prompt = f"BLOCKED: {blocker}. Repair PR A truth at merged main {head}; do not author PR B.\n"
    with (out / "COPY_PASTE_NEXT.txt").open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(prompt)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if decision == "AUTHOR_PR_B" else 2


if __name__ == "__main__":
    raise SystemExit(main())
