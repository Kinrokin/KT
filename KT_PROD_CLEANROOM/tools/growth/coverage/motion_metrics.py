import math
import json
from collections import defaultdict, Counter
from typing import List, Dict, Any, Tuple

def compute_transitions(executed_step_ids: List[str], step_tag_index: Dict[str, Dict[str, List[str]]]) -> Dict[str, Any]:
    """
    Compute domain/subdomain/microdomain transitions and matrices from executed sequence and tag index.
    """
    transitions = {
        'domain_transitions': Counter(),
        'subdomain_transitions': Counter(),
        'microdomain_transitions': Counter(),
        'missing_tag_count': 0,
        'domain_matrix': None,  # Optional, can be filled if needed
    }
    prev = None
    for sid in executed_step_ids:
        tags = step_tag_index.get(sid)
        if not tags:
            transitions['missing_tag_count'] += 1
            prev = None
            continue
        doms = tags.get('domains', [])
        subs = tags.get('subdomains', [])
        micros = tags.get('microdomains', [])
        dom = doms[0] if doms else None
        sub = subs[0] if subs else None
        micro = micros[0] if micros else None
        if prev:
            pdom, psub, pmicro = prev
            if pdom and dom:
                transitions['domain_transitions'][f"{pdom}->{dom}"] += 1
            if psub and sub:
                transitions['subdomain_transitions'][f"{psub}->{sub}"] += 1
            if pmicro and micro:
                transitions['microdomain_transitions'][f"{pmicro}->{micro}"] += 1
        prev = (dom, sub, micro)
    # Optionally, build matrices
    # ...
    return transitions

def compute_motion_metrics(executed_step_ids: List[str], step_tag_index: Dict[str, Dict[str, List[str]]]) -> Dict[str, Any]:
    """
    Compute scalar motion metrics: hop rates, revisit latency, hop entropy, etc.
    """
    metrics = {}
    n_steps = len(executed_step_ids)
    # Hop rates
    transitions = compute_transitions(executed_step_ids, step_tag_index)
    metrics['domain_hop_rate'] = sum(transitions['domain_transitions'].values()) / max(n_steps, 1)
    metrics['subdomain_hop_rate'] = sum(transitions['subdomain_transitions'].values()) / max(n_steps, 1)
    # Revisit latency
    last_seen = {}
    latencies = []
    for i, sid in enumerate(executed_step_ids):
        tags = step_tag_index.get(sid)
        if not tags:
            continue
        doms = tags.get('domains', [])
        dom = doms[0] if doms else None
        if dom:
            if dom in last_seen:
                latencies.append(i - last_seen[dom])
            last_seen[dom] = i
    metrics['mean_revisit_latency_steps_domain'] = float(sum(latencies)) / len(latencies) if latencies else None
    metrics['max_revisit_latency_steps_domain'] = max(latencies) if latencies else None
    # Hop entropy
    hop_counts = defaultdict(Counter)
    prev_dom = None
    for sid in executed_step_ids:
        tags = step_tag_index.get(sid)
        if not tags:
            prev_dom = None
            continue
        doms = tags.get('domains', [])
        dom = doms[0] if doms else None
        if prev_dom and dom:
            hop_counts[prev_dom][dom] += 1
        prev_dom = dom
    entropies = []
    for src, dests in hop_counts.items():
        total = sum(dests.values())
        probs = [c / total for c in dests.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        entropies.append(entropy)
    metrics['hop_entropy_domain'] = float(sum(entropies)) / len(entropies) if entropies else 0.0
    # TODO: Add subdomain revisit, path length, paradox counts if available
    return metrics

def emit_transitions_json(path: str, payload: Dict[str, Any]):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, sort_keys=True, indent=2, ensure_ascii=True)

def emit_motion_metrics_json(path: str, payload: Dict[str, Any]):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, sort_keys=True, indent=2, ensure_ascii=True)
