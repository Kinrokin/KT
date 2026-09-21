"""Actual canonical-path CPU integration; transport responses are synthetic, not models."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

from test_checked_generation import (
    SyntheticBackend, isolated_test_transport, tmp_path, make_contract, invoke, _rewrite_record,
)
from core import checked_generation as lane
from governance.lab_admission import operator_session, validate_contract, INTERFACE_CONTRACT_SCHEMA
from memory import lab_effect
from schemas.checked_task import (
    CheckedTaskError, canonical_bytes, identity, build_prompt, parse_proposal,
)
from schemas.response_interface import bind_proposal, build_interface_prompt


MODES = ['host_bound_answer', 'full_envelope_control']


def configuration(mode):
    return {'mode': mode, 'display_nonce': 'd' * 32 if mode == 'full_envelope_control' else None}


class InterfaceBackend(SyntheticBackend):
    override = None

    def generate(self, **kwargs):
        raw = super().generate(**kwargs)
        body = json.loads(kwargs['prompt'].split('\n', 1)[1])
        answer = json.loads(raw['output_text'])['answer']
        value = dict(body['required_output'], answer=answer)
        raw['output_text'] = self.override if self.override is not None else canonical_bytes(value).decode()
        return raw


@pytest.fixture(autouse=True)
def interface_transport(monkeypatch, isolated_test_transport):
    monkeypatch.setattr(lane, 'LocalQwenBackend', InterfaceBackend)
    monkeypatch.setattr(InterfaceBackend, 'override', None)


def contract(tmp_path, mode='host_bound_answer', **kwargs):
    path, _, value, old = make_contract(tmp_path, **kwargs)
    op = value['operations'].pop(old)
    op['response_interface'] = configuration(mode)
    value['schema_id'] = INTERFACE_CONTRACT_SCHEMA
    value['operations'][identity(op)] = op
    path.write_bytes(canonical_bytes(value))
    return path, hashlib.sha256(path.read_bytes()).hexdigest(), value, identity(op)


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('strategy', ['direct', 'self_review', 'kt_diagnostic', 'kt_constraint_detail', 'sham', 'nonconsuming'])
def test_versioned_full_path_repair_replay_and_duplicate_prevention(tmp_path, mode, strategy):
    path, pin, value, op = contract(tmp_path, mode, strategy=strategy,
        attempts=1 if strategy == 'direct' else 3, consume=strategy != 'nonconsuming')
    SyntheticBackend.answers = [42] if strategy == 'direct' else [41, 42]
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    assert result['status'] == ('CHECKED_NONCONSUMING' if strategy == 'nonconsuming' else 'CHECKED_EFFECT_RESTORED'), result
    assert result['schema_id'] == 'kt.lab.operation_result.v2'
    folder = Path(value['output_root']) / op
    requests = [lab_effect.read_record(folder / f'attempt_{i}_request.json') for i in result['attempts']]
    assert len({r['nonce'] for r in requests}) == len(requests)
    if strategy != 'direct':
        feedback = json.loads(requests[1]['prompt'].split('\n', 1)[1])['prior_attempts'][0]
        assert feedback['previous_answer'] == 41
        if strategy in ('kt_diagnostic', 'kt_constraint_detail', 'nonconsuming'):
            assert 'ARITHMETIC_EQUALITY' in json.dumps(feedback)
            assert 'MALFORMED_OR_UNBOUND_PROPOSAL' not in json.dumps(feedback)
        for request in requests:
            assert request['nonce'] not in requests[1]['prompt']
    for i in result['attempts']:
        derived = lab_effect.read_record(folder / f'attempt_{i}_derivation.json')
        raw = lab_effect.read_record(folder / f'attempt_{i}_raw.json')
        assert derived['raw_sha256'] == hashlib.sha256(raw['output_text'].encode()).hexdigest()
        assert derived['proposal']['nonce'] == requests[i]['nonce']
        assert derived['execution_permission'] == 'NOT_GRANTED'
        assert json.loads(raw['output_text']) != derived['proposal']
    assert not (folder / 'sandbox_state.json').exists()
    assert lane.verify_operation(folder, expected_contract_sha256=pin)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'
    calls = len(SyntheticBackend.seen)
    with operator_session(path, expected_sha256=pin):
        assert invoke(value, op)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'
    assert len(SyntheticBackend.seen) == calls


def test_reviewed_subtraction_diagnostic_and_fixed_input_invariance(tmp_path):
    _, _, value, op = contract(tmp_path)
    task = copy.deepcopy(value['operations'][op]['task'])
    task['problem'] = {'left': 7, 'operation': 'subtract', 'right': 10}
    history = [{'raw': '{"answer":3}', 'nonce': 'a' * 32, 'feedback_mode': 'kt_diagnostic'}]
    prompt = build_interface_prompt(task, nonce='b' * 32, history=history, interface=configuration(MODES[0]))
    assert 'ARITHMETIC_EQUALITY' in prompt and 'MALFORMED_OR_UNBOUND_PROPOSAL' not in prompt
    assert 'a' * 32 not in prompt and 'b' * 32 not in prompt
    history[0]['nonce'] = 'c' * 32
    assert prompt == build_interface_prompt(task, nonce='e' * 32, history=history, interface=configuration(MODES[0]))
    legacy = build_prompt(task, nonce='b' * 32, history=history)
    assert 'MALFORMED_OR_UNBOUND_PROPOSAL' in legacy
    with pytest.raises(CheckedTaskError):
        parse_proposal('{"answer":-3}', task, nonce='b' * 32)


@pytest.mark.parametrize('raw', ['{"answer":true}', '{"answer":42.0}', '{"answer":"42"}',
    '{"answer":null}', '{"answer":42,"answer":42}', '{"answer":42}{}',
    '{"answer":42,"success":true}', '{"answer":NaN}', '{"answer":42,"nonce":"' + 'd' * 32 + '"}'])
def test_rejected_raw_is_preserved_derived_and_replayed_without_effect(tmp_path, raw, monkeypatch):
    monkeypatch.setattr(InterfaceBackend, 'override', raw)
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    folder = Path(value['output_root']) / op
    assert result['status'] == 'HELD_TASK_PREDICATE'
    assert lab_effect.read_record(folder / 'attempt_0_raw.json')['output_text'] == raw
    assert lab_effect.read_record(folder / 'attempt_0_derivation.json')['proposal'] is None
    assert not (folder / 'effect_prepared.json').exists()
    assert lane.verify_operation(folder, expected_contract_sha256=pin)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'


@pytest.mark.parametrize('mode', MODES)
def test_wrong_content_never_reaches_effect(tmp_path, mode):
    SyntheticBackend.answers = [41]
    path, pin, value, op = contract(tmp_path, mode)
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    assert result['status'] == 'HELD_TASK_PREDICATE'
    folder = Path(value['output_root']) / op
    assert not (folder / 'effect_prepared.json').exists()
    assert len(SyntheticBackend.seen) == 3
    assert lane.verify_operation(folder, expected_contract_sha256=pin)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'


@pytest.mark.parametrize('control', ['revoked', 'expired'])
def test_effect_time_authority_survives_host_binding(tmp_path, monkeypatch, control):
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    original = lab_effect.write_record
    def changed(target, record):
        result = original(target, record)
        if target.name == 'effect_prepared.json':
            if control == 'revoked':
                (Path(value['output_root']) / 'REVOKED').write_text('synthetic revocation')
            else:
                monkeypatch.setattr(time, 'time', lambda: value['expires_at'] + 1)
        return result
    monkeypatch.setattr(lab_effect, 'write_record', changed)
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    assert result['status'] == 'HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED'
    folder = Path(value['output_root']) / op
    assert not (folder / 'effect_applied.json').exists()
    assert lane.verify_operation(folder, expected_contract_sha256=pin)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'


def test_interrupted_reservation_does_not_regenerate(tmp_path):
    path, pin, value, op = contract(tmp_path)
    with operator_session(path, expected_sha256=pin) as session:
        session.reserve(op, 0, 'c' * 64)
    with operator_session(path, expected_sha256=pin):
        assert invoke(value, op)['status'] == 'HOLD_INTERRUPTED_OPERATION_NO_RETRY'
    assert not SyntheticBackend.seen


def test_interrupted_restoration_resumes_without_new_generation(tmp_path, monkeypatch):
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    restore = lab_effect._restore_owned_target
    def fail(root, prepared):
        raise OSError('synthetic interrupted restoration')
    monkeypatch.setattr(lab_effect, '_restore_owned_target', fail)
    with operator_session(path, expected_sha256=pin):
        assert invoke(value, op)['status'] == 'HOLD_EFFECT_FAILED_OR_NOT_AUTHORIZED'
    monkeypatch.setattr(lab_effect, '_restore_owned_target', restore)
    with operator_session(path, expected_sha256=pin):
        assert invoke(value, op)['status'] == 'RECOVERED_HELD_OPERATION_NO_RETRY'
    folder = Path(value['output_root']) / op
    assert len(SyntheticBackend.seen) == 1 and not (folder / 'sandbox_state.json').exists()
    assert lane.verify_operation(folder, expected_contract_sha256=pin)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'


@pytest.mark.parametrize('field', ['proposal_hash', 'raw_sha256', 'outer_nonce', 'request_hash', 'interface', 'proposal'])
def test_detached_reconstruction_rejects_rehashed_derivation_tamper(tmp_path, field):
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    with operator_session(path, expected_sha256=pin):
        invoke(value, op)
    folder = Path(value['output_root']) / op
    _rewrite_record(folder, 'attempt_0_derivation.json', lambda item: item.update({field: None}))
    with pytest.raises(RuntimeError, match='LAB_REPLAY_DERIVATION_MISMATCH'):
        lane.verify_operation(folder, expected_contract_sha256=pin)


@pytest.mark.parametrize('mutation', ['v1_extra', 'v2_missing', 'wrong_mode', 'missing_display', 'unhashed_change'])
def test_contract_cannot_implicitly_select_or_change_interface(tmp_path, mutation):
    _, _, value, op = contract(tmp_path)
    if mutation == 'v1_extra':
        value['schema_id'] = 'kt.lab.execution_contract.v1'
    elif mutation == 'v2_missing':
        del value['operations'][op]['response_interface']
    elif mutation == 'wrong_mode':
        value['operations'][op]['response_interface']['mode'] = 'auto'
    elif mutation == 'missing_display':
        del value['operations'][op]['response_interface']['display_nonce']
    else:
        value['operations'][op]['response_interface'] = configuration(MODES[1])
    with pytest.raises((RuntimeError, CheckedTaskError)):
        validate_contract(value)


@pytest.mark.parametrize('change,reason', [
    (lambda raw: raw.update(nonce='0' * 32), 'LAB_GENERATION_IDENTITY'),
    (lambda raw: raw.update(output_tokens=True), 'LAB_GENERATION_USAGE'),
    (lambda raw: raw.update(generated_token_ids=[1] * 16 + [2], output_tokens=17), 'LAB_OUTPUT_CAP'),
    (lambda raw: raw.update(finish_reason='MAX_NEW_TOKENS'), 'LAB_GENERATION_INCOMPLETE'),
])
def test_transport_and_actual_usage_checked_before_host_derivation(tmp_path, change, reason):
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    SyntheticBackend.mutate = staticmethod(change)
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    folder = Path(value['output_root']) / op
    assert result['status'] == 'HOLD_GENERATION_FAILED'
    assert reason in lab_effect.read_record(folder / 'attempt_0_failure.json')['reason']
    assert not (folder / 'attempt_0_derivation.json').exists()
    assert not (folder / 'effect_prepared.json').exists()
    assert lane.verify_operation(folder, expected_contract_sha256=pin)['status'] == 'REPLAY_NO_INFERENCE_NO_EFFECT'


def test_detached_fresh_process_uses_operator_verify_only(tmp_path):
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    with operator_session(path, expected_sha256=pin):
        invoke(value, op)
    operator = Path(lane.__file__).resolve().parents[3] / 'tools/operator/run_checked_lab.py'
    before = {p: p.read_bytes() for p in Path(value['output_root']).rglob('*') if p.is_file()}
    run = subprocess.run([sys.executable, '-B', str(operator), '--contract', str(path),
        '--contract-sha256', pin, '--verify-only'], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    assert before == {p: p.read_bytes() for p in Path(value['output_root']).rglob('*') if p.is_file()}
    assert len(SyntheticBackend.seen) == 1


def test_oracle_preserves_interface_and_separates_routes(tmp_path):
    from scripts.v15_oracle_harvest_common import current_checked_portfolio
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    with operator_session(path, expected_sha256=pin):
        invoke(value, op)
    (tmp_path / 'CONTRACT_external_run.json').write_bytes(path.read_bytes())
    freeze = {'schema_id': 'kt.h4.external_engineering_run.v1', 'run_id': 'synthetic_interface',
        'source_head': 'a' * 40, 'source_tree': 'b' * 40,
        'contracts': {'external_run': {'name': 'CONTRACT_external_run.json', 'sha256': pin}}}
    (tmp_path / 'RUN_FREEZE.json').write_bytes(canonical_bytes(freeze))
    report = current_checked_portfolio(tmp_path, freeze_sha256=identity(freeze),
        baseline_route='external_run/direct/host_bound_answer')
    assert report['rows'][0]['response_interface'] == configuration(MODES[0])
    assert report['rows'][0]['route'] == 'external_run/direct/host_bound_answer'


def test_full_control_wrong_display_binding_is_not_repaired(tmp_path, monkeypatch):
    path, pin, value, op = contract(tmp_path, MODES[1], strategy='direct', attempts=1)
    task = value['operations'][op]['task']
    raw = canonical_bytes({'schema_id': 'kt.lab.task_proposal.v1', 'task_hash': identity(task),
        'nonce': 'e' * 32, 'answer': 42}).decode()
    monkeypatch.setattr(InterfaceBackend, 'override', raw)
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    folder = Path(value['output_root']) / op
    assert result['status'] == 'HELD_TASK_PREDICATE'
    assert lab_effect.read_record(folder / 'attempt_0_derivation.json')['rejection'] == 'PROPOSAL_BINDING'
    assert lab_effect.read_record(folder / 'attempt_0_raw.json')['output_text'] == raw
    assert not (folder / 'effect_prepared.json').exists()
    lane.verify_operation(folder, expected_contract_sha256=pin)


@pytest.mark.parametrize('mode', MODES)
def test_planning_detail_second_attempt_uses_checked_totals_and_relations(tmp_path, mode):
    from test_checked_task import plan
    path, _, value, old_op = contract(tmp_path, mode, strategy='kt_constraint_detail')
    definition = value['operations'].pop(old_op)
    definition['task'] = plan()
    op = identity(definition)
    value['operations'] = {op: definition}
    path.write_bytes(canonical_bytes(value))
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    SyntheticBackend.answers = [['B'], ['A', 'B']]
    with operator_session(path, expected_sha256=pin):
        result = invoke(value, op)
    assert result['status'] == 'CHECKED_EFFECT_RESTORED', result
    feedback = json.loads(SyntheticBackend.seen[1].split('\n', 1)[1])['prior_attempts'][0]['feedback']
    assert feedback['diagnostics'] == ['MANDATORY', 'REQUIRES']
    assert feedback['observed'] == {'cost': 3, 'time': 1, 'value': 7, 'selected_projects': 1}
    assert feedback['violated_relations']['requires'] == [['B', 'A']]
    assert feedback['optimality'] == 'NOT_CHECKED' and feedback['execution_permission'] == 'NOT_GRANTED'
    folder = Path(value['output_root']) / op
    for i in (0, 1):
        request = lab_effect.read_record(folder / f'attempt_{i}_request.json')
        assert request['nonce'] not in SyntheticBackend.seen[1]
    lane.verify_operation(folder, expected_contract_sha256=pin)


@pytest.mark.parametrize('tamper', ['missing', 'extra'])
def test_detached_derivation_exact_roster_even_after_rehash(tmp_path, tamper):
    path, pin, value, op = contract(tmp_path, strategy='direct', attempts=1)
    SyntheticBackend.answers = [42]
    with operator_session(path, expected_sha256=pin):
        invoke(value, op)
    original = Path(value['output_root']) / op
    altered = tmp_path / 'altered' / op
    altered.mkdir(parents=True)
    (altered.parent / 'operator_contract.json').write_bytes(path.read_bytes())
    for file in original.iterdir():
        if file.is_file() and not (tamper == 'missing' and file.name.endswith('_derivation.json')):
            (altered / file.name).write_bytes(file.read_bytes())
    if tamper == 'extra':
        (altered / 'attempt_1_derivation.json').write_bytes((original / 'attempt_0_derivation.json').read_bytes())
    result = lab_effect.read_record(altered / 'result.json')
    result['files'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in altered.iterdir() if p.is_file() and p.name != 'result.json'}
    (altered / 'result.json').write_bytes(canonical_bytes(result))
    with pytest.raises(RuntimeError, match='LAB_REPLAY_DERIVATION_ROSTER'):
        lane.verify_operation(altered, expected_contract_sha256=pin)
