/* eslint-disable no-alert */
(() => {
  'use strict';

  const byId = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

  const state = {
    files: /** @type {Map<string, { name: string, text: string, json: any | null }>} */ (new Map()),
    runRoot: null,
  };

  const escapeHtml = (s) =>
    String(s)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

  const classifyPassFail = (value) => {
    const v = String(value || '').toUpperCase();
    if (v === 'PASS' || v === 'OK' || v === 'TRUE') return 'pass';
    if (v === 'FAIL' || v === 'FAIL_CLOSED' || v === 'ERROR' || v === 'FALSE') return 'fail';
    return 'unknown';
  };

  const setVerdict = (text) => {
    const el = byId('verdictBlock');
    const t = String(text || '').trim();
    if (!t) {
      el.textContent = 'No verdict loaded.';
      el.className = 'verdict verdict--unknown';
      return;
    }
    el.textContent = t;
    const cls = t.includes('PASS') ? 'pass' : t.includes('FAIL') ? 'fail' : 'unknown';
    el.className = `verdict verdict--${cls}`;
  };

  const renderKv = (targetId, obj, keys) => {
    const el = byId(targetId);
    if (!obj) {
      el.className = 'kv muted';
      el.textContent = `No ${targetId} loaded.`;
      return;
    }
    const rows = [];
    for (const k of keys) {
      const v = obj[k];
      const cls = classifyPassFail(v);
      rows.push(
        `<div class="kv__row"><div class="kv__k">${escapeHtml(k)}</div><div class="kv__v kv__v--${cls}">${escapeHtml(
          v === undefined ? '(missing)' : typeof v === 'string' ? v : JSON.stringify(v)
        )}</div></div>`
      );
    }
    el.className = 'kv';
    el.innerHTML = rows.join('');
  };

  const renderKvRows = (targetId, rows) => {
    const el = byId(targetId);
    if (!rows || rows.length === 0) {
      el.className = 'kv muted';
      el.textContent = `No ${targetId} loaded.`;
      return;
    }
    el.className = 'kv';
    el.innerHTML = rows
      .map(
        (r) =>
          `<div class="kv__row"><div class="kv__k">${escapeHtml(r.k)}</div><div class="kv__v kv__v--${escapeHtml(
            r.cls || 'unknown'
          )}">${escapeHtml(r.v)}</div></div>`
      )
      .join('');
  };

  const setRunRootHint = (runRoot) => {
    const el = byId('runRootHint');
    el.textContent = `run_root: ${runRoot || '(unknown)'}`;
  };

  const setLoadedCount = (n) => {
    const el = byId('loadedCount');
    el.textContent = `${n} loaded`;
  };

  const renderFileList = () => {
    const el = byId('fileList');
    const items = Array.from(state.files.keys()).sort((a, b) => a.localeCompare(b));
    if (items.length === 0) {
      el.className = 'fileList muted';
      el.textContent = 'No files loaded.';
      return;
    }

    const rows = items.map((name) => {
      const isJson = name.toLowerCase().endsWith('.json');
      const cls = isJson ? 'fileList__item fileList__item--json' : 'fileList__item';
      return `<div class="${cls}"><button type="button" class="linkBtn" data-name="${escapeHtml(
        name
      )}">${escapeHtml(name)}</button></div>`;
    });

    el.className = 'fileList';
    el.innerHTML = rows.join('');

    for (const btn of el.querySelectorAll('button[data-name]')) {
      btn.addEventListener('click', () => {
        const name = btn.getAttribute('data-name');
        if (!name) return;
        const entry = state.files.get(name);
        if (!entry || entry.json == null) {
          byId('rawJson').textContent = 'Selected file is not JSON.';
          byId('rawJson').className = 'rawJson muted';
          return;
        }
        byId('rawJson').textContent = JSON.stringify(entry.json, null, 2);
        byId('rawJson').className = 'rawJson';
      });
    }
  };

  const _jsonFilesByPredicate = (pred) => {
    const out = [];
    for (const [name, entry] of state.files.entries()) {
      if (entry.json == null) continue;
      try {
        if (pred(name, entry.json)) out.push({ name, json: entry.json });
      } catch (_) {
        // ignore
      }
    }
    return out;
  };

  const _getJsonFile = (name) => state.files.get(name)?.json || null;

  const _getTextFile = (name) => state.files.get(name)?.text || '';

  const hydrateDerivedViews = () => {
    setLoadedCount(state.files.size);

    const verdict = _getTextFile('verdict.txt');
    setVerdict(verdict);

    const sweep = _getJsonFile('sweep_summary.json');
    if (sweep && typeof sweep === 'object') {
      state.runRoot = sweep.run_root || state.runRoot;
    }
    setRunRootHint(state.runRoot);

    renderKv('sweepSummaryBlock', sweep, ['status', 'sweep_id', 'run_root']);

    const status = _getJsonFile('status_report.json');
    renderKv('statusReportBlock', status, ['sealed_commit', 'sealed_tag', 'head', 'law_bundle_hash', 'suite_registry_id']);

    const sealVerifyFiles = _jsonFilesByPredicate((name) => name.toLowerCase().endsWith('seal_verify_report.json'));
    if (sealVerifyFiles.length === 0) {
      renderKvRows('sealVerifyBlock', []);
    } else {
      const rows = [];
      for (const f of sealVerifyFiles.sort((a, b) => a.name.localeCompare(b.name))) {
        rows.push({ k: f.name, v: '', cls: 'unknown' });
        rows.push({ k: 'status', v: String(f.json.status ?? '(missing)'), cls: classifyPassFail(f.json.status) });
        rows.push({
          k: 'bundle_root_hash',
          v: String(f.json.bundle_root_hash ?? '(missing)'),
          cls: String(f.json.bundle_root_hash || '').length ? 'unknown' : 'fail',
        });
        if (f.json.seal_pack_id !== undefined) rows.push({ k: 'seal_pack_id', v: String(f.json.seal_pack_id), cls: 'unknown' });
        if (f.json.evidence_dir !== undefined) rows.push({ k: 'evidence_dir', v: String(f.json.evidence_dir), cls: 'unknown' });
      }
      renderKvRows('sealVerifyBlock', rows);
    }

    const redAssaultFiles = _jsonFilesByPredicate((name) => name.toLowerCase().endsWith('red_assault_report.json'));
    if (redAssaultFiles.length === 0) {
      renderKvRows('redAssaultBlock', []);
    } else {
      const rows = [];
      for (const f of redAssaultFiles.sort((a, b) => a.name.localeCompare(b.name))) {
        rows.push({ k: f.name, v: '', cls: 'unknown' });
        rows.push({ k: 'all_passed', v: String(f.json.all_passed ?? '(missing)'), cls: classifyPassFail(f.json.all_passed) });
        rows.push({
          k: 'red_assault_id',
          v: String(f.json.red_assault_id ?? '(missing)'),
          cls: String(f.json.red_assault_id || '').length ? 'unknown' : 'fail',
        });
        if (f.json.status !== undefined) rows.push({ k: 'status', v: String(f.json.status), cls: classifyPassFail(f.json.status) });
      }
      renderKvRows('redAssaultBlock', rows);
    }

    // Determinism
    const detFromStatus = status && typeof status === 'object' ? status.determinism_expected_root_hash : null;
    const detAnchor = _getJsonFile('FL4_DETERMINISM_ANCHOR.v1.json');
    const detFromAnchor = detAnchor && typeof detAnchor === 'object' ? detAnchor.expected_determinism_root_hash : null;
    const det = detFromStatus || detFromAnchor || null;
    if (!det) {
      renderKvRows('determinismBlock', [{ k: 'expected_determinism_root_hash', v: '(missing)', cls: 'fail' }]);
    } else {
      renderKvRows('determinismBlock', [{ k: 'expected_determinism_root_hash', v: String(det), cls: 'unknown' }]);
    }

    // Receipts
    const receiptPtr =
      status && typeof status === 'object' ? status.authoritative_reseal_receipt || status.authoritative_v1_receipt : null;
    if (!receiptPtr) {
      renderKvRows('receiptsBlock', [{ k: 'authoritative_receipt', v: '(missing)', cls: 'fail' }]);
    } else {
      renderKvRows('receiptsBlock', [{ k: 'authoritative_receipt', v: String(receiptPtr), cls: 'unknown' }]);
    }

    // Suites
    const suiteDefs = _jsonFilesByPredicate((_, j) => j && typeof j === 'object' && j.schema_id === 'kt.suite_definition.v1');
    const packManifests = _jsonFilesByPredicate((name, j) => name.toLowerCase().includes('manifest') && j && typeof j === 'object');
    const suiteRows = [];
    for (const f of suiteDefs.sort((a, b) => a.name.localeCompare(b.name))) {
      const cases = Array.isArray(f.json.cases) ? f.json.cases.length : 0;
      suiteRows.push({ k: f.name, v: '', cls: 'unknown' });
      suiteRows.push({ k: 'suite_id', v: String(f.json.suite_id ?? '(missing)'), cls: String(f.json.suite_id || '').length ? 'unknown' : 'fail' });
      suiteRows.push({ k: 'suite_definition_id', v: String(f.json.suite_definition_id ?? '(missing)'), cls: String(f.json.suite_definition_id || '').length ? 'unknown' : 'fail' });
      suiteRows.push({ k: 'cases', v: String(cases), cls: cases > 0 ? 'unknown' : 'fail' });
    }
    // Pack manifests: best-effort display known fields without assuming schema.
    for (const f of packManifests.sort((a, b) => a.name.localeCompare(b.name))) {
      if (suiteRows.length > 0) break;
      if (!f.name.toLowerCase().includes('pack')) continue;
      suiteRows.push({ k: f.name, v: '', cls: 'unknown' });
      for (const k of ['pack_id', 'seed', 'variants_per_case', 'transforms', 'out_suite_definition_id']) {
        if (f.json[k] === undefined) continue;
        suiteRows.push({ k, v: typeof f.json[k] === 'string' ? f.json[k] : JSON.stringify(f.json[k]), cls: 'unknown' });
      }
    }
    if (suiteRows.length === 0) {
      renderKvRows('suitesBlock', [{ k: 'suite', v: '(missing)', cls: 'fail' }]);
    } else {
      renderKvRows('suitesBlock', suiteRows);
    }

    // Required artifacts panel
    const required = [];
    required.push({
      k: 'verdict.txt',
      v: verdict.trim() ? 'loaded' : 'missing',
      cls: verdict.trim() ? 'pass' : 'fail',
    });
    required.push({
      k: 'sweep_summary.json',
      v: sweep ? 'loaded' : 'missing',
      cls: sweep ? classifyPassFail(sweep.status) : 'fail',
    });
    required.push({
      k: 'status_report.json',
      v: status ? 'loaded' : 'missing',
      cls: status ? classifyPassFail(status.status) : 'fail',
    });
    required.push({
      k: 'determinism',
      v: det ? 'present' : 'missing',
      cls: det ? 'pass' : 'fail',
    });
    required.push({
      k: 'seal_verify_report.json (any)',
      v: sealVerifyFiles.length ? `loaded(${sealVerifyFiles.length})` : 'missing',
      cls: sealVerifyFiles.length ? 'pass' : 'unknown',
    });
    required.push({
      k: 'red_assault_report.json (any)',
      v: redAssaultFiles.length ? `loaded(${redAssaultFiles.length})` : 'missing',
      cls: redAssaultFiles.length ? 'pass' : 'unknown',
    });
    renderKvRows('requiredBlock', required);

    renderFileList();
  };

  const clearAll = () => {
    state.files.clear();
    state.runRoot = null;
    byId('fileInput').value = '';
    byId('rawJson').textContent = 'No JSON selected.';
    byId('rawJson').className = 'rawJson muted';
    hydrateDerivedViews();
  };

  const ingestFiles = async (fileList) => {
    const files = Array.from(fileList || []);
    for (const f of files) {
      const name = f.name;
      const text = await f.text();
      let json = null;
      if (name.toLowerCase().endsWith('.json')) {
        try {
          json = JSON.parse(text);
        } catch (e) {
          json = { __parse_error: String(e), __raw_text_preview: text.slice(0, 2000) };
        }
      }
      state.files.set(name, { name, text, json });
    }
    hydrateDerivedViews();
  };

  const main = () => {
    byId('fileInput').addEventListener('change', async (ev) => {
      const input = /** @type {HTMLInputElement} */ (ev.target);
      try {
        await ingestFiles(input.files);
      } catch (e) {
        alert(`Failed to load files: ${String(e)}`);
      }
    });
    byId('clearBtn').addEventListener('click', clearAll);

    hydrateDerivedViews();
  };

  main();
})();
