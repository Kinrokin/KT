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

  const hydrateDerivedViews = () => {
    setLoadedCount(state.files.size);

    const verdict = state.files.get('verdict.txt')?.text || '';
    setVerdict(verdict);

    const sweep = state.files.get('sweep_summary.json')?.json || null;
    if (sweep && typeof sweep === 'object') {
      state.runRoot = sweep.run_root || state.runRoot;
    }
    setRunRootHint(state.runRoot);

    renderKv('sweepSummaryBlock', sweep, ['status', 'sweep_id', 'run_root']);

    const status = state.files.get('status_report.json')?.json || null;
    renderKv('statusReportBlock', status, ['sealed_commit', 'sealed_tag', 'head', 'law_bundle_hash', 'suite_registry_id']);

    const sealVerify =
      state.files.get('seal_verify_report.json')?.json ||
      state.files.get('packC_seal_verify_report.json')?.json ||
      state.files.get('packD_seal_verify_report.json')?.json ||
      null;
    renderKv('sealVerifyBlock', sealVerify, ['status', 'bundle_root_hash', 'seal_pack_id', 'evidence_dir']);

    const redAssault =
      state.files.get('red_assault_report.json')?.json ||
      state.files.get('packC_red_assault_report.json')?.json ||
      state.files.get('packD_red_assault_report.json')?.json ||
      null;
    renderKv('redAssaultBlock', redAssault, ['all_passed', 'red_assault_id', 'status']);

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

