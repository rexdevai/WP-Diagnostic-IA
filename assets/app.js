/* =========================================================
   WP Diagnostic AI — app.js
   Pipeline client. Credentials travel in memory and are sent
   with every request (no PHP session dependency).
   Scanner API keys (VirusTotal, Sucuri) are optional and only
   sent to the `run` endpoint.
   ========================================================= */

(() => {
  'use strict';

  const ENDPOINT = 'index.php';
  const POLL_FALLBACK_MS = 1500;

  const AGENTS = [
    { key: 'forensic_agent', num: '00', title: 'Forensic',  role: 'Integrity pre-analysis' },
    { key: 'analyzer',       num: '01', title: 'Analyzer',  role: 'Structured diagnosis' },
    { key: 'verifier',       num: '02', title: 'Verifier',  role: 'Diagnosis audit' },
    { key: 'writer',         num: '03', title: 'Writer',    role: 'Client response' },
    { key: 'operator',       num: '04', title: 'Operator',  role: 'Suggested actions' },
  ];

  const state = {
    es: null,
    runId: null,
    lastHash: null,
    pollTimer: null,
    fullState: null,
    credentials: {
      site_url:       '',
      gemini_key:     '',
      wpdiag_key:     '',
      vt_api_key:     '',
      sucuri_api_key: '',
    },
  };

  // ─────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────

  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

  const pretty = (v) => { try { return JSON.stringify(v, null, 2); } catch { return String(v); } };

  async function post(action, body) {
    console.log(`[wpdiag] POST ?action=${action}`, body);
    const res = await fetch(`${ENDPOINT}?action=${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({ error: 'Response is not JSON' }));
    console.log(`[wpdiag] ← ?action=${action}`, data);
    if (!res.ok && !data.error && !data.status) data.error = `HTTP ${res.status}`;
    return data;
  }

  // ─────────────────────────────────────────────────────────
  // Views
  // ─────────────────────────────────────────────────────────

  function showView(name) {
    $$('.view').forEach(v => v.classList.toggle('active', v.dataset.view === name));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function showBanner(kind, html) {
    const b = $('#banner');
    b.className = `banner ${kind}`;
    b.innerHTML = `<span class="icon">${
      kind === 'error' ? '⛔' : kind === 'warn' ? '⚠️' :
      kind === 'ok'    ? '✅' : 'ℹ️'
    }</span><div class="body">${html}</div>`;
    b.classList.remove('hidden');
  }
  function hideBanner() { $('#banner').classList.add('hidden'); }

  function setStatus(text, kind = 'running', right = '') {
    const bar = $('#status-bar');
    bar.className = `status-bar ${kind}`;
    $('#status-text').textContent  = text;
    $('#status-right').textContent = right;
  }

  // ─────────────────────────────────────────────────────────
  // Log
  // ─────────────────────────────────────────────────────────

  function logLine(msg, kind = 'info') {
    const s = $('#log-stream');
    const el = document.createElement('div');
    el.className = `line ${kind}`;
    el.innerHTML = `<span class="ts">${ts()}</span>${esc(msg)}`;
    s.appendChild(el);
    s.scrollTop = s.scrollHeight;
  }
  function clearLog() { $('#log-stream').innerHTML = ''; }

  // ─────────────────────────────────────────────────────────
  // Pipeline: agent cards
  // ─────────────────────────────────────────────────────────

  function buildAgentCards() {
    const root = $('#pipeline');
    root.innerHTML = '';
    AGENTS.forEach(a => {
      const c = document.createElement('div');
      c.className = 'agent-card';
      c.dataset.agent = a.key;
      c.dataset.status = 'idle';
      c.innerHTML = `
        <div class="head">
          <span class="num">${a.num}</span>
          <span class="badge">waiting</span>
          <span class="title">${esc(a.title)}</span>
          <span class="role">${esc(a.role)}</span>
          <span class="toggle">▸</span>
        </div>
        <div class="body"><pre class="output"><span class="empty">Pending.</span></pre></div>`;
      c.querySelector('.head').addEventListener('click', () => c.classList.toggle('expanded'));
      root.appendChild(c);
    });
  }

  function updateAgent(key, status, output) {
    const c = document.querySelector(`.agent-card[data-agent="${key}"]`);
    if (!c) return;
    c.dataset.status = status;
    const badgeText = {
      idle: 'waiting', running: 'active', done: 'ok',
      error: 'error', paused: 'paused', skipped: 'skipped',
    }[status] || status;
    c.querySelector('.badge').textContent = badgeText;

    if (output !== undefined) {
      const pre = c.querySelector('.output');
      if (output === null) pre.innerHTML = '<span class="empty">No data.</span>';
      else pre.textContent = typeof output === 'string' ? output : pretty(output);
    }

    if (status === 'running' && !c.classList.contains('expanded')) {
      c.classList.add('expanded');
    }
  }

  // ─────────────────────────────────────────────────────────
  // Site summary
  // ─────────────────────────────────────────────────────────

  function renderSiteSummary(resumen) {
    const box = $('#site-summary');
    if (!resumen) { box.innerHTML = ''; return; }

    const corePending     = !!resumen.core_pending;
    const pendingPlugins  = Number(resumen.pending_plugins || 0);

    let updatesTxt = '—';
    let updatesCls = '';
    if (corePending && pendingPlugins > 0) {
      updatesTxt = `core + ${pendingPlugins} plugins`;
      updatesCls = 'bad';
    } else if (corePending) {
      updatesTxt = 'core pending';
      updatesCls = 'bad';
    } else if (pendingPlugins > 0) {
      updatesTxt = `${pendingPlugins} plugins`;
      updatesCls = 'warn';
    } else {
      updatesTxt = 'up to date';
      updatesCls = 'ok';
    }

    const cells = [
      ['Site',             resumen.site_name,      ''],
      ['URL',              resumen.url,            ''],
      ['WordPress',        resumen.wp_version,     ''],
      ['PHP',              resumen.php_version,    resumen.php_version && parseFloat(resumen.php_version) < 8.0 ? 'warn' : ''],
      ['Active plugins',   resumen.active_plugins, ''],
      ['WP_DEBUG',         resumen.debug_active ? 'YES' : 'no', resumen.debug_active ? 'bad' : 'ok'],
      ['SSL',              resumen.ssl_active ? 'active' : 'MISSING', resumen.ssl_active ? 'ok' : 'bad'],
      ['Updates',          updatesTxt,             updatesCls],
      ['Admins',           resumen.admin_users,    ''],
      ['DB size',          resumen.db_size,        ''],
    ];

    box.innerHTML = cells.map(([k, v, cls]) =>
      `<div class="cell"><div class="k">${esc(k)}</div><div class="v ${cls}">${esc(v ?? '—')}</div></div>`
    ).join('');
  }

  // ─────────────────────────────────────────────────────────
  // Diagnosis rendering
  // ─────────────────────────────────────────────────────────

  function renderDiagnosis(diag) {
    const box = $('#result-diag');
    if (!diag) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');

    const sev  = diag.severity   || 'informational';
    const conf = diag.confidence || '?';
    const cat  = diag.category   || '?';

    $('#diag-sev').textContent  = sev;
    $('#diag-sev').className    = `pill ${sev}`;
    $('#diag-conf').textContent = `confidence: ${conf}`;
    $('#diag-cat').textContent  = cat;
    $('#diag-cause').textContent = diag.main_cause || 'No main cause determined.';

    // Technical findings
    const ul = $('#diag-findings');
    ul.innerHTML = '';
    (diag.findings || []).forEach(h => {
      const li = document.createElement('li');
      li.innerHTML = `
        <div class="f-type">${esc(h.type || 'finding')}</div>
        <div class="f-desc">${esc(h.description || '')}</div>
        ${h.evidence ? `<div class="f-evidence">${esc(h.evidence)}</div>` : ''}
        ${h.impact   ? `<div class="f-impact">↳ ${esc(h.impact)}</div>` : ''}`;
      ul.appendChild(li);
    });

    const hyp  = (diag.alternative_hypotheses || []).filter(Boolean);
    const info = (diag.missing_info || []).filter(Boolean);
    const extras = [];
    if (hyp.length)  extras.push(`<div class="f-impact"><strong>Alternative hypotheses:</strong> ${hyp.map(esc).join(' · ')}</div>`);
    if (info.length) extras.push(`<div class="f-impact"><strong>Missing info:</strong> ${info.map(esc).join(' · ')}</div>`);
    if (extras.length) {
      const li = document.createElement('li');
      li.innerHTML = extras.join('');
      ul.appendChild(li);
    }

    // Forensic findings
    const fWrap = $('#diag-forensics-wrap');
    const fUl   = $('#diag-forensics');
    fUl.innerHTML = '';
    const forensic = diag.forensic_findings || [];
    if (forensic.length) {
      fWrap.classList.remove('hidden');
      forensic.forEach(h => {
        const li = document.createElement('li');
        const sevTag = h.severity
          ? `<span class="f-impact" style="display:inline-block;margin-left:8px">[${esc(h.severity)}]</span>`
          : '';
        const evidencia = h.evidence ? `<div class="f-evidence">${esc(h.evidence)}</div>` : '';
        li.innerHTML = `
          <div class="f-type">${esc(h.type || 'forensic')}${sevTag}</div>
          <div class="f-desc">${esc(h.description || '')}</div>
          ${evidencia}
          ${h.file ? `<div class="f-impact mono">↳ ${esc(h.file)}</div>` : ''}`;
        fUl.appendChild(li);
      });
    } else {
      fWrap.classList.add('hidden');
    }
  }

  // ─────────────────────────────────────────────────────────
  // Raw forensic panel
  // ─────────────────────────────────────────────────────────

  function renderRawForensics(raw, forensicAgent) {
    const details = $('#raw-forensics');
    if (!details) return;
    if (!raw && !forensicAgent) { details.classList.add('hidden'); return; }
    details.classList.remove('hidden');

    const hasData = raw && typeof raw === 'object';

    // Scan stats
    if (hasData && raw.scan_stats) {
      const s = raw.scan_stats;
      const wrap = $('#raw-stats-wrap');
      if (wrap) {
        wrap.classList.remove('hidden');
        $('#raw-stats').innerHTML = `
          <div class="raw-row"><span class="raw-k">Files scanned</span><span class="raw-v">${esc(s.files_scanned ?? '—')}</span></div>
          <div class="raw-row"><span class="raw-k">With patterns</span><span class="raw-v">${esc(s.with_patterns ?? '—')}</span></div>
          <div class="raw-row"><span class="raw-k">Discarded by checksum</span><span class="raw-ok">${esc(s.discarded_by_checksum ?? '—')}</span></div>
          <div class="raw-row"><span class="raw-k">Discarded by rule</span><span class="raw-ok">${esc(s.discarded_by_rule ?? '—')}</span></div>
          <div class="raw-row"><span class="raw-k">Discarded as vendor</span><span class="raw-ok">${esc(s.discarded_vendor ?? '—')}</span></div>
          <div class="raw-row"><span class="raw-k">Reported</span><span class="raw-warn">${esc(s.reported ?? '—')}</span></div>
        `;
      }
    } else {
      const wrap = $('#raw-stats-wrap');
      if (wrap) wrap.classList.add('hidden');
    }

    // Core integrity
    if (hasData && raw.core_integrity) {
      const c = raw.core_integrity;
      $('#raw-core-wrap').classList.remove('hidden');
      $('#raw-core').innerHTML = _formatList({
        'checked':    c.checked,
        'version':    c.version,
        'total':      c.total,
        'mismatches': c.mismatches,
        'missing':    c.missing,
      });
    } else {
      $('#raw-core-wrap').classList.add('hidden');
    }

    // Plugin integrity
    if (hasData && raw.plugin_integrity) {
      $('#raw-plugins-wrap').classList.remove('hidden');
      $('#raw-plugins').innerHTML = _formatList({ 'mismatches': raw.plugin_integrity.mismatches });
    } else {
      $('#raw-plugins-wrap').classList.add('hidden');
    }

    // Suspicious files
    if (hasData && raw.suspicious_files) {
      $('#raw-suspicious-wrap').classList.remove('hidden');
      $('#raw-suspicious').innerHTML = _formatList({ 'files': raw.suspicious_files });
    } else {
      $('#raw-suspicious-wrap').classList.add('hidden');
    }

    // Recent changes
    if (hasData && raw.recent_changes) {
      $('#raw-recent-wrap').classList.remove('hidden');
      $('#raw-recent').innerHTML = _formatList({ 'files': raw.recent_changes });
    } else {
      $('#raw-recent-wrap').classList.add('hidden');
    }

    // Cron
    if (hasData && raw.cron_suspicious) {
      $('#raw-cron-wrap').classList.remove('hidden');
      $('#raw-cron').innerHTML = _formatList({ 'tasks': raw.cron_suspicious });
    } else {
      $('#raw-cron-wrap').classList.add('hidden');
    }

    // .htaccess
    if (hasData) {
      $('#raw-htaccess').innerHTML = raw.htaccess_suspicious
        ? `<span class="raw-warn">⚠ Suspicious rules detected in .htaccess</span>`
        : `<span class="raw-ok">No suspicious rules</span>`;
    }

    // Forensic agent summary
    if (forensicAgent) {
      $('#raw-forensic-agent').innerHTML = _formatList({
        'risk_level':           forensicAgent.risk_level,
        'summary':              forensicAgent.summary,
        'compromise_indicators': forensicAgent.compromise_indicators,
      });
    }
  }

  function _formatList(obj) {
    const parts = [];
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined || v === null) continue;

      if (Array.isArray(v)) {
        if (v.length === 0) {
          parts.push(`<div class="raw-row"><span class="raw-k">${esc(k)}</span><span class="raw-ok">empty</span></div>`);
          continue;
        }
        const items = v.map(item => {
          if (typeof item === 'string') return `<li>${esc(item)}</li>`;
          if (typeof item === 'object') {
            if (item.path || item.file || item.ruta) {
              const main = item.path || item.file || item.ruta;
              const extras = Object.entries(item)
                .filter(([kk]) => kk !== 'path' && kk !== 'file' && kk !== 'ruta')
                .map(([kk, vv]) => `${kk}: ${typeof vv === 'object' ? JSON.stringify(vv) : vv}`)
                .join(' · ');
              return `<li><span class="mono">${esc(main)}</span>${extras ? `<br><span class="muted">${esc(extras)}</span>` : ''}</li>`;
            }
            return `<li><pre>${esc(pretty(item))}</pre></li>`;
          }
          return `<li>${esc(String(item))}</li>`;
        }).join('');
        parts.push(`<div class="raw-row"><span class="raw-k">${esc(k)}</span> <span class="raw-count">(${v.length})</span></div><ul class="raw-list">${items}</ul>`);
      } else if (typeof v === 'object') {
        parts.push(`<div class="raw-row"><span class="raw-k">${esc(k)}</span></div><pre class="raw-pre">${esc(pretty(v))}</pre>`);
      } else if (typeof v === 'boolean') {
        const cls = v ? 'raw-warn' : 'raw-ok';
        parts.push(`<div class="raw-row"><span class="raw-k">${esc(k)}</span><span class="${cls}">${v ? 'yes' : 'no'}</span></div>`);
      } else {
        parts.push(`<div class="raw-row"><span class="raw-k">${esc(k)}</span><span class="raw-v">${esc(String(v))}</span></div>`);
      }
    }
    return parts.join('');
  }

  // ─────────────────────────────────────────────────────────
  // Client response
  // ─────────────────────────────────────────────────────────

  function renderClientResponse(text) {
    const box = $('#result-reply');
    if (!text) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    $('#result-reply .content').textContent = text;
  }

  // ─────────────────────────────────────────────────────────
  // Actions
  // ─────────────────────────────────────────────────────────

  function renderActions(actions) {
    const box  = $('#result-actions');
    const grid = $('#actions-grid');
    grid.innerHTML = '';

    if (!actions || !actions.length) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');

    actions.forEach(a => {
      const card = document.createElement('div');
      card.className = 'action-card';
      card.dataset.risk = (a.risk || 'low').toLowerCase();
      const url = urlForAction(a.id, state.fullState?.site_url);
      const executable = a.executable && url;

      card.innerHTML = `
        <span class="risk">risk ${esc(a.risk || 'low')}</span>
        <h4>${esc(a.action || a.id)}</h4>
        <p class="desc">${esc(a.description || '')}</p>
        ${!executable && a.manual_action ? `<div class="manual">${esc(a.manual_action)}</div>` : ''}
        <div class="foot"></div>`;

      const foot = card.querySelector('.foot');

      if (a.id === 'copy_response') {
        const b = btn('Copy response');
        b.addEventListener('click', () => copyResponse(b));
        foot.appendChild(b);
      } else if (a.id === 'generate_report') {
        const b = btn('Generate report');
        b.addEventListener('click', () => window.print());
        foot.appendChild(b);
      } else if (executable) {
        const b = btn('Open');
        b.classList.add('primary');
        b.addEventListener('click', () => window.open(url, '_blank', 'noopener'));
        foot.appendChild(b);
      } else {
        const b = btn('Not available');
        b.disabled = true;
        foot.appendChild(b);
      }

      grid.appendChild(card);
    });
  }

  function btn(label) {
    const b = document.createElement('button');
    b.className = 'ghost';
    b.textContent = label;
    return b;
  }

  function urlForAction(id, site) {
    if (!site) return null;
    const base = site.replace(/\/$/, '') + '/wp-admin';
    switch (id) {
      case 'view_plugins':  return `${base}/plugins.php`;
      case 'view_updates':  return `${base}/update-core.php`;
      case 'view_logs':     return `${base}/tools.php`;
      default: return null;
    }
  }

  async function copyResponse(b) {
    const txt = $('#result-reply .content')?.textContent || '';
    try {
      await navigator.clipboard.writeText(txt);
      const orig = b.textContent;
      b.textContent = '✓ copied';
      setTimeout(() => (b.textContent = orig), 1500);
    } catch { logLine('Could not copy to clipboard', 'error'); }
  }

  // ─────────────────────────────────────────────────────────
  // State rendering
  // ─────────────────────────────────────────────────────────

  function applyState(st) {
    if (!st || typeof st !== 'object') return;
    state.fullState = st;

    if (st.context_summary) renderSiteSummary(st.context_summary);

    const log = st.internal_log || [];
    if (log.length !== (applyState._lastLogLen || 0)) {
      const from = applyState._lastLogLen || 0;
      for (let i = from; i < log.length; i++) logLine(log[i], 'info');
      applyState._lastLogLen = log.length;
    }

    // Forensic
    if (st.forensic_agent) updateAgent('forensic_agent', 'done', st.forensic_agent);
    else if (st.current_step >= 1) updateAgent('forensic_agent', st.current_step === 1 ? 'running' : 'idle');

    // Analyzer
    if (st.analyzer) updateAgent('analyzer', st.analyzer.confidence === 'low' ? 'paused' : 'done', st.analyzer);
    else if (st.current_step >= 2) updateAgent('analyzer', st.current_step === 2 ? 'running' : 'idle');

    // Verifier
    if (st.verifier) {
      const v = (st.verifier.verdict || '').toLowerCase();
      updateAgent('verifier', v === 'rejected' ? 'error' : 'done', st.verifier);
    } else if (st.current_step >= 3) updateAgent('verifier', st.current_step === 3 ? 'running' : 'idle');

    // Writer
    if (st.writer) updateAgent('writer', 'done', st.writer);
    else if (st.current_step >= 4) updateAgent('writer', st.current_step === 4 ? 'running' : 'idle');

    // Operator
    if (st.operator) updateAgent('operator', 'done', st.operator);
    else if (st.current_step >= 5) updateAgent('operator', st.current_step === 5 ? 'running' : 'idle');

    // Warnings
    if (Array.isArray(st.errors) && st.errors.length) {
      st.errors.forEach(e => logLine(e, 'warn'));
    }

    // Global status
    if (st.fatal_error) {
      setStatus('Fatal error', 'error');
      showBanner('error',
        `<strong>${esc(st.fatal_error.type)}</strong> — ${esc(st.fatal_error.message)}`);
    } else if (st.requires_human) {
      setStatus('Pipeline completed (with warnings)', 'ok', `${st.estimated_tokens} tokens`);
      showBanner('warn',
        `<strong>Human review required.</strong><br>${esc(st.requires_human_reason || '')}`);
    } else if (st.completed) {
      setStatus(`Pipeline completed · ${st.total_time}s`, 'ok', `${st.estimated_tokens} tokens`);
    } else {
      setStatus(`Step ${st.current_step} of 5`, 'running', `${st.estimated_tokens} tokens`);
    }

    // Final render
    if (st.completed) {
      if (st.final_diagnosis)  renderDiagnosis(st.final_diagnosis);
      if (st.client_response)  renderClientResponse(st.client_response);
      if (Array.isArray(st.actions)) renderActions(st.actions);

      if (st.forensics_raw || st.forensic_agent) {
        renderRawForensics(st.forensics_raw, st.forensic_agent);
      }
    }
  }

  // ─────────────────────────────────────────────────────────
  // SSE + polling fallback
  // ─────────────────────────────────────────────────────────

  function startStream() {
    if (state.es) state.es.close();
    if (!state.runId) return;

    const es = new EventSource(`${ENDPOINT}?action=stream&run_id=${encodeURIComponent(state.runId)}`);
    state.es = es;

    es.addEventListener('state', (e) => {
      try {
        const st = JSON.parse(e.data);
        if (st._hash && st._hash === state.lastHash) return;
        state.lastHash = st._hash;
        applyState(st);
      } catch (err) { logLine(`Malformed state in SSE: ${err.message}`, 'error'); }
    });

    es.addEventListener('fatal', (e) => {
      try {
        const d = JSON.parse(e.data);
        showBanner('error', `<strong>${esc(d.type || 'error')}</strong> — ${esc(d.message || '')}`);
      } catch {}
    });

    es.addEventListener('done', () => {
      es.close();
      state.es = null;
      stopPolling();
      finalizeUI();
    });

    es.addEventListener('error', () => {
      if (es.readyState === EventSource.CLOSED) return;
      logLine('Reconnecting stream…', 'warn');
    });
  }

  function stopPolling() {
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
  }

  function startPolling() {
    if (state.pollTimer || !state.runId) return;
    state.pollTimer = setInterval(async () => {
      try {
        const st = await fetch(
          `${ENDPOINT}?action=state&run_id=${encodeURIComponent(state.runId)}`,
          { credentials: 'same-origin' }
        ).then(r => r.json());
        if (!st || st.error) return;
        if (st._hash && st._hash === state.lastHash) return;
        state.lastHash = st._hash;
        applyState(st);
        if (st.completed) { stopPolling(); finalizeUI(); }
      } catch {}
    }, POLL_FALLBACK_MS);
  }

  function finalizeUI() {
    const b1 = $('#btn-new-run');
    if (b1) b1.classList.remove('hidden');
  }

  // ─────────────────────────────────────────────────────────
  // Handlers
  // ─────────────────────────────────────────────────────────

  /**
   * STEP 1: site URL + Gemini key (+ optional scanner keys) → detect plugin.
   */
  async function handleConnect(ev) {
    ev.preventDefault();
    hideBanner();
    const fd = new FormData(ev.target);

    const site_url = fd.get('site_url')?.toString().trim().replace(/\/$/, '');
    const gemini   = fd.get('gemini_key')?.toString().trim();
    const vt       = (fd.get('vt_api_key')?.toString()     || '').trim();
    const sucuri   = (fd.get('sucuri_api_key')?.toString() || '').trim();

    state.credentials.site_url       = site_url;
    state.credentials.gemini_key     = gemini;
    state.credentials.vt_api_key     = vt;
    state.credentials.sucuri_api_key = sucuri;

    const btn = ev.target.querySelector('button[type="submit"]');
    btn.disabled = true;

    try {
      const res = await post('detect', { site_url, gemini_key: gemini });

      if (res.status === 'installed') {
        showBanner('ok', `Plugin detected (v${esc(res.version || '?')}). Enter your credentials to get the key.`);
        showView('key');
      } else if (res.status === 'not_installed') {
        showView('install');
        hideBanner();
      } else {
        showBanner('error', esc(res.message || 'Unknown error while checking the site.'));
      }
    } catch (e) {
      showBanner('error', esc(e.message));
    } finally {
      btn.disabled = false;
    }
  }

  /**
   * STEP 2A: fetch WPDiag Key with admin credentials.
   */
  async function handleKey(ev) {
    ev.preventDefault();
    hideBanner();
    const fd = new FormData(ev.target);
    const wp_user = fd.get('wp_user')?.toString().trim();
    const wp_pass = fd.get('wp_password')?.toString();

    if (!wp_user || !wp_pass) {
      showBanner('error', 'Username and password are required.');
      return;
    }

    const btn = ev.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Fetching key…';

    try {
      const res = await post('get_key', {
        site_url:    state.credentials.site_url,
        gemini_key:  state.credentials.gemini_key,
        wp_user:     wp_user,
        wp_password: wp_pass,
      });

      const passField = ev.target.querySelector('#wp_password_key');
      if (passField) passField.value = '';

      if (res.status === 'ok' && res.wpdiag_key) {
        state.credentials.wpdiag_key = res.wpdiag_key;
        showBanner('ok', 'Key retrieved. Starting pipeline…');
        setTimeout(startRun, 400);
      } else {
        showBanner('error',
          `<strong>Could not retrieve the key.</strong><br>${esc(res.message || '')}` +
          (res.type === 'credentials' ? '<br>Check username and password.'
            : res.type === '2fa' ? '<br>Disable 2FA temporarily.'
            : '<br>Use the manual fallback to paste the key.')
        );
      }
    } catch (e) {
      showBanner('error', esc(e.message));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Get key and run';
    }
  }

  /**
   * Manual key fallback.
   */
  async function handleKeyManual(ev) {
    ev.preventDefault();
    hideBanner();
    const fd = new FormData(ev.target);
    const wpdiag_key = fd.get('wpdiag_key')?.toString().trim();
    if (!wpdiag_key) { showBanner('error', 'Enter the WPDiag Key.'); return; }
    state.credentials.wpdiag_key = wpdiag_key;
    const btn = ev.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    try {
      const res = await post('verify', {
        site_url:   state.credentials.site_url,
        gemini_key: state.credentials.gemini_key,
        wpdiag_key: wpdiag_key,
      });
      if (res.status === 'ok') startRun();
      else showBanner('error', esc(res.message || 'Invalid WPDiag Key.'));
    } catch (e) { showBanner('error', esc(e.message)); }
    finally { btn.disabled = false; }
  }

  /**
   * STEP 2B: install plugin via admin credentials.
   */
  async function handleInstall(ev) {
    ev.preventDefault();
    hideBanner();
    const fd = new FormData(ev.target);
    const btn = ev.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Installing…';

    try {
      const res = await post('install', {
        site_url:    state.credentials.site_url,
        gemini_key:  state.credentials.gemini_key,
        wp_user:     fd.get('wp_user')?.toString(),
        wp_password: fd.get('wp_password')?.toString(),
      });

      const passField = ev.target.querySelector('#wp_password');
      if (passField) passField.value = '';

      if (res.status === 'ok' && res.wpdiag_key) {
        state.credentials.wpdiag_key = res.wpdiag_key;
        showBanner('ok', 'Plugin installed and activated. Starting pipeline…');
        setTimeout(startRun, 700);
      } else {
        showBanner('error',
          `<strong>Automatic install failed.</strong><br>${esc(res.message || '')}`);
      }
    } catch (e) { showBanner('error', esc(e.message)); }
    finally { btn.disabled = false; btn.textContent = 'Install and continue'; }
  }

  /**
   * STEP 4: start pipeline.
   * Scanner keys travel only with this request.
   */
  async function startRun() {
    if (!state.credentials.site_url || !state.credentials.gemini_key || !state.credentials.wpdiag_key) {
      showBanner('error', 'Missing credentials in memory. Please start over.');
      showView('connect');
      return;
    }

    showView('pipeline');
    hideBanner();
    clearLog();
    buildAgentCards();
    applyState._lastLogLen = 0;
    setStatus('Starting pipeline…', 'running');
    logLine(`Site: ${state.credentials.site_url}`, 'info');

    try {
      const res = await post('run', {
        site_url:       state.credentials.site_url,
        gemini_key:     state.credentials.gemini_key,
        wpdiag_key:     state.credentials.wpdiag_key,
        vt_api_key:     state.credentials.vt_api_key,
        sucuri_api_key: state.credentials.sucuri_api_key,
      });

      if (res.status !== 'ok' || !res.run_id) {
        showBanner('error', esc(res.message || 'Could not start the pipeline.'));
        setStatus('Start error', 'error');
        return;
      }

      state.runId = res.run_id;
      startStream();
      startPolling();
    } catch (e) {
      showBanner('error', esc(e.message));
      setStatus('Start error', 'error');
    }
  }

  // ─────────────────────────────────────────────────────────
  // Bind
  // ─────────────────────────────────────────────────────────

  document.addEventListener('DOMContentLoaded', async () => {
    try {
      const ping = await fetch(`${ENDPOINT}?action=ping`).then(r => r.json());
      console.log('[wpdiag] Server:', ping);
    } catch (e) { console.warn('[wpdiag] Could not reach ?action=ping', e); }

    buildAgentCards();
    $('#form-connect')?.addEventListener('submit', handleConnect);
    $('#form-key')?.addEventListener('submit', handleKey);
    $('#form-key-manual')?.addEventListener('submit', handleKeyManual);
    $('#form-install')?.addEventListener('submit', handleInstall);

    $$('.btn-back-connect').forEach(b =>
      b.addEventListener('click', () => showView('connect'))
    );

    $('#btn-new-run')?.addEventListener('click', () => {
      if (state.es) state.es.close();
      stopPolling();
      state.runId = null;
      state.lastHash = null;
      state.fullState = null;
      applyState._lastLogLen = 0;
      showView('connect');
    });

    $('#btn-copy-reply')?.addEventListener('click', (e) => copyResponse(e.target));
    $('#btn-print')?.addEventListener('click', () => window.print());

    showView('connect');
  });
})();