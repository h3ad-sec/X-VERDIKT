
let currentVerdictFilter = 'all';
let currentTypeFilter    = 'all';
let currentSearch        = '';

const TYPE_BADGES = {
  ip:          '<span class="type-badge type-ip">IPv4</span>',
  ipv6:        '<span class="type-badge type-ipv6">IPv6</span>',
  domain:      '<span class="type-badge type-domain">Domain</span>',
  url:         '<span class="type-badge type-url">URL</span>',
  hash_md5:    '<span class="type-badge type-hash">MD5</span>',
  hash_sha1:   '<span class="type-badge type-hash">SHA-1</span>',
  hash_sha256: '<span class="type-badge type-hash">SHA-256</span>',
  hash_sha512: '<span class="type-badge type-hash">SHA-512</span>',
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function escapeAttr(s) { return escapeHtml(s); }
function truncate(s, n) { s = String(s||''); return s.length > n ? s.slice(0,n)+'…' : s; }

function showToast(msg, type = 'info') {
  let t = document.getElementById('xv-toast');
  if (!t) {
    t = document.createElement('div'); t.id = 'xv-toast';
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;padding:11px 18px;font-family:var(--mono);font-size:13px;border:1px solid;border-radius:4px;pointer-events:none;transition:opacity .3s;max-width:340px;';
    document.body.appendChild(t);
  }
  const styles = {
    success: 'background:rgba(0,255,159,.08);border-color:rgba(0,255,159,.4);color:var(--accent)',
    error:   'background:rgba(255,59,92,.08);border-color:rgba(255,59,92,.4);color:var(--red)',
    warning: 'background:rgba(255,214,10,.08);border-color:rgba(255,214,10,.4);color:var(--yellow)',
    info:    'background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.4);color:var(--accent2)',
  };
  t.style.cssText += styles[type] || styles.info;
  t.textContent = msg; t.style.opacity = '1';
  clearTimeout(t._tid);
  t._tid = setTimeout(() => { t.style.opacity = '0'; }, 3200);
}

function copyToClipboard(val) {
  navigator.clipboard.writeText(val).then(() => showToast('Copied!', 'success'));
}

/* ── Result table ────────────────────────────────────────────────────────── */
function renderResultRows(results) {
  document.getElementById('results-body').innerHTML = results.map((e, i) => buildRow(e, i)).join('');
  applyFilters();
}

function buildRow(entry, i) {
  const { ioc, verdict, action, score, vtPts, abPts, mbPts, otxPts, confidence, flags, done } = entry;
  const privateBadge = ioc.isPrivate ? '<div class="ioc-private-badge">PRIVATE</div>' : '';
  const typeBadge    = TYPE_BADGES[ioc.type] || `<span class="type-badge">${escapeHtml(ioc.label)}</span>`;
  const displayVal = ioc.type === 'url' || ioc.type.startsWith('hash_')
    ? truncate(ioc.value, 48) : ioc.value;
  const isHash = ioc.type.startsWith('hash_');

  return `<tr data-row="${i}" data-verdict="${verdict||'pending'}" data-action="${action||''}" data-type="${escapeAttr(ioc.type)}" data-ioc="${escapeAttr(ioc.value)}">
    <td class="td-ioc">
      <div class="ioc-val-wrap">
        <span class="ioc-val" title="${escapeAttr(ioc.value)}">${escapeHtml(displayVal)}</span>
        <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy">⎘</button>
      </div>
      ${privateBadge}
    </td>
    <td>${typeBadge}</td>
    <td id="v-${i}">${buildVerdictCell(verdict, score, confidence, done)}</td>
    <td id="vt-${i}">${buildSourceScoreCell('vt', vtPts, entry.vt, done)}</td>
    <td id="ab-${i}">${isHash ? buildSourceScoreCell('mb', mbPts, entry.mb, done) : buildSourceScoreCell('ab', abPts, entry.ab, done)}</td>
    <td id="otx-${i}">${buildSourceScoreCell('otx', otxPts, entry.otx, done)}</td>
    <td id="ha-${i}">${buildHAScoreCell(entry.ha, done)}</td>
    <td id="tf-${i}">${buildTFScoreCell(entry.threatfox, done)}</td>
    <td id="fl-${i}">${buildFlagsCell(flags, done)}</td>
    <td>${done ? `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>` : '<span class="src-loading">…</span>'}</td>
  </tr>`;
}

function buildVerdictCell(verdict, score, confidence, done) {
  if (!done) return `<div class="verdict-pending-cell"><div class="vc-spinner"></div><span>Scanning…</span></div>`;
  const vMap = {
    malicious:  { icon: '🔴', label: 'MALICIOUS',  cls: 'verdict-malicious' },
    suspicious: { icon: '🟡', label: 'SUSPICIOUS', cls: 'verdict-suspicious' },
    benign:     { icon: '🟢', label: 'BENIGN',     cls: 'verdict-benign' },
    unknown:    { icon: '⚪', label: 'UNKNOWN',    cls: 'verdict-unknown' },
  };
  const v = vMap[verdict] || vMap.unknown;
  const confColor = { high: 'var(--accent)', medium: 'var(--yellow)', low: 'var(--muted)', informational: 'var(--accent2)' }[confidence] || 'var(--muted)';
  return `<div class="verdict-cell">
    <span class="verdict-badge ${v.cls}">${v.icon} ${v.label}</span>
    <div class="vc-meta">
      <span class="vc-score">${score != null ? score : '—'}<span class="vc-score-unit">/100</span></span>
      <span class="vc-conf" style="color:${confColor}">${(confidence||'—').toUpperCase()}</span>
    </div>
  </div>`;
}

function buildSourceScoreCell(src, pts, data, done) {
  if (!done) return '<span class="src-loading">…</span>';
  const colors = { vt: 'var(--vt)', ab: 'var(--ab)', otx: 'var(--otx)', mb: 'var(--mb)' };
  const maxPts = { vt: 40, ab: 40, otx: 20, mb: 40 };
  const col = colors[src];
  if (!data || data.skipped || data.error) {
    const reason = data?.error || data?.reason || 'N/A';
    return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px">${escapeHtml(truncate(reason,22))}</span></div>`;
  }
  const pct = pts != null ? Math.round((pts / maxPts[src]) * 100) : 0;
  let label = '';
  if (src === 'vt')  label = data.total > 0 ? `${data.malicious}/${data.total}` : 'N/A';
  if (src === 'ab')  label = `${data.score || 0}%`;
  if (src === 'otx') label = `${data.pulseCount || 0} pulses`;
  if (src === 'mb')  label = data.notFound ? 'Not found' : `${data.count || 0} sample${(data.count||0) !== 1 ? 's' : ''}`;
  return `<div class="src-score-cell">
    <div class="src-pts" style="color:${col}">${pts != null ? pts : '—'}<span class="src-pts-max">/${maxPts[src]}</span></div>
    <div class="src-bar"><div class="src-bar-fill" style="width:${pct}%;background:${col}"></div></div>
    <div class="src-label">${escapeHtml(label)}</div>
  </div>`;
}

function buildHAScoreCell(ha, done) {
  if (!done) return '<span class="src-loading">…</span>';
  if (!ha || ha.skipped) return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px">${escapeHtml(truncate(ha?.reason||'N/A',18))}</span></div>`;
  if (ha.error) return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px">${escapeHtml(truncate(ha.error,18))}</span></div>`;
  if (ha.notFound || !ha.count) return `<div class="src-score-cell"><span style="color:var(--accent);font-size:11px">No hits</span></div>`;
  const col = ha.maliciousCount > 0 ? 'var(--red)' : 'var(--yellow)';
  return `<div class="src-score-cell">
    <div class="src-pts" style="color:${col}">${ha.count}</div>
    <div class="src-label">${ha.maliciousCount > 0 ? `${ha.maliciousCount} mal` : 'hits'}</div>
  </div>`;
}

function buildTFScoreCell(tf, done) {
  if (!done) return '<span class="src-loading">…</span>';
  if (!tf || tf.skipped) return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px">${escapeHtml(truncate(tf?.reason||'N/A',18))}</span></div>`;
  if (tf.error) return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px">${escapeHtml(truncate(tf.error,18))}</span></div>`;
  if (tf.notFound) return `<div class="src-score-cell"><span style="color:var(--accent);font-size:11px">No C2</span></div>`;
  return `<div class="src-score-cell">
    <div class="src-pts" style="color:var(--tf)">${tf.iocCount}</div>
    <div class="src-label">C2${tf.maxConfidence ? ` ${tf.maxConfidence}%` : ''}</div>
  </div>`;
}

function buildFlagsCell(flags, done) {
  if (!done) return '<span class="src-loading">…</span>';
  if (!flags?.length) return '<span style="color:var(--muted);font-size:11px">—</span>';
  const flagColors = {
    'TF:C2': 'var(--tf)', 'UH:URLS': 'var(--uh)', 'HA:SANDBOX': 'var(--ha)',
    'MB:HIT': 'var(--mb)', 'SH:CVE': 'var(--sh)', 'SH:TAG': 'var(--sh)',
  };
  return flags.map(f => {
    const col = flagColors[f] || (f.startsWith('US:') ? 'var(--us)' : 'var(--muted)');
    return `<span class="flag-chip" style="border-color:${col};color:${col}">${escapeHtml(f)}</span>`;
  }).join('');
}

function updateRow(i, entry) {
  const { verdict, score, vtPts, abPts, mbPts, otxPts, confidence, flags, vt, ab, mb, otx, ha, threatfox } = entry;
  const isHash = entry.ioc.type.startsWith('hash_');
  const vEl  = document.getElementById(`v-${i}`);
  const vtEl = document.getElementById(`vt-${i}`);
  const abEl = document.getElementById(`ab-${i}`);
  const otxEl= document.getElementById(`otx-${i}`);
  const haEl = document.getElementById(`ha-${i}`);
  const tfEl = document.getElementById(`tf-${i}`);
  const flEl = document.getElementById(`fl-${i}`);
  const row  = document.querySelector(`tr[data-row="${i}"]`);
  if (vEl)   vEl.innerHTML  = buildVerdictCell(verdict, score, confidence, true);
  if (vtEl)  vtEl.innerHTML = buildSourceScoreCell('vt', vtPts, vt, true);
  if (abEl)  abEl.innerHTML = isHash ? buildSourceScoreCell('mb', mbPts, mb, true) : buildSourceScoreCell('ab', abPts, ab, true);
  if (otxEl) otxEl.innerHTML= buildSourceScoreCell('otx', otxPts, otx, true);
  if (haEl)  haEl.innerHTML = buildHAScoreCell(ha, true);
  if (tfEl)  tfEl.innerHTML = buildTFScoreCell(threatfox, true);
  if (flEl)  flEl.innerHTML = buildFlagsCell(flags, true);
  if (row) {
    row.dataset.verdict = verdict || 'unknown';
    row.dataset.action  = entry.action || '';
    const lastTd = row.querySelector('td:last-child');
    if (lastTd) lastTd.innerHTML = `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>`;
  }
  applyFilters();
}

function updateRowLoading(i) {
  const row = document.querySelector(`tr[data-row="${i}"]`);
  if (row) row.querySelectorAll('[id^="v-"],[id^="vt-"],[id^="ab-"],[id^="otx-"],[id^="ha-"],[id^="tf-"],[id^="fl-"]').forEach(el => { el.innerHTML = '<div class="verdict-pending-cell"><div class="vc-spinner"></div></div>'; });
}

/* ── Summary strip ────────────────────────────────────────────────────────── */
function renderSummary(results) {
  const done = results.filter(r => r.done);
  const counts = { malicious: 0, suspicious: 0, benign: 0, unknown: 0 };
  let scoreSum = 0;
  for (const r of done) {
    if (r.verdict) counts[r.verdict] = (counts[r.verdict] || 0) + 1;
    scoreSum += r.score || 0;
  }
  const avgScore = done.length ? Math.round(scoreSum / done.length) : 0;
  document.getElementById('summary-strip').innerHTML = `
    <div class="summary-card sc-total"><span class="sc-icon">📋</span><div><div class="summary-num">${results.length}</div><div class="summary-lbl">TOTAL IOCs</div></div></div>
    <div class="summary-card sc-malicious"><span class="sc-icon">🔴</span><div><div class="summary-num">${counts.malicious}</div><div class="summary-lbl">MALICIOUS</div></div></div>
    <div class="summary-card sc-suspicious"><span class="sc-icon">🟡</span><div><div class="summary-num">${counts.suspicious}</div><div class="summary-lbl">SUSPICIOUS</div></div></div>
    <div class="summary-card sc-benign"><span class="sc-icon">🟢</span><div><div class="summary-num">${counts.benign}</div><div class="summary-lbl">BENIGN</div></div></div>
    <div class="summary-card"><span class="sc-icon">⚪</span><div><div class="summary-num">${counts.unknown}</div><div class="summary-lbl">UNKNOWN</div></div></div>
    <div class="summary-card"><div><div class="summary-num" style="color:var(--accent2)">${avgScore}</div><div class="summary-lbl">AVG SCORE</div></div></div>
  `;
}

/* ── Filters ─────────────────────────────────────────────────────────────── */
function filterResults(f, btn) {
  currentVerdictFilter = f;
  document.querySelectorAll('.result-filter[data-filter]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}

function filterByType(t, btn) {
  currentTypeFilter = t;
  document.querySelectorAll('.type-filter[data-tfilter]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}

function searchResults(val) { currentSearch = val.toLowerCase().trim(); applyFilters(); }

function applyFilters() {
  document.querySelectorAll('#results-body tr').forEach(row => {
    const v  = row.dataset.verdict || '';
    const tp = row.dataset.type || '';
    const ioc = (row.dataset.ioc || '').toLowerCase();
    const matchV = currentVerdictFilter === 'all' || v === currentVerdictFilter;
    const matchT = currentTypeFilter === 'all' || tp === currentTypeFilter
                   || (currentTypeFilter === 'hash' && tp.startsWith('hash_'));
    const matchS = !currentSearch || ioc.includes(currentSearch);
    row.classList.toggle('hidden', !(matchV && matchT && matchS));
  });
}

/* ── Status dots ─────────────────────────────────────────────────────────── */
function setServerStatusDots(status) {
  const map = {
    'vt-status': status.vt, 'ab-status': status.abuseipdb, 'otx-status': status.otx,
    'us-status': status.urlscan, 'tf-status': true, 'uh-status': true,
    'mb-status': status.abusech, 'ha-status': status.hybridanalysis,
    'sh-status': status.shodan,
  };
  for (const [id, active] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (!el) continue;
    const dot = el.querySelector('.hstatus-dot');
    if (dot) { dot.className = active ? 'hstatus-dot on' : 'hstatus-dot off'; }
  }
}

/* ── Modal ────────────────────────────────────────────────────────────────── */
function openModal(i) {
  const entry = scanResults[i];
  if (!entry) return;
  document.getElementById('modal-title').innerHTML = buildModalTitle(entry);
  document.getElementById('modal-body').innerHTML  = buildModalContent(entry);
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() { document.getElementById('modal-overlay')?.classList.remove('open'); }

function buildModalTitle(entry) {
  const vMap = { malicious: 'var(--red)', suspicious: 'var(--yellow)', benign: 'var(--accent)', unknown: 'var(--muted)' };
  const col = vMap[entry.verdict] || 'var(--muted)';
  const displayVal = entry.ioc.type === 'url' || entry.ioc.type.startsWith('hash_')
    ? truncate(entry.ioc.value, 60) : entry.ioc.value;
  return `<span style="color:${col}" title="${escapeAttr(entry.ioc.value)}">${escapeHtml(displayVal)}</span>
    <span style="color:var(--muted);font-size:11px;margin-left:12px">${escapeHtml(entry.ioc.label)}</span>`;
}

function buildModalContent(entry) {
  const { ioc, vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha, shodan, score, vtPts, abPts, mbPts, otxPts, verdict, confidence, action, reasons } = entry;
  const iocType = ioc.type;
  const iocIsIP   = iocType === 'ip' || iocType === 'ipv6';
  const iocIsHash = iocType.startsWith('hash_');
  const vMap = { malicious: ['var(--red)','🔴 MALICIOUS'], suspicious: ['var(--yellow)','🟡 SUSPICIOUS'], benign: ['var(--accent)','🟢 BENIGN'], unknown: ['var(--muted)','⚪ UNKNOWN'] };
  const aMap = { block: ['var(--red)','🚫 BLOCK'], investigate: ['var(--yellow)','🔍 INVESTIGATE'], allow: ['var(--accent)','✅ ALLOW'], monitor: ['var(--muted)','⏳ MONITOR'] };
  const [vcol, vlabel] = vMap[verdict] || vMap.unknown;
  const [acol, alabel] = aMap[action] || aMap.monitor;
  const confColors = { high: 'var(--accent)', medium: 'var(--yellow)', low: 'var(--muted)', informational: 'var(--accent2)' };
  const ccol = confColors[confidence] || 'var(--muted)';
  const barPct = score || 0;
  const barColor = barPct >= 60 ? 'var(--red)' : barPct >= 30 ? 'var(--yellow)' : 'var(--accent)';

  const parts = [];

  /* Score card */
  parts.push(`<div class="modal-score-card">
    <div class="msc-left">
      <span class="verdict-badge" style="color:${vcol};border-color:${vcol}40;background:${vcol}10">${vlabel}</span>
      <span class="action-badge" style="color:${acol};border-color:${acol}40;background:${acol}10">${alabel}</span>
    </div>
    <div class="msc-center">
      <div class="mvc-score-num" style="color:${barColor}">${score != null ? score : '—'}</div>
      <div class="mvc-score-bar"><div class="mvc-score-fill" style="width:${barPct}%;background:${barColor}"></div></div>
      <div class="mvc-score-label">RISK SCORE / 100</div>
    </div>
    <div class="msc-right">
      <div class="mvc-conf-val" style="color:${ccol}">${(confidence||'—').toUpperCase()}</div>
      <div class="mvc-conf-label">CONFIDENCE</div>
      <div style="margin-top:10px;display:flex;flex-direction:column;gap:3px">
        ${reasons.map(r => `<div style="font-size:11px;color:var(--muted);font-family:var(--mono)">${escapeHtml(r)}</div>`).join('')}
      </div>
    </div>
  </div>`);

  /* Score breakdown */
  const maxNote = iocIsIP ? 'VT(40) + AbuseIPDB(40) + OTX(20)'
    : iocIsHash ? 'VT(40) + MalwareBazaar(40) + OTX(20)'
    : 'VT(40) + OTX(20) → normalized ×100/60';
  const secondRow = iocIsHash
    ? buildSBDRow('MALWAREBAZAAR', mbPts, 40, 'var(--mb)', mb ? (mb.error ? 'Error: '+mb.error : mb.skipped ? mb.reason||'Skipped' : mb.notFound ? 'Not found' : `${mb.count} samples`) : '—')
    : buildSBDRow('ABUSEIPDB', abPts, 40, 'var(--ab)', ab ? (ab.error ? 'Error: '+ab.error : ab.skipped ? ab.reason||'Skipped' : `${ab.score||0}% confidence`) : '—');
  parts.push(`<div class="sbd-section">
    <div class="sbd-label">SCORE BREAKDOWN</div>
    <table class="sbd-table">
      <thead><tr><th>SOURCE</th><th>PTS</th><th>MAX</th><th style="min-width:100px">CONTRIBUTION</th><th>SIGNAL</th></tr></thead>
      <tbody>
        ${buildSBDRow('VIRUSTOTAL', vtPts, 40, 'var(--vt)', vt ? (vt.error ? 'Error: '+vt.error : vt.skipped ? 'Skipped' : `${vt.malicious||0}/${vt.total||0} engines`) : '—')}
        ${secondRow}
        ${buildSBDRow('OTX', otxPts, 20, 'var(--otx)', otx ? (otx.error ? 'Error: '+otx.error : otx.skipped ? 'Skipped' : `${otx.pulseCount||0} pulses`) : '—')}
      </tbody>
      <tfoot><tr class="sbd-total"><td>TOTAL</td><td><strong style="color:var(--accent)">${score}</strong></td><td>100</td><td colspan="2" style="color:var(--muted);font-size:11px">${maxNote}</td></tr></tfoot>
    </table>
  </div>`);

  /* Mandatory 3-column intel — hash uses MB instead of AbuseIPDB */
  parts.push(`<div class="modal-intel-grid">
    ${buildVTBlock(vt, iocType)}
    ${iocIsHash ? buildMBIntelBlock(mb) : buildAbuseIPDBBlock(ab, iocType)}
    ${buildOTXBlock(otx)}
  </div>`);

  /* Supplementary intel */
  parts.push(`<div class="modal-supp-label">SUPPLEMENTARY INTELLIGENCE</div>`);
  parts.push(`<div class="modal-supp-grid">
    ${buildSuppCard('SHODAN', 'var(--sh)', buildShodanContent(shodan))}
    ${buildSuppCard('URLSCAN', 'var(--us)', buildURLScanContent(urlscan))}
    ${buildSuppCard('THREATFOX', 'var(--tf)', buildThreatFoxContent(threatfox))}
    ${buildSuppCard('URLHAUS', 'var(--uh)', buildURLhausContent(urlhaus))}
    ${buildSuppCard('HYBRIDANALYSIS', 'var(--ha)', buildHAContent(ha))}
    ${buildSuppCard('MALWAREBAZAAR', 'var(--mb)', buildMBContent(mb))}
  </div>`);

  return parts.join('');
}

function buildSBDRow(name, pts, max, col, note) {
  const pct = pts != null && max > 0 ? Math.round((pts / max) * 100) : 0;
  const cls = pts == null ? 'sbd-na' : '';
  return `<tr class="sbd-row ${cls}">
    <td class="sbd-src" style="color:${col}">${name}</td>
    <td class="sbd-pts">${pts != null ? pts : '—'}</td>
    <td class="sbd-cap" style="color:var(--muted)">${max}</td>
    <td class="sbd-bar-cell"><div class="sbd-bar"><div class="sbd-bar-fill" style="width:${pct}%;background:${col}"></div></div></td>
    <td class="sbd-note">${escapeHtml(note)}</td>
  </tr>`;
}

function kv(k, v, col) {
  if (v == null || v === '' || v === 'null') return '';
  const val = typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v);
  const colorClass = col ? ` style="color:${col}"` : '';
  return `<div class="modal-k">${escapeHtml(k)}</div><div class="modal-v"${colorClass}>${escapeHtml(val)}</div>`;
}

function buildVTBlock(vt, iocType) {
  if (!vt || vt.skipped || vt.error) {
    const msg = vt?.error || vt?.reason || 'Not available';
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL</div><div class="intel-na">${escapeHtml(msg)}</div></div>`;
  }
  const scoreColor = vt.malicious > 0 ? 'var(--red)' : vt.suspicious > 0 ? 'var(--yellow)' : 'var(--accent)';
  const lastStats = `${vt.malicious} mal · ${vt.suspicious} sus · ${vt.harmless} harm · ${vt.undetected} undet · ${vt.total} total`;
  const linkHtml = vt.link ? ` <a href="${escapeAttr(vt.link)}" target="_blank" class="modal-link">↗</a>` : '';

  /* IP / IPv6 */
  if (iocType === 'ip' || iocType === 'ipv6') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('IP', vt.ip)}
        ${kv('ASN', vt.asn != null ? `AS${vt.asn}` : null)}
        ${kv('AS Owner', vt.as_owner)}
        ${kv('Country', vt.country)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : vt.reputation > 0 ? 'var(--accent)' : null)}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Network', vt.network)}
        ${kv('JARM', vt.jarm ? truncate(vt.jarm, 32) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
        ${kv('Self-signed', vt.cert_self_signed)}
        ${kv('Valid Until', vt.cert_valid_until)}
        ${kv('SHA-256', vt.cert_thumbprint ? truncate(vt.cert_thumbprint, 40) : null)}
      </div>` : ''}
    </div>`;
  }

  /* Domain */
  if (iocType === 'domain') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Domain', vt.domain)}
        ${kv('Registrar', vt.registrar)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
        ${kv('Valid Until', vt.cert_valid_until)}
      </div>` : ''}
    </div>`;
  }

  /* URL */
  if (iocType === 'url') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Title', vt.title ? truncate(vt.title, 48) : null)}
        ${kv('Final URL', vt.finalUrl ? truncate(vt.finalUrl, 48) : null)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  /* Hash */
  if (iocType.startsWith('hash_')) {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('File Name', vt.name)}
        ${kv('File Type', vt.fileType)}
        ${kv('Size', vt.size)}
        ${kv('Signature', vt.signatureInfo)}
        ${kv('First Seen', vt.firstSeen)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('MD5', vt.md5 ? truncate(vt.md5, 40) : null)}
        ${kv('SHA-1', vt.sha1 ? truncate(vt.sha1, 40) : null)}
        ${kv('SHA-256', vt.sha256 ? truncate(vt.sha256, 44) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  /* Fallback */
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
    <div class="modal-kv-grid">${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}</div>
  </div>`;
}

function buildAbuseIPDBBlock(ab, iocType) {
  if (!ab || ab.error) {
    const msg = ab?.error || 'Not available';
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB</div><div class="intel-na">${escapeHtml(msg)}</div></div>`;
  }
  if (ab.skipped) {
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB</div><div class="intel-na" style="color:var(--muted)">${escapeHtml(ab.reason || 'IP only')}</div></div>`;
  }
  const scoreCol = ab.score >= 75 ? 'var(--red)' : ab.score >= 25 ? 'var(--yellow)' : 'var(--accent)';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB ${ab.link ? `<a href="${escapeAttr(ab.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('IP Address', ab.ipAddress)}
      ${kv('IP Version', ab.ipVersion != null ? `IPv${ab.ipVersion}` : null)}
      ${kv('Is Public', ab.isPublic)}
      ${kv('Whitelisted', ab.isWhitelisted)}
      ${kv('Abuse Score', `${ab.score}%`, scoreCol)}
      ${kv('Usage Type', ab.usageType)}
      ${kv('ISP', ab.isp)}
      ${kv('Domain', ab.domain)}
      ${kv('Is Tor', ab.isTor)}
      ${kv('Total Reports', ab.totalReports != null ? String(ab.totalReports) : null)}
      ${kv('Last Reported', ab.lastReportedAt?.split('T')[0])}
    </div>
    ${ab.hostnames?.length ? `<div class="intel-sub-label">HOSTNAMES</div><div class="modal-tags">${ab.hostnames.slice(0,6).map(h => `<span class="modal-tag">${escapeHtml(h)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function buildOTXBlock(otx) {
  if (!otx || otx.skipped || otx.error) {
    const msg = otx?.error || otx?.reason || 'Not available';
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--otx)">ALIENVAULT OTX</div><div class="intel-na">${escapeHtml(msg)}</div></div>`;
  }
  const pulseCol = otx.pulseCount >= 5 ? 'var(--red)' : otx.pulseCount >= 1 ? 'var(--yellow)' : 'var(--accent)';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--otx)">ALIENVAULT OTX ${otx.link ? `<a href="${escapeAttr(otx.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('Pulse Count', String(otx.pulseCount), pulseCol)}
      ${kv('Subscriber Count', otx.subscriberCount > 0 ? String(otx.subscriberCount) : null)}
      ${kv('Indicator Count', otx.indicatorCount > 0 ? String(otx.indicatorCount) : null)}
      ${kv('Validation', otx.validation)}
      ${kv('Recent Pulse', otx.recentPulse ? truncate(otx.recentPulse, 44) : null)}
    </div>
    ${otx.pulseSources?.length ? `<div class="intel-sub-label">PULSE SOURCES</div><div class="modal-tags">${otx.pulseSources.map(s => `<span class="modal-tag">${escapeHtml(s)}</span>`).join('')}</div>` : ''}
    ${otx.malwareFamilies?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${otx.malwareFamilies.map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
    ${otx.adversaries?.length ? `<div class="intel-sub-label">ADVERSARIES</div><div class="modal-tags">${otx.adversaries.map(a => `<span class="modal-tag" style="color:var(--yellow)">${escapeHtml(a)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function buildMBIntelBlock(mb) {
  if (!mb || mb.error)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na">${escapeHtml(mb?.error || 'Not available')}</div></div>`;
  if (mb.skipped)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na" style="color:var(--muted)">${escapeHtml(mb.reason || 'Skipped')}</div></div>`;
  if (mb.notFound || !mb.count)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na" style="color:var(--accent)">Not found in malware database</div></div>`;
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div>
    <div class="modal-kv-grid">
      ${kv('Samples', String(mb.count), 'var(--red)')}
      ${kv('File Name', mb.fileName)}
      ${kv('File Type', mb.fileType)}
      ${kv('First Seen', mb.firstSeen)}
    </div>
    ${mb.families?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${mb.families.slice(0,5).map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function buildSuppCard(title, col, content) {
  return `<div class="supp-card">
    <div class="supp-card-title" style="color:${col}">${title}</div>
    ${content}
  </div>`;
}

function buildShodanContent(sh) {
  if (!sh || sh.skipped) return `<div class="intel-na">${escapeHtml(sh?.reason || 'Skipped')}</div>`;
  if (sh.error) return `<div class="intel-na">Error: ${escapeHtml(sh.error)}</div>`;
  if (sh.raw === null) return `<div class="intel-na" style="color:var(--accent)">Not indexed</div>`;
  const lines = [];
  if (sh.ports?.length) lines.push(`<div class="supp-kv"><span>Ports</span><span>${sh.ports.slice(0,8).join(', ')}</span></div>`);
  if (sh.cves?.length)  lines.push(`<div class="supp-kv"><span>CVEs</span><span style="color:var(--yellow)">${sh.cves.slice(0,4).join(', ')}${sh.cves.length > 4 ? ` +${sh.cves.length-4}` : ''}</span></div>`);
  if (sh.tags?.length)  lines.push(`<div class="supp-kv"><span>Tags</span><span>${sh.tags.join(', ')}</span></div>`);
  if (sh.hostnames?.length) lines.push(`<div class="supp-kv"><span>Hostnames</span><span>${sh.hostnames.slice(0,3).join(', ')}</span></div>`);
  if (sh.isp)   lines.push(`<div class="supp-kv"><span>ISP</span><span>${escapeHtml(sh.isp)}</span></div>`);
  if (sh.org)   lines.push(`<div class="supp-kv"><span>Org</span><span>${escapeHtml(sh.org)}</span></div>`);
  return lines.length ? lines.join('') : `<div class="intel-na" style="color:var(--accent)">No data</div>`;
}

function buildURLScanContent(us) {
  if (!us || us.skipped) return `<div class="intel-na">${escapeHtml(us?.reason || 'Skipped')}</div>`;
  if (us.error) return `<div class="intel-na">Error: ${escapeHtml(us.error)}</div>`;
  if (us.notFound || !us.total) return `<div class="intel-na" style="color:var(--accent)">No scans found</div>`;
  const lines = [`<div class="supp-kv"><span>Total Scans</span><span>${us.total}</span></div>`];
  if (us.maliciousCount) lines.push(`<div class="supp-kv"><span>Malicious</span><span style="color:var(--red)">${us.maliciousCount}</span></div>`);
  if (us.recent?.length) {
    lines.push(`<div style="margin-top:6px;font-size:11px;color:var(--muted);font-family:var(--mono)">RECENT SCANS</div>`);
    us.recent.slice(0, 3).forEach(r => lines.push(`<div class="supp-url-item ${r.malicious ? 'supp-url-mal' : ''}">${escapeHtml(truncate(r.domain || r.url, 36))} <span>${r.date}</span></div>`));
  }
  return lines.join('');
}

function buildThreatFoxContent(tf) {
  if (!tf || tf.skipped) return `<div class="intel-na">${escapeHtml(tf?.reason || 'Skipped')}</div>`;
  if (tf.error) return `<div class="intel-na">Error: ${escapeHtml(tf.error)}</div>`;
  if (tf.notFound) return `<div class="intel-na" style="color:var(--accent)">No IOCs found</div>`;
  const lines = [`<div class="supp-kv"><span>IOC Count</span><span style="color:var(--red)">${tf.iocCount}</span></div>`];
  if (tf.maxConfidence) lines.push(`<div class="supp-kv"><span>Confidence</span><span>${tf.maxConfidence}%</span></div>`);
  if (tf.firstSeen) lines.push(`<div class="supp-kv"><span>First Seen</span><span>${tf.firstSeen}</span></div>`);
  if (tf.lastSeen)  lines.push(`<div class="supp-kv"><span>Last Seen</span><span>${tf.lastSeen}</span></div>`);
  if (tf.threatTypes?.length)     lines.push(`<div class="supp-kv"><span>Threat Type</span><span>${tf.threatTypes.join(', ')}</span></div>`);
  if (tf.malwareFamilies?.length) lines.push(`<div class="supp-kv"><span>Malware</span><span style="color:var(--red)">${tf.malwareFamilies.slice(0,3).join(', ')}</span></div>`);
  return lines.join('');
}

function buildURLhausContent(uh) {
  if (!uh || uh.skipped) return `<div class="intel-na">${escapeHtml(uh?.reason || 'Skipped')}</div>`;
  if (uh.error) return `<div class="intel-na">Error: ${escapeHtml(uh.error)}</div>`;
  if (uh.notFound) return `<div class="intel-na" style="color:var(--accent)">No URLs found</div>`;
  const lines = [`<div class="supp-kv"><span>URLs Listed</span><span style="color:var(--red)">${uh.urlsCount}</span></div>`];
  if (uh.onlineCount) lines.push(`<div class="supp-kv"><span>Online</span><span style="color:var(--red)">${uh.onlineCount}</span></div>`);
  if (uh.threats?.length) lines.push(`<div class="supp-kv"><span>Threat</span><span>${uh.threats.join(', ')}</span></div>`);
  if (uh.tags?.length)    lines.push(`<div class="supp-kv"><span>Tags</span><span>${uh.tags.join(', ')}</span></div>`);
  if (uh.dateAdded) lines.push(`<div class="supp-kv"><span>First Seen</span><span>${uh.dateAdded}</span></div>`);
  return lines.join('');
}

function buildHAContent(ha) {
  if (!ha || ha.skipped) return `<div class="intel-na">${escapeHtml(ha?.reason || 'Skipped')}</div>`;
  if (ha.error) return `<div class="intel-na">Error: ${escapeHtml(ha.error)}</div>`;
  if (ha.notFound || !ha.count) return `<div class="intel-na" style="color:var(--accent)">No sandbox matches</div>`;
  const lines = [`<div class="supp-kv"><span>Sandbox Hits</span><span>${ha.count}</span></div>`];
  if (ha.maliciousCount) lines.push(`<div class="supp-kv"><span>Malicious</span><span style="color:var(--red)">${ha.maliciousCount}</span></div>`);
  if (ha.maxScore) lines.push(`<div class="supp-kv"><span>Threat Score</span><span>${ha.maxScore}/100</span></div>`);
  if (ha.families?.length) lines.push(`<div class="supp-kv"><span>Malware</span><span style="color:var(--red)">${ha.families.slice(0,3).join(', ')}</span></div>`);
  return lines.join('');
}

function buildMBContent(mb) {
  if (!mb || mb.skipped) return `<div class="intel-na">${escapeHtml(mb?.reason || 'Skipped')}</div>`;
  if (mb.error) return `<div class="intel-na">Error: ${escapeHtml(mb.error)}</div>`;
  if (mb.notFound || !mb.count) return `<div class="intel-na" style="color:var(--accent)">Not found</div>`;
  const lines = [
    mb.fileName ? `<div class="supp-kv"><span>File Name</span><span>${escapeHtml(mb.fileName)}</span></div>` : '',
    `<div class="supp-kv"><span>Samples</span><span style="color:var(--red)">${mb.count}</span></div>`,
  ];
  if (mb.fileType) lines.push(`<div class="supp-kv"><span>File Type</span><span>${escapeHtml(mb.fileType)}</span></div>`);
  if (mb.families?.length) lines.push(`<div class="supp-kv"><span>Families</span><span style="color:var(--red)">${mb.families.join(', ')}</span></div>`);
  if (mb.firstSeen) lines.push(`<div class="supp-kv"><span>First Seen</span><span>${mb.firstSeen}</span></div>`);
  return lines.filter(Boolean).join('');
}

/* ── Results meta ────────────────────────────────────────────────────────── */
function updateResultsMeta(results) {
  const done = results.filter(r => r.done).length;
  const el = document.getElementById('results-meta');
  if (el) el.innerHTML = `<span>${done}</span> / ${results.length} analyzed`;
}

/* ── Key save/load (no-ops — panel removed, kept for null safety) ─────────── */
function saveKeys() {}
function clearKeys() {}
function loadSavedKeys() {}
function updateStatusDots() {}

function toggleKey(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.type = el.type === 'password' ? 'text' : 'password';
  const btn = el.nextElementSibling;
  if (btn) btn.textContent = el.type === 'password' ? 'SHOW' : 'HIDE';
}

function togglePanel(id) {
  const body = document.getElementById(id + '-body');
  const chev = document.getElementById(id + '-chevron');
  if (!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  if (chev) chev.classList.toggle('closed', open);
}

function switchInputTab(tab, btn) {
  document.querySelectorAll('.input-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const pane = document.getElementById(`tab-${tab}`);
  if (pane) pane.classList.add('active');
}

function scanSingleIOC() {
  const input = document.getElementById('single-ip-input');
  const val = input?.value.trim();
  if (!val) return;
  document.getElementById('ip-input').value = val;
  parseIOCsRealtime();
  startScan();
  input.value = '';
}

/* alias kept for any stale references */
function scanSingleIP() { scanSingleIOC(); }

function updateVTPaidUI() {}
