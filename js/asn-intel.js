/* ── ASN / CIDR Intel Module ─────────────────────────────────────────────── */

let asnIntelResults  = [];
let cidrIntelResults = [];
let asnIntelMode     = 'profile'; // 'profile' | 'iplist'

/* ── Parser ──────────────────────────────────────────────────────────────── */
function parseASNsAndCIDRs(raw) {
  const lines = raw.split(/[\r\n,;\s]+/).map(l => l.trim()).filter(Boolean);
  const asns = [], cidrs = [];
  for (const token of lines) {
    const asnMatch = token.match(/^(?:AS(?:N)?)?(\d{1,10})$/i);
    if (asnMatch) {
      const num = parseInt(asnMatch[1], 10);
      if (num > 0 && num < 4294967296 && !asns.find(a => a.num === num))
        asns.push({ raw: token, num });
      continue;
    }
    const cidrMatch = token.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}|[a-f0-9:]+\/\d{1,3})$/i);
    if (cidrMatch && !cidrs.find(c => c.cidr === cidrMatch[1]))
      cidrs.push({ raw: token, cidr: cidrMatch[1] });
  }
  return { asns, cidrs };
}

function parseASNCIDRRealtime() {
  const raw = document.getElementById('ip-input')?.value || '';
  const { asns, cidrs } = parseASNsAndCIDRs(raw);
  const total = asns.length + cidrs.length;
  const info  = document.getElementById('ioc-parsed-info');
  const btn   = document.getElementById('scan-btn');
  const mcount = document.getElementById('mcount-asnintel');

  if (info) {
    if (!total) { info.innerHTML = ''; }
    else {
      const parts = [];
      if (asns.length)  parts.push(`${asns.length} ASN${asns.length  > 1 ? 's' : ''}`);
      if (cidrs.length) parts.push(`${cidrs.length} CIDR${cidrs.length > 1 ? 's' : ''}`);
      info.innerHTML = `<span>${total}</span> entr${total > 1 ? 'ies' : 'y'} · ` + parts.join(' · ');
    }
  }
  if (btn)    btn.disabled = total === 0;
  if (mcount) mcount.textContent = total > 0 ? String(total) : '';
}

/* ── API wrappers ────────────────────────────────────────────────────────── */
async function _bgpview(type, value, signal) {
  const r = await fetch(`${SERVER_BASE}/api/bgpview?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`, { signal });
  if (!r.ok) throw new Error(`BGPView ${r.status}`);
  return r.json();
}

async function _rdap(type, value, signal) {
  const r = await fetch(`${SERVER_BASE}/api/rdap?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`, { signal });
  if (!r.ok && r.status !== 404) throw new Error(`RDAP ${r.status}`);
  return r.json();
}

async function _abuseBlock(network, signal) {
  const r = await fetch(`${SERVER_BASE}/api/abuseipdb-block?network=${encodeURIComponent(network)}`, { signal });
  if (!r.ok) throw new Error(`AbuseIPDB-block ${r.status}`);
  return r.json();
}

/* ── RDAP helpers ────────────────────────────────────────────────────────── */
function _rdapFn(rdap) {
  if (!rdap?.entities) return null;
  for (const e of rdap.entities) {
    const roles = e.roles || [];
    if (roles.includes('registrant') || roles.includes('administrative')) {
      if (e.vcardArray) for (const v of e.vcardArray[1] || []) if (v[0] === 'fn') return v[3];
      if (e.handle) return e.handle;
    }
  }
  for (const e of rdap?.entities || []) {
    if (e.vcardArray) for (const v of e.vcardArray[1] || []) if (v[0] === 'fn') return v[3];
  }
  return null;
}

function _rdapAbuse(rdap) {
  if (!rdap?.entities) return null;
  for (const e of rdap.entities) {
    if ((e.roles || []).includes('abuse') && e.vcardArray)
      for (const v of e.vcardArray[1] || []) if (v[0] === 'email') return v[3];
    for (const sub of e.entities || [])
      if ((sub.roles || []).includes('abuse') && sub.vcardArray)
        for (const v of sub.vcardArray[1] || []) if (v[0] === 'email') return v[3];
  }
  return null;
}

/* ── Scan engine ─────────────────────────────────────────────────────────── */
async function startASNCIDRScan() {
  const raw = document.getElementById('ip-input')?.value || '';
  if (!raw.trim()) return;
  const { asns, cidrs } = parseASNsAndCIDRs(raw);
  if (!asns.length && !cidrs.length) { showToast('No ASNs or CIDRs detected', 'error'); return; }

  asnIntelResults = []; cidrIntelResults = [];
  isScanning = true; stopRequested = false; totalScanned = 0;

  for (const a of asns)  asnIntelResults .push({ ...a, bgpview: null, rdap: null, prefixes: null, done: false });
  for (const c of cidrs) cidrIntelResults.push({ ...c, bgpview: null, rdap: null, abuse:    null, done: false });

  document.getElementById('results-panel').style.display  = 'none';
  document.getElementById('ipintel-panel').style.display  = 'none';
  document.getElementById('asnintel-panel').style.display = '';
  document.getElementById('progress-container').style.display = '';
  setScanBtnState('scanning');
  renderASNIntelPanel();

  const total = asns.length + cidrs.length;

  for (let i = 0; i < asnIntelResults.length; i++) {
    if (stopRequested) break;
    const entry = asnIntelResults[i];
    updateProgress(i, total, `AS${entry.num}`);
    await _runASNScan(entry);
    entry.done = true; totalScanned++;
    updateASNRow(i, entry);
  }

  for (let i = 0; i < cidrIntelResults.length; i++) {
    if (stopRequested) break;
    const entry = cidrIntelResults[i];
    updateProgress(asnIntelResults.length + i, total, entry.cidr);
    await _runCIDRScan(entry);
    entry.done = true; totalScanned++;
    updateCIDRRow(i, entry);
  }

  isScanning = false;
  updateProgress(totalScanned, total, stopRequested ? 'Stopped' : 'Complete');
  setScanBtnState('idle');
  setTimeout(() => { document.getElementById('progress-container').style.display = 'none'; }, 2000);
  showToast(
    stopRequested
      ? `Stopped — ${totalScanned} entr${totalScanned !== 1 ? 'ies' : 'y'} enriched`
      : `ASN/CIDR Intel complete — ${total} entr${total !== 1 ? 'ies' : 'y'} enriched`,
    'success'
  );
}

async function _runASNScan(entry) {
  const num = String(entry.num);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 14000);
  try {
    const [bgpData, prefixData, rdapData] = await Promise.all([
      _bgpview('asn', num, ctrl.signal).catch(e => ({ _err: e.message })),
      _bgpview('asn_prefixes', num, ctrl.signal).catch(e => ({ _err: e.message })),
      _rdap('autnum', num, ctrl.signal).catch(e => ({ _err: e.message })),
    ]);
    clearTimeout(timer);
    entry.bgpview = bgpData?.data || (bgpData?._err ? null : bgpData);
    entry.rdap    = rdapData?._err ? null : rdapData;
    if (prefixData && !prefixData._err) entry.prefixes = prefixData.data || prefixData;
  } catch (e) {
    clearTimeout(timer);
    entry._err = e.message;
  }
}

async function _runCIDRScan(entry) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 14000);
  try {
    const [bgpData, rdapData, abuseData] = await Promise.all([
      _bgpview('prefix', entry.cidr, ctrl.signal).catch(e => ({ _err: e.message })),
      _rdap('ip', entry.cidr, ctrl.signal).catch(e => ({ _err: e.message })),
      _abuseBlock(entry.cidr, ctrl.signal).catch(e => ({ _err: e.message })),
    ]);
    clearTimeout(timer);
    entry.bgpview = bgpData?.data || (bgpData?._err ? null : bgpData);
    entry.rdap    = rdapData?._err ? null : rdapData;
    entry.abuse   = abuseData?._err ? null : (abuseData?.data || abuseData);
  } catch (e) {
    clearTimeout(timer);
    entry._err = e.message;
  }
}

/* ── UI rendering ────────────────────────────────────────────────────────── */
function renderASNIntelPanel() {
  const asnSection  = document.getElementById('asnintel-asn-section');
  const cidrSection = document.getElementById('asnintel-cidr-section');

  if (asnIntelResults.length) {
    asnSection.style.display = '';
    document.getElementById('asnintel-asn-body').innerHTML =
      asnIntelResults.map((e, i) => _buildASNRow(e, i)).join('');
  } else {
    asnSection.style.display = 'none';
  }

  if (cidrIntelResults.length) {
    cidrSection.style.display = '';
    document.getElementById('asnintel-cidr-body').innerHTML =
      cidrIntelResults.map((e, i) => _buildCIDRRow(e, i)).join('');
  } else {
    cidrSection.style.display = 'none';
  }
}

function _loading() { return `<span class="src-loading">…</span>`; }

function _buildASNRow(entry, i) {
  const { num, done } = entry;
  if (!done) return `<tr id="asn-row-${i}">
    <td class="td-ioc"><span class="ioc-val">AS${num}</span></td>
    ${Array(6).fill(`<td>${_loading()}</td>`).join('')}<td></td><td></td></tr>`;

  const d = entry.bgpview || {};
  const name    = escapeHtml(d.name || '—');
  const country = escapeHtml(d.country_code || entry.rdap?.country || '—');
  const desc    = escapeHtml(d.description_short || d.description_long || '—');
  const rir     = escapeHtml(d.rir_name || '—');
  const ip4cnt  = entry.prefixes?.ipv4_prefixes?.length ?? '—';
  const ip6cnt  = entry.prefixes?.ipv6_prefixes?.length ?? '—';
  const abuse   = escapeHtml(_rdapAbuse(entry.rdap) || (d.abuse_contacts?.[0]?.email) || '—');

  const kv = `AS: AS${num}\nName: ${d.name||'—'}\nDescription: ${d.description_short||'—'}\nCountry: ${country}\nRIR: ${rir}\nIPv4 Prefixes: ${ip4cnt}\nIPv6 Prefixes: ${ip6cnt}\nAbuse Contact: ${abuse}`;

  return `<tr id="asn-row-${i}">
    <td class="td-ioc">
      <span class="ioc-val">AS${escapeHtml(String(num))}</span>
      <button class="ioc-copy-btn" onclick="copyToClipboard('AS${num}')" title="Copy">⎘</button>
    </td>
    <td class="asni-cell">${name}</td>
    <td class="asni-cell asni-muted">${country}</td>
    <td class="asni-cell asni-desc" title="${escapeAttr(d.description_short||d.description_long||'')}">${desc}</td>
    <td class="asni-cell asni-num">${ip4cnt}</td>
    <td class="asni-cell asni-num">${ip6cnt}</td>
    <td class="asni-cell asni-muted">${rir}</td>
    <td><button class="ioc-copy-btn" onclick="copyToClipboard(${JSON.stringify(kv)})" title="Copy details">⎘</button></td>
    <td><button class="btn-detail" onclick="openASNModal(${i})">DETAIL</button></td>
  </tr>`;
}

function _buildCIDRRow(entry, i) {
  const { cidr, done } = entry;
  if (!done) return `<tr id="cidr-row-${i}">
    <td class="td-ioc"><span class="ioc-val">${escapeHtml(cidr)}</span></td>
    ${Array(6).fill(`<td>${_loading()}</td>`).join('')}<td></td><td></td></tr>`;

  const d   = entry.bgpview || {};
  const ral = d.rir_allocation || {};
  const name      = escapeHtml(d.name || '—');
  const country   = escapeHtml(d.country_code || ral.country_code || entry.rdap?.country || '—');
  const desc      = escapeHtml(d.description || '—');
  const rir       = escapeHtml(ral.rir_name || '—');
  const allocated = escapeHtml((ral.date_allocated || '').slice(0, 10) || '—');
  const asns      = escapeHtml((d.asns || []).map(a => `AS${a.asn}`).join(', ') || '—');

  let abuseCell = '<span style="color:var(--muted)">—</span>';
  if (entry.abuse) {
    const rep = Array.isArray(entry.abuse.reportedAddress) ? entry.abuse.reportedAddress.length : (entry.abuse.reportedAddress || 0);
    const tot = entry.abuse.numAddresses    || 0;
    const pct = tot > 0 ? Math.round((rep / tot) * 100) : 0;
    const col = pct >= 20 ? 'var(--red)' : pct >= 5 ? 'var(--yellow)' : 'var(--accent)';
    abuseCell = `<span style="color:${col};font-family:var(--mono);font-size:11px">${rep}/${tot} (${pct}%)</span>`;
  }

  const abuseEmail = escapeHtml(_rdapAbuse(entry.rdap) || '—');
  const kv = `Prefix: ${cidr}\nName: ${d.name||'—'}\nDescription: ${d.description||'—'}\nCountry: ${country}\nAllocated: ${allocated}\nRIR: ${rir}\nOrigin ASN: ${asns}\nAbuse Contact: ${abuseEmail}`;

  return `<tr id="cidr-row-${i}">
    <td class="td-ioc">
      <span class="ioc-val">${escapeHtml(cidr)}</span>
      <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(cidr)}')" title="Copy">⎘</button>
    </td>
    <td class="asni-cell">${name}</td>
    <td class="asni-cell asni-muted">${country}</td>
    <td class="asni-cell asni-desc" title="${escapeAttr(d.description||'')}">${desc}</td>
    <td class="asni-cell asni-muted">${allocated}</td>
    <td class="asni-cell" style="color:var(--accent2)">${asns}</td>
    <td>${abuseCell}</td>
    <td><button class="ioc-copy-btn" onclick="copyToClipboard(${JSON.stringify(kv)})" title="Copy details">⎘</button></td>
    <td><button class="btn-detail" onclick="openCIDRModal(${i})">DETAIL</button></td>
  </tr>`;
}

function updateASNRow(i, entry) {
  const el = document.getElementById(`asn-row-${i}`);
  if (el) el.outerHTML = _buildASNRow(entry, i);
}
function updateCIDRRow(i, entry) {
  const el = document.getElementById(`cidr-row-${i}`);
  if (el) el.outerHTML = _buildCIDRRow(entry, i);
}

/* ── Modals ──────────────────────────────────────────────────────────────── */
function openASNModal(i) {
  const entry = asnIntelResults[i];
  if (!entry) return;
  const { num, bgpview: d = {}, rdap, prefixes } = entry;

  const rdapOrg   = escapeHtml(_rdapFn(rdap) || '—');
  const abuseEmail = escapeHtml(_rdapAbuse(rdap) || d.abuse_contacts?.[0]?.email || '—');

  let prefixHtml = '';
  if (prefixes) {
    const ip4 = (prefixes.ipv4_prefixes || []).slice(0, 30);
    const ip6 = (prefixes.ipv6_prefixes || []).slice(0, 10);
    const chip = p => `<span class="asni-prefix-chip">${escapeHtml(p.prefix)}</span>`;
    if (ip4.length) prefixHtml += `<div class="modal-intel-section"><div class="modal-intel-label">IPv4 PREFIXES — ${prefixes.ipv4_prefixes?.length || 0} total${ip4.length < (prefixes.ipv4_prefixes?.length||0) ? `, showing first ${ip4.length}` : ''}</div><div class="asni-chip-grid">${ip4.map(chip).join('')}</div></div>`;
    if (ip6.length) prefixHtml += `<div class="modal-intel-section"><div class="modal-intel-label">IPv6 PREFIXES — ${prefixes.ipv6_prefixes?.length || 0} total${ip6.length < (prefixes.ipv6_prefixes?.length||0) ? `, showing first ${ip6.length}` : ''}</div><div class="asni-chip-grid">${ip6.map(chip).join('')}</div></div>`;
  }

  document.getElementById('modal-title').textContent = `AS${num} — ${d.name || 'ASN Detail'}`;
  document.getElementById('modal-header-actions').innerHTML =
    `<a href="https://bgpview.io/asn/${num}" target="_blank" rel="noopener" class="btn btn-secondary" style="font-size:11px;padding:5px 10px">BGPView ↗</a>`;
  document.getElementById('modal-body').innerHTML = `
    <div class="modal-intel-grid">
      <div class="modal-intel-section">
        <div class="modal-intel-label">IDENTITY · BGPVIEW</div>
        <div class="modal-intel-kv">
          <div class="mkv-row"><span class="mkv-k">ASN</span><span class="mkv-v">AS${escapeHtml(String(num))}</span></div>
          <div class="mkv-row"><span class="mkv-k">Name</span><span class="mkv-v">${escapeHtml(d.name||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Description</span><span class="mkv-v">${escapeHtml(d.description_short||d.description_long||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Country</span><span class="mkv-v">${escapeHtml(d.country_code||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">RIR</span><span class="mkv-v">${escapeHtml(d.rir_name||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Website</span><span class="mkv-v">${d.website?`<a href="${escapeAttr(d.website)}" target="_blank" rel="noopener" style="color:var(--accent2)">${escapeHtml(d.website)}</a>`:'—'}</span></div>
        </div>
      </div>
      <div class="modal-intel-section">
        <div class="modal-intel-label">REGISTRY · RDAP</div>
        <div class="modal-intel-kv">
          <div class="mkv-row"><span class="mkv-k">Registrant</span><span class="mkv-v">${rdapOrg}</span></div>
          <div class="mkv-row"><span class="mkv-k">Abuse Email</span><span class="mkv-v">${abuseEmail}</span></div>
          <div class="mkv-row"><span class="mkv-k">Handle</span><span class="mkv-v">${escapeHtml(rdap?.handle||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Type</span><span class="mkv-v">${escapeHtml(rdap?.type||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Autnum Range</span><span class="mkv-v">${rdap?.startAutnum!=null?`${rdap.startAutnum} – ${rdap.endAutnum}`:'—'}</span></div>
        </div>
      </div>
    </div>
    ${prefixHtml}`;
  document.getElementById('modal-overlay').classList.add('open');
}

function openCIDRModal(i) {
  const entry = cidrIntelResults[i];
  if (!entry) return;
  const { cidr, bgpview: d = {}, rdap, abuse } = entry;
  const ral = d.rir_allocation || {};

  const rdapOrg    = escapeHtml(_rdapFn(rdap) || '—');
  const abuseEmail = escapeHtml(_rdapAbuse(rdap) || '—');

  let abuseSection = '';
  if (abuse) {
    const rep = Array.isArray(abuse.reportedAddress) ? abuse.reportedAddress.length : (abuse.reportedAddress || 0);
    const tot = abuse.numAddresses    || 0;
    const pct = tot > 0 ? Math.round((rep / tot) * 100) : 0;
    const col = pct >= 20 ? 'var(--red)' : pct >= 5 ? 'var(--yellow)' : 'var(--accent)';
    abuseSection = `<div class="modal-intel-section">
      <div class="modal-intel-label">BLOCK REPUTATION · ABUSEIPDB</div>
      <div class="modal-intel-kv">
        <div class="mkv-row"><span class="mkv-k">Reported IPs</span><span class="mkv-v" style="color:${col}">${rep} / ${tot} (${pct}%)</span></div>
        <div class="mkv-row"><span class="mkv-k">Network</span><span class="mkv-v">${escapeHtml(abuse.networkAddress||cidr)}</span></div>
        <div class="mkv-row"><span class="mkv-k">Prefix</span><span class="mkv-v">${escapeHtml(abuse.netmask||'—')}</span></div>
      </div></div>`;
  }

  const asnsRows = (d.asns || []).map(a =>
    `<div class="mkv-row"><span class="mkv-k">AS${a.asn}</span><span class="mkv-v">${escapeHtml(a.name||a.description||'—')}</span></div>`
  ).join('');

  document.getElementById('modal-title').textContent = `${cidr} — CIDR Detail`;
  document.getElementById('modal-header-actions').innerHTML =
    `<a href="https://bgpview.io/prefix/${cidr}" target="_blank" rel="noopener" class="btn btn-secondary" style="font-size:11px;padding:5px 10px">BGPView ↗</a>`;
  document.getElementById('modal-body').innerHTML = `
    <div class="modal-intel-grid">
      <div class="modal-intel-section">
        <div class="modal-intel-label">PREFIX INFO · BGPVIEW</div>
        <div class="modal-intel-kv">
          <div class="mkv-row"><span class="mkv-k">Prefix</span><span class="mkv-v">${escapeHtml(d.prefix||cidr)}</span></div>
          <div class="mkv-row"><span class="mkv-k">Name</span><span class="mkv-v">${escapeHtml(d.name||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Description</span><span class="mkv-v">${escapeHtml(d.description||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Country</span><span class="mkv-v">${escapeHtml(d.country_code||ral.country_code||'—')}</span></div>
        </div>
      </div>
      <div class="modal-intel-section">
        <div class="modal-intel-label">RIR ALLOCATION · BGPVIEW + RDAP</div>
        <div class="modal-intel-kv">
          <div class="mkv-row"><span class="mkv-k">RIR</span><span class="mkv-v">${escapeHtml(ral.rir_name||rdap?.type||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Allocated</span><span class="mkv-v">${escapeHtml((ral.date_allocated||'').slice(0,10)||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Status</span><span class="mkv-v">${escapeHtml(ral.allocation_status||'—')}</span></div>
          <div class="mkv-row"><span class="mkv-k">Registrant</span><span class="mkv-v">${rdapOrg}</span></div>
          <div class="mkv-row"><span class="mkv-k">Abuse Email</span><span class="mkv-v">${abuseEmail}</span></div>
          <div class="mkv-row"><span class="mkv-k">Handle</span><span class="mkv-v">${escapeHtml(rdap?.handle||'—')}</span></div>
        </div>
      </div>
    </div>
    ${asnsRows ? `<div class="modal-intel-section"><div class="modal-intel-label">ORIGIN ASNs · BGPVIEW</div><div class="modal-intel-kv">${asnsRows}</div></div>` : ''}
    ${abuseSection}`;
  document.getElementById('modal-overlay').classList.add('open');
}

/* ── ASN mode toggle ─────────────────────────────────────────────────────── */
function switchASNIntelMode(mode, btn) {
  asnIntelMode = mode;
  document.querySelectorAll('.asn-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
}
