
let scanResults   = [];
let isScanning    = false;
let stopRequested = false;
let totalScanned  = 0;

const VtBucket = {
  tokens: 4, max: 4, refillRate: 4,
  lastRefill: Date.now(), paid: false,
  async acquire() {
    if (this.paid) return;
    const now = Date.now();
    this.tokens = Math.min(this.max, this.tokens + ((now - this.lastRefill) / 60000) * this.refillRate);
    this.lastRefill = now;
    if (this.tokens >= 1) { this.tokens--; return; }
    const waitMs = ((1 - this.tokens) / this.refillRate) * 60000;
    updateProgressSub(`VT rate limit — waiting ${Math.ceil(waitMs / 1000)}s…`);
    await sleep(waitMs);
    this.tokens = 0; this.lastRefill = Date.now();
  }
};

async function fetchWithRetry(fn, retries = 2, ms = 10000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), ms);
      const r = await fn(ctrl.signal);
      clearTimeout(t); return r;
    } catch(e) {
      if (i === retries) throw e;
      if (e.name === 'AbortError') throw new Error('Timeout');
      await sleep(1000 * (i + 1));
    }
  }
}

async function startScan() {
  const raw = getInputText();
  if (!raw?.trim()) return;

  const { iocs } = parseIOCsWithMeta(raw);
  if (!iocs.length) { showToast('No valid IOCs detected', 'error'); return; }

  const privateCount = iocs.filter(i => i.isPrivate).length;
  if (privateCount > 0)
    showToast(`${privateCount} private IP${privateCount > 1 ? 's' : ''} detected — will skip external queries`, 'warning');

  VtBucket.paid = window._serverVTPaid === true;
  VtBucket.tokens = 4; VtBucket.lastRefill = Date.now();

  isScanning = true; stopRequested = false; scanResults = []; totalScanned = 0;

  for (const ioc of iocs) {
    scanResults.push({
      ioc, vt: null, ab: null, otx: null,
      urlscan: null, threatfox: null, urlhaus: null,
      mb: null, ha: null, shodan: null,
      verdict: null, confidence: null, action: null,
      score: null, vtPts: null, abPts: null, otxPts: null,
      reasons: [], indicators: [], flags: [], done: false,
    });
  }

  document.getElementById('results-panel').style.display = '';
  document.getElementById('progress-container').style.display = '';
  setScanBtnState('scanning');

  const rn = document.getElementById('rate-note-text');
  if (rn) rn.textContent = VtBucket.paid ? 'Parallel · VT Paid — no rate limit' : 'Parallel · VT Free — token bucket (4 req/min)';

  renderResultRows(scanResults);
  renderSummary(scanResults);

  for (let i = 0; i < iocs.length; i++) {
    if (stopRequested) break;
    const ioc = iocs[i], entry = scanResults[i];
    updateProgress(i, iocs.length, ioc.value);
    updateRowLoading(i);
    await runParallelScan(entry);
    const scored = scoreEntry(entry);
    Object.assign(entry, scored, { done: true });
    totalScanned++;
    updateRow(i, entry);
    renderSummary(scanResults);
    updateHeaderCount();
  }

  isScanning = false;
  updateProgress(totalScanned, iocs.length, stopRequested ? 'Stopped' : 'Complete');
  setScanBtnState('idle');
  setTimeout(() => { document.getElementById('progress-container').style.display = 'none'; }, 2000);
  const n = iocs.length;
  showToast(
    stopRequested
      ? `Stopped — ${totalScanned} IOC${totalScanned !== 1 ? 's' : ''} analyzed`
      : `X-VERDIKT complete — ${n} IOC${n !== 1 ? 's' : ''} analyzed`,
    'success'
  );
}

async function runParallelScan(entry) {
  const { ioc } = entry;
  const t = ioc.type;
  const isIP   = t === 'ip' || t === 'ipv6';
  const isHash = t.startsWith('hash_');
  const isDomOrUrl = t === 'domain' || t === 'url';

  if (ioc.isPrivate) {
    const skip = s => ({ source: s, skipped: true, reason: 'Private IP — skipped' });
    entry.vt = skip('virustotal'); entry.ab = skip('abuseipdb'); entry.otx = skip('otx');
    entry.urlscan = skip('urlscan'); entry.threatfox = skip('threatfox');
    entry.urlhaus = skip('urlhaus'); entry.mb = skip('malwarebazaar');
    entry.ha = skip('hybridanalysis'); entry.shodan = skip('shodan');
    return;
  }

  const vtP = (async () => {
    await VtBucket.acquire();
    return fetchWithRetry(sig => API.virusTotal(ioc, sig)).catch(e => ({ source: 'virustotal', error: e.message }));
  })();

  /* AbuseIPDB: IP/IPv6 only */
  const abP = isIP
    ? fetchWithRetry(sig => API.abuseIPDB(ioc, sig)).catch(e => ({ source: 'abuseipdb', error: e.message }))
    : Promise.resolve({ source: 'abuseipdb', skipped: true, reason: 'IP only' });

  const otxP = fetchWithRetry(sig => API.otx(ioc, sig)).catch(e => ({ source: 'otx', error: e.message }));

  /* URLScan: IP/domain/URL only */
  const usP = !isHash
    ? fetchWithRetry(sig => API.urlscan(ioc, sig)).catch(e => ({ source: 'urlscan', error: e.message }))
    : Promise.resolve({ source: 'urlscan', skipped: true, reason: 'N/A for hashes' });

  const tfP = fetchWithRetry(sig => API.threatfox(ioc, sig)).catch(e => ({ source: 'threatfox', error: e.message }));

  /* URLhaus: IP/domain/URL/MD5/SHA256 */
  const uhOk = isIP || isDomOrUrl || t === 'hash_md5' || t === 'hash_sha256';
  const uhP = uhOk
    ? fetchWithRetry(sig => API.urlhaus(ioc, sig)).catch(e => ({ source: 'urlhaus', error: e.message }))
    : Promise.resolve({ source: 'urlhaus', skipped: true, reason: 'Hash type not supported' });

  /* MB: hash + IP (tag search) */
  const mbOk = isHash || t === 'ip';
  const mbP = mbOk
    ? fetchWithRetry(sig => API.malwarebazaar(ioc, sig)).catch(e => ({ source: 'malwarebazaar', skipped: true, reason: e.message }))
    : Promise.resolve({ source: 'malwarebazaar', skipped: true, reason: 'IP/hash only' });

  /* HA: IP + MD5/SHA1/SHA256 */
  const haOk = t === 'ip' || t === 'hash_md5' || t === 'hash_sha1' || t === 'hash_sha256';
  const haP = haOk
    ? fetchWithRetry(sig => API.hybridanalysis(ioc, sig)).catch(e => ({ source: 'hybridanalysis', error: e.message }))
    : Promise.resolve({ source: 'hybridanalysis', skipped: true, reason: isDomOrUrl ? 'IP/hash only' : 'SHA-512 not supported' });

  /* Shodan: IPv4 only */
  const shP = t === 'ip'
    ? fetchWithRetry(sig => API.shodan(ioc, sig)).catch(e => ({ source: 'shodan', error: e.message }))
    : Promise.resolve({ source: 'shodan', skipped: true, reason: t === 'ipv6' ? 'IPv4 only' : 'IP only' });

  const [vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha, shodan] =
    await Promise.all([vtP, abP, otxP, usP, tfP, uhP, mbP, haP, shP]);

  entry.vt = vt; entry.ab = ab; entry.otx = otx;
  entry.urlscan = urlscan; entry.threatfox = threatfox; entry.urlhaus = urlhaus;
  entry.mb = mb; entry.ha = ha; entry.shodan = shodan;
}

function scoreEntry(entry) {
  const { vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha, shodan } = entry;
  const iocIsHash = entry.ioc.type.startsWith('hash_');
  const iocIsIP   = entry.ioc.type === 'ip' || entry.ioc.type === 'ipv6';
  let vtPts = 0, abPts = 0, otxPts = 0;
  let sourcesChecked = 0;
  const reasons = [], indicators = [], flags = [];

  /* VT — max 40 pts */
  if (vt && !vt.skipped && !vt.error) {
    const mal = vt.malicious || 0, total = vt.total || 0;
    if (total > 0) {
      sourcesChecked++;
      vtPts = Math.round((mal / total) * 40);
      indicators.push(`VT: ${mal}/${total}`);
      if (mal > 0) reasons.push(`Detected by ${mal} VT engine${mal > 1 ? 's' : ''}`);
    }
  }

  /* AbuseIPDB — max 40 pts (IP only) */
  if (ab && !ab.skipped && !ab.error) {
    sourcesChecked++;
    const s = ab.score || 0;
    abPts = Math.round((s / 100) * 40);
    indicators.push(`AbuseIPDB: ${s}%`);
    if (s >= 75) reasons.push(`High abuse score (${s}%) on AbuseIPDB`);
    else if (s >= 25) reasons.push(`Moderate abuse score (${s}%) on AbuseIPDB`);
  }

  /* OTX — max 20 pts */
  if (otx && !otx.skipped && !otx.error) {
    sourcesChecked++;
    const p = otx.pulseCount || 0;
    otxPts = Math.min(20, Math.round((p / 5) * 20));
    if (p > 0) {
      indicators.push(`OTX: ${p} pulse${p > 1 ? 's' : ''}`);
      reasons.push(`Listed in ${p} OTX pulse${p > 1 ? 's' : ''}`);
    }
  }

  /* Score — normalize to 100 for non-IP types (max available = VT40 + OTX20 = 60) */
  let score;
  if (iocIsIP) {
    score = Math.min(100, vtPts + abPts + otxPts);
  } else {
    const raw = vtPts + otxPts;
    score = raw === 0 ? 0 : Math.min(100, Math.round(raw / 60 * 100));
  }

  /* Supplementary flags */
  const tfHit = threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound && (threatfox.iocCount || 0) > 0;
  const uhHit = urlhaus  && !urlhaus.skipped  && !urlhaus.error  && !urlhaus.notFound  && (urlhaus.urlsCount || 0) > 0;
  const haHit = ha       && !ha.skipped       && !ha.error       && !ha.notFound       && (ha.count || 0) > 0;
  const usHit = urlscan  && !urlscan.skipped  && !urlscan.error  && !urlscan.notFound  && (urlscan.total || 0) > 0;
  const shCve = shodan   && !shodan.skipped   && !shodan.error   && (shodan.cves?.length || 0) > 0;
  const shTag = shodan   && !shodan.skipped   && !shodan.error   && shodan.tags?.some(t => ['tor','honeypot','malware'].includes(t));
  const mbHit = mb       && !mb.skipped       && !mb.error       && !mb.notFound       && (mb.count || 0) > 0;

  if (tfHit) {
    flags.push('TF:C2');
    indicators.push(`ThreatFox: ${threatfox.iocCount} C2`);
    reasons.push(`ThreatFox: ${threatfox.iocCount} C2 indicator${threatfox.iocCount > 1 ? 's' : ''}`);
  }
  if (uhHit) {
    flags.push('UH:URLS');
    indicators.push(`URLhaus: ${urlhaus.urlsCount} URL${urlhaus.urlsCount > 1 ? 's' : ''}`);
    if (!reasons.find(r => r.startsWith('URLhaus')))
      reasons.push(`URLhaus: ${urlhaus.urlsCount} malicious URL${urlhaus.urlsCount > 1 ? 's' : ''}`);
  }
  if (mbHit) {
    flags.push('MB:HIT');
    indicators.push(`MalwareBazaar: ${mb.count} sample${mb.count > 1 ? 's' : ''}`);
    reasons.push(`Found in MalwareBazaar${mb.families?.length ? ` (${mb.families[0]})` : ''}`);
  }
  if (haHit)  { flags.push('HA:SANDBOX'); indicators.push(`HA: ${ha.count} sandbox hit${ha.count > 1 ? 's' : ''}`); }
  if (usHit)  flags.push(`US:${urlscan.total}`);
  if (shCve)  { flags.push('SH:CVE'); indicators.push(`Shodan: ${shodan.cves.length} CVE${shodan.cves.length > 1 ? 's' : ''}`); }
  if (shTag)  flags.push('SH:TAG');

  /* Verdict */
  const abScore = ab?.score || 0;
  const vtMal   = vt?.malicious || 0;
  let verdict;
  if      (abScore >= 75 || vtMal >= 5 || score >= 60 || tfHit || shTag || (mbHit && iocIsHash)) verdict = 'malicious';
  else if (score >= 30 || abScore >= 25 || vtMal >= 1 || uhHit || shCve || haHit || mbHit)       verdict = 'suspicious';
  else if (sourcesChecked >= 2)                                                                    verdict = 'benign';
  else                                                                                             verdict = 'unknown';

  if (sourcesChecked === 0 && !tfHit && !uhHit && !mbHit && verdict === 'benign') verdict = 'unknown';
  if (verdict === 'benign' && (otx?.pulseCount || 0) > 0) verdict = 'unknown';

  const verdictMeta = {
    malicious:  { confidence: 'high',          action: 'block' },
    suspicious: { confidence: 'medium',        action: 'investigate' },
    benign:     { confidence: 'informational', action: 'allow' },
    unknown:    { confidence: 'low',           action: 'monitor' },
  };
  const { confidence, action } = verdictMeta[verdict];

  if (!reasons.length)
    reasons.push(sourcesChecked === 0 ? 'Sources pending or unavailable' : 'No threat signals detected');

  return {
    score, vtPts, abPts, otxPts,
    verdict, confidence, action,
    reasons: reasons.slice(0, 3),
    indicators: indicators.slice(0, 6),
    flags,
  };
}

function stopScan() { stopRequested = true; showToast('Stopping after current IOC…', 'warning'); }

function setScanBtnState(state) {
  const btn = document.getElementById('scan-btn'), stop = document.getElementById('stop-btn');
  if (state === 'scanning') {
    btn.disabled = true; btn.style.display = 'none'; stop.style.display = '';
  } else {
    btn.disabled = false; btn.style.display = ''; stop.style.display = 'none';
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.5"/><path d="M7 4.5v2.5l1.8 1.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> ANALYZE`;
  }
}

function updateProgress(done, total, label) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-stats').textContent = `${done} / ${total}`;
  const complete = label === 'Complete' || label === 'Stopped' || done >= total;
  document.getElementById('progress-label').textContent = complete ? 'X-VERDIKT COMPLETE' : 'ANALYZING…';
  document.getElementById('progress-sub').innerHTML = complete
    ? `<span style="color:var(--accent)">✓ ${totalScanned} IOC${totalScanned !== 1 ? 's' : ''} analyzed</span><span style="color:var(--muted)">${pct}%</span>`
    : `<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%">${escapeHtml(label)}</span><span style="color:var(--muted)">${pct}%</span>`;
}
function updateProgressSub(msg) { const el = document.getElementById('progress-sub'); if (el) el.innerHTML = `<span style="color:var(--yellow)">${escapeHtml(msg)}</span>`; }
function updateHeaderCount() { const el = document.getElementById('session-count'); if (el) el.textContent = totalScanned; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
