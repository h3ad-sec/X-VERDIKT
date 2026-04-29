
const SERVER_BASE = (() => {
  const isStatic = ['github.io','netlify.app','pages.dev'].some(h => location.hostname.endsWith(h));
  return isStatic ? 'https://x-verdikt.vercel.app' : '';
})();

const API = {

  async virusTotal(ip, signal) {
    const path = `/api/v3/ip_addresses/${encodeURIComponent(ip.value)}`;
    try {
      const resp = await fetch(`${SERVER_BASE}/api/vt?path=${encodeURIComponent(path)}`, { signal });
      if (!resp.ok) return vtHttpErr(resp.status);
      return parseVTIPResponse(await resp.json());
    } catch(e) { return { source: 'virustotal', error: fmtErr(e) }; }
  },

  async abuseIPDB(ip, signal) {
    try {
      const resp = await fetch(`${SERVER_BASE}/api/abuseipdb?ip=${encodeURIComponent(ip.value)}`, { signal });
      if (!resp.ok) return abHttpErr(resp.status);
      return parseAbuseIPDBResponse(await resp.json());
    } catch(e) { return { source: 'abuseipdb', error: fmtErr(e) }; }
  },

  async otx(ip, signal) {
    const section = ip.type === 'ipv6' ? 'IPv6' : 'IPv4';
    const path = `/api/v1/indicators/${section}/${ip.value}/general`;
    try {
      const resp = await fetch(`${SERVER_BASE}/api/otx?path=${encodeURIComponent(path)}`, { signal });
      if (!resp.ok) return otxHttpErr(resp.status);
      return parseOTXIPResponse(await resp.json());
    } catch(e) { return { source: 'otx', error: fmtErr(e) }; }
  },

  async urlscan(ip, signal) {
    try {
      const resp = await fetch(`${SERVER_BASE}/api/urlscan?q=${encodeURIComponent(`ip:${ip.value}`)}`, { signal });
      if (!resp.ok) return { source: 'urlscan', error: `HTTP ${resp.status}` };
      return parseURLScanResponse(await resp.json());
    } catch(e) { return { source: 'urlscan', error: fmtErr(e) }; }
  },

  async threatfox(ip, signal) {
    try {
      const resp = await fetch(`${SERVER_BASE}/api/threatfox?q=${encodeURIComponent(ip.value)}`, { signal });
      if (!resp.ok) return { source: 'threatfox', error: `HTTP ${resp.status}` };
      return parseThreatFoxResponse(await resp.json());
    } catch(e) { return { source: 'threatfox', error: fmtErr(e) }; }
  },

  async urlhaus(ip, signal) {
    try {
      const resp = await fetch(`${SERVER_BASE}/api/urlhaus?host=${encodeURIComponent(ip.value)}`, { signal });
      if (!resp.ok) return { source: 'urlhaus', error: `HTTP ${resp.status}` };
      return parseURLhausHostResponse(await resp.json());
    } catch(e) { return { source: 'urlhaus', error: fmtErr(e) }; }
  },

  async malwarebazaar(ip, signal) {
    try {
      const resp = await fetch(`${SERVER_BASE}/api/malwarebazaar?tag=${encodeURIComponent(ip.value)}`, { signal });
      if (!resp.ok) return { source: 'malwarebazaar', skipped: true, reason: 'No response' };
      return parseMBTagResponse(await resp.json());
    } catch(e) { return { source: 'malwarebazaar', skipped: true, reason: fmtErr(e) }; }
  },

  async hybridanalysis(ip, signal) {
    try {
      const resp = await fetch(`${SERVER_BASE}/api/hybridanalysis?ip=${encodeURIComponent(ip.value)}`, { signal });
      if (!resp.ok) return { source: 'hybridanalysis', error: `HTTP ${resp.status}` };
      return parseHybridAnalysisResponse(await resp.json());
    } catch(e) { return { source: 'hybridanalysis', error: fmtErr(e) }; }
  },

  async shodan(ip, signal) {
    if (ip.type === 'ipv6') return { source: 'shodan', skipped: true, reason: 'IPv4 only' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/shodan?ip=${encodeURIComponent(ip.value)}`, { signal });
      if (resp.ok) return parseShodanFullResponse(await resp.json());
      if (resp.status === 404) return { source: 'shodan', verdict: 'benign', ports: [], cves: [], tags: [], hostnames: [], full: true, scoreLabel: 'Not indexed' };
      return { source: 'shodan', error: `HTTP ${resp.status}` };
    } catch(e) { return { source: 'shodan', error: fmtErr(e) }; }
  },
};


function parseVTIPResponse(data) {
  const attrs = data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const mal = stats.malicious || 0, sus = stats.suspicious || 0;
  const harm = stats.harmless || 0, undet = stats.undetected || 0;
  const total = mal + sus + harm + undet;
  const cert = attrs.last_https_certificate || null;
  return {
    source: 'virustotal',
    verdict: mal > 0 ? 'malicious' : sus > 0 ? 'suspicious' : 'benign',
    malicious: mal, suspicious: sus, harmless: harm, undetected: undet, total,
    ip: data?.data?.id || '',
    asn: attrs.asn ?? null,
    as_owner: attrs.as_owner || null,
    country: attrs.country || null,
    reputation: attrs.reputation ?? null,
    tags: attrs.tags || [],
    jarm: attrs.jarm || null,
    network: attrs.network || null,
    last_analysis_date: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString().split('T')[0] : null,
    cert_subject_cn: cert?.subject?.CN || null,
    cert_issuer_cn: cert?.issuer?.CN || null,
    cert_self_signed: cert ? (cert.self_signed ?? null) : null,
    cert_thumbprint: cert?.thumbprint_sha256 || null,
    cert_valid_until: cert?.validity?.not_after || null,
    link: data?.data?.id ? `https://www.virustotal.com/gui/ip-address/${data.data.id}` : null,
    raw: data,
  };
}

function parseAbuseIPDBResponse(data) {
  const d = data?.data || {};
  const score = d.abuseConfidenceScore || 0;
  return {
    source: 'abuseipdb',
    verdict: score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : 'benign',
    score, scoreLabel: `${score}%`,
    ipAddress: d.ipAddress || '',
    isPublic: d.isPublic ?? null,
    ipVersion: d.ipVersion ?? null,
    isWhitelisted: d.isWhitelisted ?? null,
    usageType: d.usageType || null,
    isp: d.isp || null,
    domain: d.domain || null,
    hostnames: d.hostnames || [],
    isTor: d.isTor || false,
    totalReports: d.totalReports || 0,
    lastReportedAt: d.lastReportedAt || null,
    link: `https://www.abuseipdb.com/check/${d.ipAddress || ''}`,
    raw: data,
  };
}

function parseOTXIPResponse(data) {
  const pulseCount = data?.pulse_info?.count || 0;
  const pulses = data?.pulse_info?.pulses || [];
  let totalSubscribers = 0, maxIndicatorCount = 0;
  const pulseAuthors = [], malwareFamilies = [], tags = [], adversaries = [];
  for (const p of pulses) {
    totalSubscribers += p.subscriber_count || 0;
    if ((p.indicator_count || 0) > maxIndicatorCount) maxIndicatorCount = p.indicator_count;
    if (p.author_name) pulseAuthors.push(p.author_name);
  }
  for (const p of pulses.slice(0, 5)) {
    if (p.malware_families) malwareFamilies.push(...p.malware_families.map(f => f.display_name || f));
    if (p.tags) tags.push(...p.tags.slice(0, 3));
    if (p.adversary) adversaries.push(p.adversary);
  }
  const validation = data?.validation || [];
  return {
    source: 'otx',
    verdict: pulseCount >= 5 ? 'malicious' : pulseCount >= 1 ? 'suspicious' : 'benign',
    pulseCount, scoreLabel: `${pulseCount} pulse${pulseCount !== 1 ? 's' : ''}`,
    subscriberCount: totalSubscribers,
    indicatorCount: maxIndicatorCount,
    validation: validation.length > 0 ? 'Validated' : 'Unvalidated',
    pulseSources: [...new Set(pulseAuthors)].slice(0, 5),
    malwareFamilies: [...new Set(malwareFamilies)].slice(0, 5),
    tags: [...new Set(tags)].slice(0, 8),
    adversaries: [...new Set(adversaries)].slice(0, 3),
    recentPulse: pulses[0]?.name || null,
    link: `https://otx.alienvault.com/indicator/ip/${data?.indicator || ''}`,
    raw: data,
  };
}

function parseURLScanResponse(data) {
  const results = data?.results || [];
  const total = data?.total || results.length;
  if (!total && !results.length) return { source: 'urlscan', notFound: true, total: 0, results: [], maliciousCount: 0 };
  const maliciousCount = results.filter(r => r.verdicts?.overall?.malicious).length;
  const recent = results.slice(0, 5).map(r => ({
    url: r.page?.url || '',
    domain: r.page?.domain || '',
    date: r.task?.time?.split('T')[0] || '',
    malicious: r.verdicts?.overall?.malicious || false,
  }));
  return { source: 'urlscan', total, maliciousCount, recent, notFound: false, raw: data };
}

function parseThreatFoxResponse(data) {
  if (data?.query_status === 'no_result' || !data?.data?.length)
    return { source: 'threatfox', notFound: true, iocCount: 0, raw: data };
  const iocs = data.data || [];
  return {
    source: 'threatfox',
    iocCount: iocs.length,
    malwareFamilies: [...new Set(iocs.map(i => i.malware).filter(Boolean))],
    threatTypes: [...new Set(iocs.map(i => i.threat_type).filter(Boolean))],
    maxConfidence: Math.max(...iocs.map(i => i.confidence_level || 0), 0),
    notFound: false,
    firstSeen: iocs[0]?.first_seen?.split(' ')[0] || null,
    lastSeen: iocs[0]?.last_seen?.split(' ')[0] || null,
    raw: data,
  };
}

function parseURLhausHostResponse(data) {
  if (data?.query_status === 'no_results')
    return { source: 'urlhaus', notFound: true, urlsCount: 0, raw: data };
  const urls = data?.urls || [];
  return {
    source: 'urlhaus',
    urlsCount: urls.length,
    onlineCount: urls.filter(u => u.url_status === 'online').length,
    threats: [...new Set(urls.map(u => u.threat).filter(Boolean))],
    notFound: false, tags: data?.tags || [],
    dateAdded: urls[0]?.date_added?.split(' ')[0] || null,
    raw: data,
  };
}

function parseMBTagResponse(data) {
  if (data?.query_status !== 'ok' || !data?.data?.length)
    return { source: 'malwarebazaar', notFound: true, count: 0, raw: data };
  const items = data.data || [];
  return {
    source: 'malwarebazaar',
    count: items.length,
    families: [...new Set(items.map(i => i.signature).filter(Boolean))].slice(0, 5),
    notFound: false, raw: data,
  };
}

function parseHybridAnalysisResponse(data) {
  const results = data?.result || data?.results || [];
  if (!results.length) return { source: 'hybridanalysis', notFound: true, count: 0, raw: data };
  const maliciousCount = results.filter(r => r.verdict === 'malicious' || (r.threat_level || 0) >= 2).length;
  const families = [...new Set(results.slice(0, 5).map(r => r.malware_family || r.threat_level_human).filter(Boolean))];
  return {
    source: 'hybridanalysis',
    count: results.length, maliciousCount,
    families: families.slice(0, 5),
    maxScore: Math.max(...results.map(r => r.threat_score || 0), 0),
    notFound: false, raw: data,
  };
}

function parseShodanFullResponse(data) {
  const cves = Object.keys(data?.vulns || {});
  const ports = data?.ports || [];
  const tags = data?.tags || [];
  let verdict = 'benign';
  if (cves.length > 0) verdict = 'suspicious';
  if (tags.includes('honeypot') || tags.includes('malware') || tags.includes('tor')) verdict = 'malicious';
  return {
    source: 'shodan', verdict, ports, cves, tags,
    hostnames: data?.hostnames || [],
    isp: data?.isp || null, org: data?.org || null,
    country: data?.country_code || null, os: data?.os || null,
    city: data?.city || null, full: true,
    scoreLabel: cves.length > 0 ? `${cves.length} CVE${cves.length > 1 ? 's' : ''}` : ports.length ? `${ports.length} ports` : 'No data',
    link: `https://www.shodan.io/host/${data?.ip_str || ''}`, raw: data,
  };
}

function vtHttpErr(s)  { return { source: 'virustotal',  error: { 404: 'Not found', 401: 'Unauthorized', 429: 'Rate limited', 503: 'API key not configured' }[s] || `HTTP ${s}` }; }
function abHttpErr(s)  { return { source: 'abuseipdb',   error: { 401: 'Unauthorized', 429: 'Rate limited', 503: 'API key not configured' }[s] || `HTTP ${s}` }; }
function otxHttpErr(s) { return { source: 'otx',         error: { 401: 'Unauthorized', 404: 'Not found', 429: 'Rate limited', 503: 'API key not configured' }[s] || `HTTP ${s}` }; }
function fmtErr(e)     { return e?.name === 'AbortError' ? 'Timeout (8s)' : e?.message?.match(/fetch|network|load/i) ? 'Network error' : (e.message || 'Unknown error'); }
