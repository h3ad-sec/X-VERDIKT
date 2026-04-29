
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV6_RE = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}/g;

const PRIVATE_V4 = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^127\.\d+\.\d+\.\d+$/,
  /^0\.0\.0\.0$/,
  /^169\.254\.\d+\.\d+$/,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+$/,
  /^255\.255\.255\.255$/,
];

function isPrivateV4(ip) { return PRIVATE_V4.some(r => r.test(ip)); }
function isPrivateV6(ip) {
  const l = ip.toLowerCase();
  return l === '::1' || l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd');
}

function defang(raw) {
  return raw
    .replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.')
    .replace(/\[:\]/g, ':').replace(/\s/g, '');
}

function parseIPs(raw) {
  const seen = new Set();
  const results = [];
  const text = defang(raw);

  for (const m of text.matchAll(new RegExp(IPV4_RE.source, 'g'))) {
    const ip = m[0];
    if (!seen.has(ip)) {
      seen.add(ip);
      results.push({
        value: ip, type: 'ip', baseType: 'ip', label: 'IPv4',
        isPrivate: isPrivateV4(ip),
        defanged: raw.includes('[.]') ? raw.split(/\s+/).find(t => defang(t) === ip && t !== ip) || null : null,
      });
    }
  }

  for (const m of text.matchAll(new RegExp(IPV6_RE.source, 'g'))) {
    const ip = m[0];
    if (!seen.has(ip) && ip.includes(':') && ip.length > 6) {
      seen.add(ip);
      results.push({
        value: ip, type: 'ipv6', baseType: 'ip', label: 'IPv6',
        isPrivate: isPrivateV6(ip), defanged: null,
      });
    }
  }

  return results;
}

function parseIPsWithMeta(raw) {
  const ips = parseIPs(raw);
  return {
    ips,
    total: ips.length,
    ipv4: ips.filter(i => i.type === 'ip').length,
    ipv6: ips.filter(i => i.type === 'ipv6').length,
    private: ips.filter(i => i.isPrivate).length,
  };
}

function parseIPsRealtime() {
  const raw = document.getElementById('ip-input')?.value || '';
  const meta = parseIPsWithMeta(raw);
  const info = document.getElementById('ip-parsed-info');
  const btn = document.getElementById('scan-btn');
  if (meta.total === 0) {
    if (info) info.innerHTML = '';
    if (btn) btn.disabled = true;
    document.getElementById('ip-breakdown')?.style && (document.getElementById('ip-breakdown').style.display = 'none');
    return;
  }
  const parts = [`<span>${meta.total}</span> IP${meta.total > 1 ? 's' : ''}`];
  if (meta.ipv4 && meta.ipv6) parts.push(`${meta.ipv4} IPv4 · ${meta.ipv6} IPv6`);
  else if (meta.ipv4) parts.push(`IPv4`);
  else if (meta.ipv6) parts.push(`IPv6`);
  if (meta.private) parts.push(`<span style="color:var(--yellow)">${meta.private} private</span>`);
  if (info) info.innerHTML = parts.join(' · ');
  if (btn) btn.disabled = false;
}

function getInputText() { return document.getElementById('ip-input')?.value || ''; }
