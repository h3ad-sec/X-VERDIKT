export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { src } = req.query;

  /* ── BGPView ── */
  if (src === 'bgpview') {
    const { type, q } = req.query;
    if (!type || !q) return res.status(400).json({ error: 'Missing type or q' });
    let url;
    if (type === 'asn') {
      const num = q.replace(/^AS/i, '');
      if (!/^\d{1,10}$/.test(num)) return res.status(400).json({ error: 'Invalid ASN' });
      url = `https://api.bgpview.io/asn/${num}`;
    } else if (type === 'prefix') {
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(q))
        return res.status(400).json({ error: 'Invalid CIDR' });
      const [ip, len] = q.split('/');
      url = `https://api.bgpview.io/prefix/${ip}/${len}`;
    } else {
      return res.status(400).json({ error: 'type must be asn or prefix' });
    }
    return proxyUpstream(url, {}, res);
  }

  /* ── IPLocate ── */
  if (src === 'iplocate') {
    const { ip } = req.query;
    if (!ip) return res.status(400).json({ error: 'Missing ip' });
    if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip)) return res.status(400).json({ error: 'Invalid IP' });
    const apiKey = process.env.IPLOCATE_API_KEY;
    const headers = { 'Accept': 'application/json' };
    if (apiKey) headers['x-api-key'] = apiKey;
    return proxyUpstream(`https://www.iplocate.io/api/lookup/${encodeURIComponent(ip)}`, headers, res);
  }

  return res.status(400).json({ error: 'Missing or unknown src parameter' });
}

async function proxyUpstream(url, headers = {}, res) {
  try {
    const upstream = await fetch(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'x-verdikt/1.0', ...headers },
      signal: AbortSignal.timeout(8000),
    });
    if (upstream.status === 404) return res.status(404).json({ error: 'Not found' });
    if (upstream.status === 429) return res.status(429).json({ error: 'Upstream rate limit' });
    if (!upstream.ok) return res.status(502).json({ error: `Upstream returned ${upstream.status}` });
    let data;
    try { data = await upstream.json(); }
    catch (_) { return res.status(502).json({ error: 'Upstream returned non-JSON response' }); }
    return res.status(200).json(data);
  } catch (e) {
    const isTimeout = e.name === 'TimeoutError' || e.name === 'AbortError';
    return res.status(isTimeout ? 504 : 502).json({
      error: isTimeout ? 'Upstream timed out' : 'Upstream request failed',
      detail: e.message,
    });
  }
}
