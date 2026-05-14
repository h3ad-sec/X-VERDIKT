export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { type, value } = req.query;
  if (!type || !value) return res.status(400).json({ error: 'Missing type or value' });

  let url;
  if (type === 'autnum') {
    if (!/^\d{1,10}$/.test(value)) return res.status(400).json({ error: 'Invalid ASN' });
    url = `https://rdap.arin.net/registry/autnum/${value}`;
  } else if (type === 'ip') {
    if (!/^[\d.:a-fA-F/]+$/.test(value)) return res.status(400).json({ error: 'Invalid IP/CIDR' });
    url = `https://rdap.arin.net/registry/ip/${value}`;
  } else {
    return res.status(400).json({ error: 'Invalid type. Use autnum or ip' });
  }

  try {
    const resp = await fetch(url, {
      headers: { 'Accept': 'application/rdap+json, application/json', 'User-Agent': 'X-VERDIKT/1.0' },
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });
    if (resp.status === 404) return res.status(404).json({ error: 'Not found in ARIN registry' });
    if (!resp.ok) return res.status(resp.status).json({ error: `RDAP returned ${resp.status}` });
    const data = await resp.json();
    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'RDAP request failed', detail: e.message });
  }
}
