export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  try {
    /* Use search_hash for MD5/SHA256 hashes; search_ioc for IPs, domains, URLs */
    const isMd5    = /^[0-9a-fA-F]{32}$/.test(q);
    const isSha256 = /^[0-9a-fA-F]{64}$/.test(q);
    const body = (isMd5 || isSha256)
      ? JSON.stringify({ query: 'search_hash', hash: q.toLowerCase() })
      : JSON.stringify({ query: 'search_ioc', search_term: q });
    const upstream = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.THREATFOX_API_KEY ? { 'Api-Key': process.env.THREATFOX_API_KEY } : {}),
      },
      body,
    });
    /* ThreatFox returns 401 when no valid API key is provided; treat as no results */
    if (upstream.status === 401) return res.status(200).json({ query_status: 'no_result', data: [] });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
