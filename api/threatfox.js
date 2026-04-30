export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  const headers = {
    'Content-Type': 'application/json',
    ...(process.env.THREATFOX_API_KEY ? { 'Api-Key': process.env.THREATFOX_API_KEY } : {}),
  };
  const EMPTY = { query_status: 'no_result', data: [] };

  async function tfPost(body) {
    const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    if (r.status === 401) return null;          // no key / key invalid
    if (!r.ok) return null;
    return r.json();
  }

  try {
    const isMd5    = /^[0-9a-fA-F]{32}$/.test(q);
    const isSha256 = /^[0-9a-fA-F]{64}$/.test(q);

    let data = null;
    if (isMd5 || isSha256) {
      /* Try search_hash first; fall back to search_ioc if ThreatFox rejects it */
      data = await tfPost({ query: 'search_hash', hash: q.toLowerCase() });
      if (!data || data.query_status === 'illegal_query')
        data = await tfPost({ query: 'search_ioc', search_term: q.toLowerCase() });
    } else {
      data = await tfPost({ query: 'search_ioc', search_term: q });
    }

    return res.status(200).json(data ?? EMPTY);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
