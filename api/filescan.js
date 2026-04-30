export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { hash } = req.query;
  if (!hash) return res.status(400).json({ error: 'Missing hash parameter' });
  if (!/^[0-9a-fA-F]{32,64}$/.test(hash))
    return res.status(400).json({ error: 'Invalid hash format' });

  const headers = { 'accept': 'application/json' };
  if (process.env.FILESCAN_API_KEY) headers['X-Api-Key'] = process.env.FILESCAN_API_KEY;

  try {
    const upstream = await fetch(
      `https://www.filescan.io/api/reports/search?query=${encodeURIComponent(hash.toLowerCase())}`,
      { method: 'GET', headers }
    );
    if (!upstream.ok) return res.status(200).json({ count: 0, items: [] });
    return res.status(200).json(await upstream.json());
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
