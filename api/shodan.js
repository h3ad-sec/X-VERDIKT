export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'SHODAN_API_KEY not configured' });

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip parameter' });
  if (!/^[0-9.]{7,15}$/.test(ip)) return res.status(400).json({ error: 'Invalid IPv4 format' });

  try {
    const upstream = await fetch(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`
    );
    if (upstream.status === 404) return res.status(404).json({ error: 'Not found' });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
