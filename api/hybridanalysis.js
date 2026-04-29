export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.HYBRIDANALYSIS_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'HYBRIDANALYSIS_API_KEY not configured' });

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip parameter' });
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip)) return res.status(400).json({ error: 'Invalid IP format' });

  try {
    const formBody = new URLSearchParams({ 'terms[network_ip]': ip });
    const upstream = await fetch('https://www.hybrid-analysis.com/api/v2/search/terms', {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Falcon Sandbox',
      },
      body: formBody,
    });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
