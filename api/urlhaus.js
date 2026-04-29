export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  const formBody = new URLSearchParams({ host });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (process.env.ABUSECH_AUTH_KEY) headers['Auth-Key'] = process.env.ABUSECH_AUTH_KEY;

  try {
    const upstream = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers,
      body: formBody,
    });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
