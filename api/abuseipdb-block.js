export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'ABUSEIPDB_API_KEY not configured' });

  const { network } = req.query;
  if (!network) return res.status(400).json({ error: 'Missing network parameter' });
  if (!/^[\d.:a-fA-F/]+$/.test(network)) return res.status(400).json({ error: 'Invalid network format' });

  try {
    const upstream = await fetch(
      `https://api.abuseipdb.com/api/v2/check-block?network=${encodeURIComponent(network)}&maxAgeInDays=90`,
      { headers: { 'Key': apiKey, 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) }
    );
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'AbuseIPDB request failed', detail: e.message });
  }
}
