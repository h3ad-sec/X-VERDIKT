export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { type, q } = req.query;
  if (!type || !q) return res.status(400).json({ error: 'Missing type or q parameter' });

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

  try {
    const upstream = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (upstream.status === 404) return res.status(404).json({ error: 'Not found' });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
