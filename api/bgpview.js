export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { type, value } = req.query;
  if (!type || !value) return res.status(400).json({ error: 'Missing type or value' });

  if (type === 'asn' || type === 'asn_prefixes') {
    if (!/^\d{1,10}$/.test(value)) return res.status(400).json({ error: 'Invalid ASN' });
  } else if (type === 'prefix') {
    if (!/^[\d.:a-fA-F/]+$/.test(value)) return res.status(400).json({ error: 'Invalid prefix' });
  } else {
    return res.status(400).json({ error: 'Invalid type' });
  }

  let url;
  if (type === 'asn') url = `https://api.bgpview.io/asn/${value}`;
  else if (type === 'asn_prefixes') url = `https://api.bgpview.io/asn/${value}/prefixes`;
  else url = `https://api.bgpview.io/prefix/${value}`;

  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'X-VERDIKT/1.0 (github.com/h3ad-sec)', 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'BGPView request failed', detail: e.message });
  }
}
