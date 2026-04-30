export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.HYBRIDANALYSIS_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'HYBRIDANALYSIS_API_KEY not configured' });

  const { ip, hash, htype } = req.query;

  try {
    let formBody;

    if (ip) {
      if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip))
        return res.status(400).json({ error: 'Invalid IP format' });
      formBody = `terms[network_ip]=${encodeURIComponent(ip)}`;

    } else if (hash && htype) {
      const htypeMap = { md5: 32, sha1: 40, sha256: 64 };
      const expectedLen = htypeMap[htype];
      if (!expectedLen)
        return res.status(400).json({ error: 'htype must be md5, sha1, or sha256' });
      if (!/^[0-9a-fA-F]+$/.test(hash) || hash.length !== expectedLen)
        return res.status(400).json({ error: `Invalid ${htype} hash format` });

      const h = hash.toLowerCase();
      const haHeaders = {
        'api-key': apiKey, 'User-Agent': 'Falcon Sandbox', 'accept': 'application/json',
      };

      if (htype === 'sha256') {
        /* Direct overview lookup — same endpoint used by the HA console */
        const upstream = await fetch(
          `https://www.hybrid-analysis.com/api/v2/overview/${h}`,
          { method: 'GET', headers: haHeaders }
        );
        if (upstream.status === 404 || upstream.status === 400)
          return res.status(200).json({ count: 0, result: [] });
        if (!upstream.ok) return res.status(200).json({ count: 0, result: [] });
        const data = await upstream.json();
        /* Normalize: overview has a top-level object + reports[]; wrap for consistent parsing */
        const reports = (data.reports && data.reports.length) ? data.reports : [data];
        return res.status(200).json({ count: reports.length, result: reports });
      }

      /* MD5 / SHA1 — use search/hash */
      formBody = `hash=${encodeURIComponent(h)}`;

    } else {
      return res.status(400).json({ error: 'Missing parameter: ip, or hash+htype' });
    }

    const upstream = await fetch('https://www.hybrid-analysis.com/api/v2/search/hash', {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Falcon Sandbox',
        'accept': 'application/json',
      },
      body: formBody,
    });
    if (upstream.status === 404 || upstream.status === 400)
      return res.status(200).json({ count: 0, result: [] });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
