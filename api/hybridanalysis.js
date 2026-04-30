export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.HYBRIDANALYSIS_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'HYBRIDANALYSIS_API_KEY not configured' });

  const { ip, hash, htype } = req.query;
  const headers = { 'api-key': apiKey, 'User-Agent': 'Falcon Sandbox', 'accept': 'application/json' };

  try {
    if (ip) {
      if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip))
        return res.status(400).json({ error: 'Invalid IP format' });
      const upstream = await fetch('https://www.hybrid-analysis.com/api/v2/search/terms', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `terms[network_ip]=${encodeURIComponent(ip)}`,
      });
      if (!upstream.ok) return res.status(200).json({ count: 0, result: [] });
      return res.status(200).json(await upstream.json());

    } else if (hash && htype) {
      const htypeMap = { md5: 32, sha1: 40, sha256: 64 };
      const expectedLen = htypeMap[htype];
      if (!expectedLen)
        return res.status(400).json({ error: 'htype must be md5, sha1, or sha256' });
      if (!/^[0-9a-fA-F]+$/.test(hash) || hash.length !== expectedLen)
        return res.status(400).json({ error: `Invalid ${htype} hash format` });

      /* GET /search/hash?hash=VALUE — recommended endpoint, accepts MD5/SHA1/SHA256/SHA512 */
      const upstream = await fetch(
        `https://www.hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(hash.toLowerCase())}`,
        { method: 'GET', headers }
      );
      if (upstream.status === 404 || upstream.status === 400)
        return res.status(200).json({ count: 0, result: [] });
      if (!upstream.ok) return res.status(200).json({ count: 0, result: [] });
      return res.status(200).json(await upstream.json());

    } else {
      return res.status(400).json({ error: 'Missing parameter: ip, or hash+htype' });
    }
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
