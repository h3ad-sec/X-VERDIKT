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

  const hdrs = { 'Accept': 'application/json', 'User-Agent': 'X-VERDIKT/1.0' };

  try {
    if (type === 'asn') {
      const r = await fetch(
        `https://stat.ripe.net/data/as-overview/data.json?resource=AS${value}&sourceapp=x-verdikt`,
        { headers: hdrs, signal: AbortSignal.timeout(10000) }
      );
      if (!r.ok) return res.status(r.status).json({ error: `RIPE Stat ${r.status}` });
      const json = await r.json();
      const block = json.data?.block || {};
      return res.status(200).json({
        status: 'ok',
        data: {
          asn:               parseInt(value, 10),
          name:              block.name              || null,
          description_short: block.desc              || null,
          description_long:  block.desc              || null,
          country_code:      block.country           || null,
          rir_name:          null,
          website:           null,
          abuse_contacts:    [],
        }
      });
    }

    if (type === 'asn_prefixes') {
      const r = await fetch(
        `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${value}&sourceapp=x-verdikt`,
        { headers: hdrs, signal: AbortSignal.timeout(10000) }
      );
      if (!r.ok) return res.status(r.status).json({ error: `RIPE Stat ${r.status}` });
      const json = await r.json();
      const all = (json.data?.prefixes || []).map(p => ({ prefix: p.prefix }));
      return res.status(200).json({
        status: 'ok',
        data: {
          ipv4_prefixes: all.filter(p => p.prefix.includes('.')),
          ipv6_prefixes: all.filter(p => p.prefix.includes(':')),
        }
      });
    }

    // type === 'prefix'
    const r = await fetch(
      `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(value)}&sourceapp=x-verdikt`,
      { headers: hdrs, signal: AbortSignal.timeout(10000) }
    );
    if (!r.ok) return res.status(r.status).json({ error: `RIPE Stat ${r.status}` });
    const json = await r.json();
    const d     = json.data  || {};
    const block = d.block    || {};
    const asns  = (d.asns || []).map(a => ({
      asn:         a.asn,
      name:        a.holder || null,
      description: a.holder || null,
    }));
    return res.status(200).json({
      status: 'ok',
      data: {
        prefix:      value,
        name:        block.name    || null,
        description: block.desc    || null,
        country_code: block.country || null,
        asns,
        rir_allocation: {
          rir_name:          null,
          date_allocated:    null,
          country_code:      block.country || null,
          allocation_status: null,
        },
      }
    });
  } catch (e) {
    return res.status(500).json({ error: 'ASN lookup failed', detail: e.message });
  }
}
