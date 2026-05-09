# X-VERDIKT

Deep IOC enrichment across 11+ threat intelligence sources. No API key management — managed mode only.

Live: [h3ad-sec.github.io/X-VERDIKT](https://h3ad-sec.github.io/X-VERDIKT/)

---

## Modes

### Standard Enrichment

Supports IP, domain, URL, and hash (MD5 / SHA1 / SHA256 / SHA512). Paste IOCs or upload a file (.txt, .csv, .md, .json, .xlsx).

**Sources by type:**

| Source | IP | Domain | URL | Hash |
|---|---|---|---|---|
| VirusTotal | 30 pts | 50 pts | 50 pts | 25 pts |
| AbuseIPDB | 40 pts | — | — | — |
| OTX | 10 pts | 10 pts | 10 pts | 10 pts |
| ThreatFox | 20 pts | 20 pts | — | 10 pts |
| URLScan | — | 20 pts | 20 pts | — |
| URLhaus | — | — | 20 pts | — |
| MalwareBazaar | — | — | — | 10 pts |
| HybridAnalysis | — | — | — | 20 pts |
| FileScan.io | — | — | — | 25 pts |
| Shodan | supplementary | — | — | — |

Results: verdict + score, per-source raw values, detail modal, and export to CSV / JSON / Markdown / Excel.

---

### IP Intel Mode

IP-only deep enrichment. Produces a dedicated table with geolocation, network, and privacy context alongside threat data.

**Sources:** IPLocate · AbuseIPDB · VirusTotal · OTX · ThreatFox

**Table columns:**

| Column | Source |
|---|---|
| AbuseIPDB score | AbuseIPDB |
| VT detections | VirusTotal |
| OTX pulses | OTX |
| ThreatFox hits | ThreatFox |
| Country | IPLocate |
| Organization | IPLocate |
| Domain | IPLocate → AbuseIPDB fallback |
| Privacy flags | IPLocate (`ABUSER · TOR · BOGON · VPN · PROXY · ANON · HOSTING · iCLOUD`) |

**Copy:** KV format for ≤ 5 IPs; TSV for > 5.  
**Export:** Excel / TSV with context fields (AB confidence + reports, VT engine counts, OTX pulses, ThreatFox hits).

---

## Stack

- Frontend: static HTML/CSS/JS — GitHub Pages
- Backend: Vercel serverless proxies (`/api/`) — one file per source
- No build step, no framework

## File structure

```
X-VERDIKT/
├── index.html
├── css/style.css
├── js/
│   ├── ioc-parser.js   — multi-type IOC parser with defang support
│   ├── api.js          — source integrations + response parsers
│   ├── scanner.js      — parallel scan engine (standard + IP Intel)
│   ├── ui.js           — table/modal rendering, copy/export helpers
│   ├── export.js       — CSV/JSON/Markdown/Excel export
│   └── app.js          — init, server status probe, file upload
└── api/
    ├── vt.js · abuseipdb.js · otx.js · urlscan.js · threatfox.js
    ├── urlhaus.js · malwarebazaar.js · hybridanalysis.js
    ├── shodan.js · filescan.js · iplocate.js · status.js
```

---

Part of [H3AD-SEC](https://h3ad-sec.github.io/) — H3AD-X suite.
