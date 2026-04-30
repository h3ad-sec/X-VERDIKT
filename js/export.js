
/* ── X-VERDIKT Export Engine ─────────────────────────────────────────────── */

function getExportRows(order) {
  let rows = scanResults.filter(r => r.done);
  if (order === 'verdict') {
    const v = ['malicious', 'suspicious', 'unknown', 'benign'];
    rows = [...rows].sort((a, b) => v.indexOf(a.verdict || 'unknown') - v.indexOf(b.verdict || 'unknown'));
  } else if (order === 'type') {
    rows = [...rows].sort((a, b) => a.ioc.type.localeCompare(b.ioc.type));
  }
  return rows;
}

function rowToFlat(entry) {
  const srcVal = (src, skippedLabel, fn) => {
    if (!src) return '';
    if (src.skipped) return '—';
    if (src.error)   return `Error: ${src.error}`;
    return fn(src) || '';
  };
  return {
    'IOC':          entry.ioc.value,
    'Type':         entry.ioc.label,
    'Verdict':      entry.verdict    || '',
    'Score':        entry.score      ?? '',
    'Confidence':   entry.confidence || '',
    'Action':       entry.action     || '',
    'VT Det':       srcVal(entry.vt,  '—', s => `${s.malicious||0}/${s.total||0}`),
    'VT Pts':       entry.vtPts ?? '',
    'AbuseIPDB':    srcVal(entry.ab,  '—', s => `${s.score||0}%`),
    'AB Pts':       entry.abPts ?? '',
    'OTX Pulses':   srcVal(entry.otx, '—', s => s.pulseCount ?? 0),
    'OTX Pts':      entry.otxPts ?? '',
    'ThreatFox':    srcVal(entry.threatfox, '—', s => s.notFound ? 'Not found' : `${s.iocCount} C2`),
    'TF Pts':       entry.tfPts ?? '',
    'URLScan':      srcVal(entry.urlscan, '—', s => s.notFound ? 'Not found' : `${s.maliciousCount||0}/${s.total||0} mal`),
    'US Pts':       entry.usPts ?? '',
    'URLhaus':      srcVal(entry.urlhaus, '—', s => s.notFound ? 'Not found' : `${s.urlsCount||0} URLs`),
    'UH Pts':       entry.uhPts ?? '',
    'MalwareBazaar':srcVal(entry.mb, '—', s => s.notFound ? 'Not found' : `${s.count||0} samples`),
    'MB Pts':       entry.mbPts ?? '',
    'HybridAnalysis':srcVal(entry.ha, '—', s => s.notFound ? 'No hits' : `${s.count||0} hits`),
    'HA Pts':       entry.haPts ?? '',
    'FileScan':     srcVal(entry.filescan, '—', s => s.notFound ? 'Not found' : `${s.count||0} reports (TL:${s.maxThreatLevel||0})`),
    'FS Pts':       entry.fsPts ?? '',
    'Shodan':       srcVal(entry.shodan, '—', s => s.cves?.length ? `${s.cves.length} CVEs` : `${s.ports?.length||0} ports`),
    'Flags':        (entry.flags   || []).join(', '),
    'Reasons':      (entry.reasons || []).join(' | '),
  };
}

function downloadFile(content, filename, mimeType) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function expDateTag() { return new Date().toISOString().slice(0, 10); }

/* ── CSV ──────────────────────────────────────────────────────────────────── */
function exportCSV(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const flat = rows.map(rowToFlat);
  const headers = Object.keys(flat[0]);
  const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [
    headers.map(escape).join(','),
    ...flat.map(r => headers.map(h => escape(r[h])).join(',')),
  ];
  downloadFile('﻿' + lines.join('\r\n'), `x-verdikt-${order}-${expDateTag()}.csv`, 'text/csv;charset=utf-8;');
  showToast(`CSV exported — ${rows.length} row${rows.length !== 1 ? 's' : ''}`, 'success');
}

/* ── JSON ─────────────────────────────────────────────────────────────────── */
function exportJSON(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  let out;
  if (order === 'verdict') {
    out = {};
    for (const r of rows) { const k = r.verdict || 'unknown'; (out[k] = out[k] || []).push(rowToFlat(r)); }
  } else if (order === 'type') {
    out = {};
    for (const r of rows) { const k = r.ioc.type; (out[k] = out[k] || []).push(rowToFlat(r)); }
  } else {
    out = rows.map(rowToFlat);
  }
  downloadFile(JSON.stringify(out, null, 2), `x-verdikt-${order}-${expDateTag()}.json`, 'application/json');
  showToast(`JSON exported — ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Markdown ─────────────────────────────────────────────────────────────── */
function exportMarkdown(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const cols = ['IOC', 'Type', 'Verdict', 'Score', 'Action', 'Reasons'];
  const esc  = v => String(v ?? '—').replace(/\|/g, '\\|');
  const mkTable = list => {
    const hdr = '| ' + cols.join(' | ') + ' |';
    const sep = '| ' + cols.map(() => '---').join(' | ') + ' |';
    const body = list.map(r => '| ' + cols.map(c => esc(rowToFlat(r)[c])).join(' | ') + ' |').join('\n');
    return `${hdr}\n${sep}\n${body}`;
  };
  let md = `# X-VERDIKT Export\n_Generated: ${new Date().toISOString()}_\n\n`;
  if (order === 'verdict' || order === 'type') {
    const groups = {};
    for (const r of rows) {
      const k = order === 'verdict' ? (r.verdict || 'unknown') : r.ioc.type;
      (groups[k] = groups[k] || []).push(r);
    }
    md += Object.entries(groups).map(([k, rs]) => `## ${k.toUpperCase()} (${rs.length})\n\n${mkTable(rs)}`).join('\n\n');
  } else {
    md += mkTable(rows);
  }
  downloadFile(md, `x-verdikt-${order}-${expDateTag()}.md`, 'text/markdown;charset=utf-8;');
  showToast(`Markdown exported — ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Excel (HTML table → .xls) ───────────────────────────────────────────── */
function exportExcel(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const flat = rows.map(rowToFlat);
  const headers = Object.keys(flat[0]);
  const esc = v => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  let html = `<html><head><meta charset="UTF-8"></head><body><table>`;
  if (order === 'verdict' || order === 'type') {
    const groups = {};
    for (const r of rows) {
      const k = order === 'verdict' ? (r.verdict || 'unknown') : r.ioc.type;
      (groups[k] = groups[k] || []).push(rowToFlat(r));
    }
    for (const [k, rs] of Object.entries(groups)) {
      html += `<tr><td colspan="${headers.length}" style="background:#1a2238;color:#00ff9f;font-weight:bold">${esc(k.toUpperCase())} (${rs.length})</td></tr>`;
      html += `<tr>${headers.map(h => `<th style="background:#0b0f1a;font-weight:bold">${esc(h)}</th>`).join('')}</tr>`;
      html += rs.map(r => `<tr>${headers.map(h => `<td>${esc(r[h])}</td>`).join('')}</tr>`).join('');
    }
  } else {
    html += `<tr>${headers.map(h => `<th style="background:#0b0f1a;font-weight:bold">${esc(h)}</th>`).join('')}</tr>`;
    html += flat.map(r => `<tr>${headers.map(h => `<td>${esc(r[h])}</td>`).join('')}</tr>`).join('');
  }
  html += `</table></body></html>`;
  downloadFile(new Blob([html], { type: 'application/vnd.ms-excel;charset=utf-8;' }), `x-verdikt-${order}-${expDateTag()}.xls`, 'application/vnd.ms-excel');
  showToast(`Excel exported — ${rows.length} row${rows.length !== 1 ? 's' : ''}`, 'success');
}

/* ── Export modal ────────────────────────────────────────────────────────── */
function openExportModal() {
  if (!scanResults.filter(r => r.done).length) {
    showToast('No completed results to export', 'error');
    return;
  }
  document.getElementById('export-modal')?.classList.add('open');
}

function closeExportModal(e) {
  if (e && e.target !== document.getElementById('export-modal')) return;
  document.getElementById('export-modal')?.classList.remove('open');
}

function doExport() {
  const fmt   = document.querySelector('input[name="exp-fmt"]:checked')?.value   || 'csv';
  const order = document.querySelector('input[name="exp-order"]:checked')?.value || 'serial';
  document.getElementById('export-modal')?.classList.remove('open');
  if (fmt === 'csv')  exportCSV(order);
  else if (fmt === 'json') exportJSON(order);
  else if (fmt === 'md')   exportMarkdown(order);
  else if (fmt === 'xls')  exportExcel(order);
}
