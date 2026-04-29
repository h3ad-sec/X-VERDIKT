
document.addEventListener('DOMContentLoaded', async () => {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const btn = document.getElementById('scan-btn');
      if (!btn?.disabled) startScan();
    }
  });

  await detectServerStatus();
  loadSavedKeys();
  updateStatusDots();
});

async function detectServerStatus() {
  const isStatic = ['github.io','netlify.app','pages.dev'].some(h => location.hostname.endsWith(h));
  const statusUrl = isStatic ? 'https://x-verdikt.vercel.app/api/status' : '/api/status';
  try {
    const resp = await fetch(statusUrl, { signal: AbortSignal.timeout(4000) });
    if (resp.ok) {
      const status = await resp.json();
      if (status.mode === 'server') {
        window._serverVTPaid = status.vt_paid === true;
        setServerStatusDots(status);
        const rn = document.getElementById('rate-note-text');
        if (rn) rn.textContent = status.vt_paid ? 'VT Paid — fully parallel' : 'VT Free — token bucket';
        const active = ['vt','abuseipdb','otx'].filter(k => status[k]).length;
        showToast(`Server online — ${active}/3 primary sources configured`, active >= 2 ? 'success' : 'warning');
        return;
      }
    }
  } catch(e) { /* server not available */ }
  showToast('Server not reachable — deploy to Vercel and configure env vars', 'warning');
}

function handleDragOver(e)  { e.preventDefault(); document.getElementById('upload-zone')?.classList.add('dragover'); }
function handleDragLeave()  { document.getElementById('upload-zone')?.classList.remove('dragover'); }
function handleDrop(e) { e.preventDefault(); document.getElementById('upload-zone')?.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if (f) processFile(f); }
function handleFileUpload(e) { const f = e.target.files[0]; if (f) processFile(f); e.target.value = ''; }

function processFile(file) {
  const badge = document.getElementById('upload-badge');
  if (badge) { badge.textContent = file.name; badge.style.display = ''; }
  const r = new FileReader();
  r.onload = e => {
    const firstTab = document.querySelector('.input-tab');
    if (firstTab) switchInputTab('text', firstTab);
    document.getElementById('ip-input').value = e.target.result;
    parseIPsRealtime();
    showToast('File loaded', 'success');
  };
  r.readAsText(file);
}
