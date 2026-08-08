'use strict';

const express     = require('express');
const router      = express.Router();
const scanManager = require('../services/scanManager');
const { validateDomain } = require('../utils/validator');
const fs   = require('fs');
const os   = require('os');
const path = require('path');

// POST /api/scan
router.post('/', (req, res) => {
  const raw = req.body.domain || '';
  const { valid, domain, error } = validateDomain(raw);
  if (!valid) return res.status(400).json({ error });
  const scanId = scanManager.startScan(domain);
  return res.json({ scanId, domain, status: 'started' });
});

// POST /api/scan/:scanId/stop
router.post('/:scanId/stop', (req, res) => {
  const ok = scanManager.stopScan(req.params.scanId);
  if (!ok) return res.status(404).json({ error: 'Scan not found' });
  res.json({ status: 'stopping' });
});

// GET /api/scan/:scanId/events — SSE (direct connection)
router.get('/:scanId/events', (req, res) => {
  res.setHeader('Content-Type',                'text/event-stream');
  res.setHeader('Cache-Control',               'no-cache');
  res.setHeader('Connection',                  'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('X-Accel-Buffering',           'no');
  res.flushHeaders();

  const ok = scanManager.addClient(req.params.scanId, res);
  if (!ok) {
    res.write(`data: ${JSON.stringify({ type: 'error', msg: 'Scan not found' })}\n\n`);
    return res.end();
  }

  const heartbeat = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(heartbeat); }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    scanManager.removeClient(req.params.scanId, res);
  });
});

// GET /api/scan/:scanId/status
router.get('/:scanId/status', (req, res) => {
  const scan = scanManager.getScan(req.params.scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json({ scanId: scan.scanId, domain: scan.domain, status: scan.status, progress: scan.progress });
});

// GET /api/scan/:scanId/results
router.get('/:scanId/results', (req, res) => {
  const data = scanManager.getResults(req.params.scanId);
  if (!data) return res.status(404).json({ error: 'Scan not found' });
  res.json(data);
});

// GET /api/scan/:scanId/export — HTML export
router.get('/:scanId/export', (req, res) => {
  const data = scanManager.getResults(req.params.scanId);
  if (!data || !data.result) return res.status(404).json({ error: 'No results yet' });
  const rows = data.result.finalData || [];
  const domain = data.domain;
  const ts = new Date().toLocaleString();

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>ReconX Report — ${domain}</title>
<style>
  body { font-family: monospace; background: #080c10; color: #e6edf3; margin: 0; padding: 24px; }
  h1 { color: #00e5ff; } h2 { color: #8b949e; font-size: 13px; margin-top: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 16px; }
  th { background: #0d1117; color: #8b949e; padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  td { padding: 7px 12px; border-bottom: 1px solid #161b22; vertical-align: top; }
  tr:hover td { background: #0d1117; }
  .ok { color: #00c853; } .warn { color: #ff9800; } .danger { color: #ff4444; }
  .badge { background: rgba(0,229,255,0.12); color: #00e5ff; border-radius: 3px; padding: 1px 6px; font-size: 10px; }
  .to { background: rgba(255,68,68,0.12); color: #ff4444; }
  .summary { display: flex; gap: 32px; margin: 16px 0 24px; }
  .stat { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 12px 20px; }
  .stat-n { font-size: 28px; font-weight: 700; color: #00e5ff; }
  .stat-l { font-size: 11px; color: #8b949e; margin-top: 2px; }
</style></head>
<body>
<h1>🔍 ReconX Report</h1>
<h2>Domain: ${domain} &nbsp;|&nbsp; Generated: ${ts} &nbsp;|&nbsp; Total: ${rows.length} subdomains</h2>
<div class="summary">
  <div class="stat"><div class="stat-n">${rows.length}</div><div class="stat-l">Total Subdomains</div></div>
  <div class="stat"><div class="stat-n ok">${rows.filter(r=>r.resolved).length}</div><div class="stat-l">DNS Resolved</div></div>
  <div class="stat"><div class="stat-n" style="color:#7c3aed">${rows.filter(r=>r.probed).length}</div><div class="stat-l">HTTP Probed</div></div>
  <div class="stat"><div class="stat-n warn">${rows.filter(r=>r.is404).length}</div><div class="stat-l">404 Responses</div></div>
  <div class="stat"><div class="stat-n warn">${rows.filter(r=>r.hasCname).length}</div><div class="stat-l">Has CNAME</div></div>
  <div class="stat"><div class="stat-n danger">${rows.filter(r=>r.takeover).length}</div><div class="stat-l">Takeovers</div></div>
</div>
<table>
<thead><tr>
  <th>Subdomain</th><th>IP (A)</th><th>CNAME</th><th>Status</th><th>Title</th><th>Tech</th><th>RTT</th><th>MX</th><th>Flags</th>
</tr></thead>
<tbody>
${rows.map(r => `<tr>
  <td><a href="${r.url}" target="_blank" style="color:#00e5ff;text-decoration:none">${r.subdomain}</a></td>
  <td>${(r.records?.A||[]).join('<br>') || r.ip || '—'}</td>
  <td style="font-size:10px;color:#ff9800">${r.cnameChain || '—'}</td>
  <td class="${r.status>=500?'danger':r.status>=400?'warn':r.status>=200?'ok':''}">${r.status||'—'}</td>
  <td>${r.title||'—'}</td>
  <td style="font-size:10px">${r.tech||'—'}</td>
  <td style="font-size:10px;color:#8b949e">${r.responseTime||'—'}</td>
  <td style="font-size:10px">${(r.records?.MX||[]).join('<br>')||'—'}</td>
  <td>
    ${r.takeover?'<span class="badge to">⚠ TAKEOVER</span>':''}
    ${r.is404?'<span class="badge" style="background:rgba(255,152,0,.12);color:#ff9800">404</span>':''}
    ${r.hasCname?'<span class="badge">CNAME</span>':''}
    ${r.isWildcard?'<span class="badge" style="color:#a78bfa">WILDCARD</span>':''}
  </td>
</tr>`).join('\n')}
</tbody></table>
</body></html>`;

  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Content-Disposition', `attachment; filename="reconx-${domain}-${Date.now()}.html"`);
  res.send(html);
});

// GET /api/scan/:scanId/file/:filename
router.get('/:scanId/file/:filename', (req, res) => {
  const scan = scanManager.getScan(req.params.scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  const ALLOWED = ['all_subdomains.txt', 'logs.txt', 'final.json'];
  const { filename } = req.params;
  if (!ALLOWED.includes(filename)) return res.status(400).json({ error: 'Not allowed' });
  const fp = path.join(os.homedir(), 'recon', scan.domain, filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Not yet available' });
  res.sendFile(fp);
});

module.exports = router;
