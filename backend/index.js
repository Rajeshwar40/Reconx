'use strict';

require('dotenv').config();

const os = require('os');

// ── Enrich PATH before requiring anything else ────────────────────────────────
// Node.js background processes on macOS inherit a stripped PATH.
// Prepend every directory where security tools (go install, brew) live.
const extraDirs = [
  `${os.homedir()}/go/bin`,
  `${process.env.GOPATH ? process.env.GOPATH + '/bin' : os.homedir() + '/go/bin'}`,
  `${os.homedir()}/.local/bin`,
  `${os.homedir()}/bin`,
  '/opt/homebrew/bin',
  '/opt/homebrew/sbin',
  '/usr/local/bin',
  '/usr/local/sbin',
  '/usr/bin', '/bin', '/usr/sbin', '/sbin',
];
process.env.PATH = [
  ...new Set([...extraDirs, ...(process.env.PATH || '').split(':').filter(Boolean)])
].join(':');

const express    = require('express');
const cors       = require('cors');
const { execSync } = require('child_process');
const { resolvePaths } = require('./utils/toolPaths');
const { requireApiKey } = require('./middleware/auth');
const scanRoutes = require('./routes/scan');

const app  = express();
const PORT = process.env.PORT || 2000;

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Scan routes ───────────────────────────────────────────────────────────────
// Gated by API_KEY when set (see backend/.env.example) — scans shell out to
// real recon tools against arbitrary domains, so this should not sit open
// on a public IP without it.
app.use('/api/scan',  requireApiKey, scanRoutes);

// ── List all scans ────────────────────────────────────────────────────────────
app.get('/api/scans', (req, res) => {
  const scanManager = require('./services/scanManager');
  res.json(scanManager.listScans());
});

// ── Tools check ───────────────────────────────────────────────────────────────
app.get('/api/tools/check', (req, res) => {
  const { paths, missing } = resolvePaths();
  res.json({ paths, missing, ready: missing.length === 0 });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', hostname: os.hostname(), ts: new Date().toISOString() });
});

// ── Connectivity ──────────────────────────────────────────────────────────────
app.get('/api/connectivity', (req, res) => {
  try { execSync('ping -c1 -W2 1.1.1.1', { stdio: 'ignore' }); res.json({ online: true }); }
  catch { res.json({ online: false }); }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const { paths, missing } = resolvePaths();
  const found = Object.entries(paths).filter(([,v]) => v).map(([k]) => k);

  console.log(`\n╔══════════════════════════════════════════════════════╗`);
  console.log(`║   ReconX Backend  •  Port ${PORT}                       ║`);
  console.log(`║   Powered by Rajeshwar Singh                         ║`);
  console.log(`╚══════════════════════════════════════════════════════╝\n`);
  console.log(`API:      http://localhost:${PORT}/api/health`);
  console.log(`Frontend: http://localhost:4000\n`);
  console.log(`Tools found:   ${found.join(', ') || 'none'}`);
  if (missing.length) console.log(`Tools missing: ${missing.join(', ')}`);
  console.log('');
});

module.exports = app;

// ── SSE test endpoint (debug) ─────────────────────────────────────────────────
// curl http://localhost:2000/api/sse-test
app.get('/api/sse-test', (req, res) => {
  res.setHeader('Content-Type',                'text/event-stream');
  res.setHeader('Cache-Control',               'no-cache');
  res.setHeader('Connection',                  'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();
  let i = 0;
  const t = setInterval(() => {
    res.write(`data: ${JSON.stringify({ tick: ++i, ts: new Date().toISOString() })}\n\n`);
    if (i >= 5) { clearInterval(t); res.end(); }
  }, 500);
  req.on('close', () => clearInterval(t));
});
