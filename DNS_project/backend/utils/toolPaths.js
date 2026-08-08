'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const SEARCH_DIRS = [
  path.join(os.homedir(), 'go', 'bin'),
  path.join(process.env.GOPATH || path.join(os.homedir(), 'go'), 'bin'),
  path.join(os.homedir(), '.local', 'bin'),
  path.join(os.homedir(), 'bin'),
  '/opt/homebrew/bin',
  '/opt/homebrew/sbin',
  '/usr/local/bin',
  '/usr/local/sbin',
  '/usr/bin',
  '/bin',
];

const UNIQUE_DIRS = [...new Set(SEARCH_DIRS)];

// Build enriched PATH string — used by all child_process spawns
const ENRICHED_PATH = [
  ...UNIQUE_DIRS,
  ...(process.env.PATH || '').split(':').filter(Boolean),
].join(':');

function findTool(name) {
  for (const dir of UNIQUE_DIRS) {
    const full = path.join(dir, name);
    try { fs.accessSync(full, fs.constants.X_OK); return full; } catch {}
  }
  return null;
}

const REQUIRED_TOOLS = ['subfinder', 'assetfinder', 'amass', 'dnsx', 'httpx', 'nuclei'];
const OPTIONAL_TOOLS = ['shuffledns'];

function resolvePaths() {
  const paths   = {};
  const missing = [];
  for (const t of REQUIRED_TOOLS) {
    const p = findTool(t);
    if (p) paths[t] = p; else missing.push(t);
  }
  for (const t of OPTIONAL_TOOLS) {
    paths[t] = findTool(t) || null;
  }
  return { paths, missing };
}

function getEnrichedEnv() {
  return { ...process.env, PATH: ENRICHED_PATH };
}

module.exports = { resolvePaths, findTool, getEnrichedEnv, ENRICHED_PATH };
