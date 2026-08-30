'use strict';

/**
 * toolDetector.js
 * Finds security tool binaries by scanning known directories directly.
 * No shell, no `which` — works even when PATH is stripped in background processes.
 */

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

const toolCache = {};

function detectTool(name) {
  if (toolCache[name] !== undefined) return toolCache[name];

  for (const dir of UNIQUE_DIRS) {
    const full = path.join(dir, name);
    try {
      fs.accessSync(full, fs.constants.X_OK);
      toolCache[name] = full;
      return full;
    } catch { /* keep looking */ }
  }

  toolCache[name] = null;
  return null;
}

function checkAllTools() {
  const tools = ['subfinder', 'assetfinder', 'amass', 'httpx', 'dnsx', 'shuffledns', 'nuclei'];
  const result = {};
  for (const t of tools) {
    const p = detectTool(t);
    result[t] = { available: !!p, path: p || 'NOT FOUND' };
  }
  return result;
}

function getEnv() {
  return {
    ...process.env,
    PATH: [...UNIQUE_DIRS, ...(process.env.PATH || '').split(':').filter(Boolean)].join(':'),
    SHELL: '/bin/zsh',
  };
}

module.exports = { detectTool, checkAllTools, getEnv };
