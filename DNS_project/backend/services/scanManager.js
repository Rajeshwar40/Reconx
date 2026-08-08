'use strict';

const { EventEmitter } = require('events');
const { v4: uuidv4 }  = require('uuid');
const os              = require('os');
const fs              = require('fs');

const { createLogger }   = require('../utils/logger');
const { resolvePaths }   = require('../utils/toolPaths');
const { runEnumeration } = require('./enumeration');

class ScanManager extends EventEmitter {
  constructor() {
    super();
    this.scans  = new Map();
    this._tools = null;
  }

  getTools() {
    if (!this._tools) {
      const { paths, missing } = resolvePaths();
      this._tools = paths;
      if (missing.length) console.warn(`[ScanManager] Missing tools: ${missing.join(', ')}`);
    }
    return this._tools;
  }

  startScan(domain) {
    // Concurrent scans of the same domain would share the same on-disk
    // output path (~/recon/<domain>/logs.txt, all_subdomains.txt) and
    // corrupt each other's files — reuse the in-flight scan instead.
    for (const existing of this.scans.values()) {
      if (existing.domain === domain && (existing.status === 'running' || existing.status === 'stopping')) {
        return { scanId: existing.scanId, reused: true };
      }
    }

    const scanId  = uuidv4();
    const logFile = `${os.homedir()}/recon/${domain}/logs.txt`;
    fs.mkdirSync(`${os.homedir()}/recon/${domain}`, { recursive: true });

    const cancelToken = { cancelled: false, paused: false };

    const scan = {
      scanId,
      domain,
      status:    'running',
      startedAt: Date.now(),
      clients:   new Set(),
      events:    [],
      result:    null,
      cancelToken,
      progress:  0,
    };
    this.scans.set(scanId, scan);

    const broadcast = (evt) => {
      // Track progress
      if (evt.type === 'progress') scan.progress = evt.progress;
      scan.events.push(evt);
      for (const client of scan.clients) {
        try { client.write(`data: ${JSON.stringify(evt)}\n\n`); } catch {}
      }
    };

    const logger = createLogger(logFile, broadcast);

    // Small delay so SSE client connects before events fire
    setTimeout(async () => {
      try {
        const tools  = this.getTools();
        const result = await runEnumeration(domain, tools, logger, broadcast, cancelToken);
        if (result === null) {
          scan.status = 'cancelled';
          broadcast({ type: 'status', status: 'cancelled' });
        } else {
          scan.result = result;
          scan.status = 'done';
          broadcast({ type: 'status', status: 'done' });
        }
      } catch (err) {
        console.error('[ScanManager]', err);
        logger.error(`Scan failed: ${err.message}`);
        scan.status = 'error';
        broadcast({ type: 'status', status: 'error', msg: err.message });
      }
    }, 600);

    return { scanId, reused: false };
  }

  stopScan(scanId) {
    const scan = this.scans.get(scanId);
    if (!scan) return false;
    scan.cancelToken.cancelled = true;
    scan.status = 'stopping';
    return true;
  }

  getScan(scanId)   { return this.scans.get(scanId) || null; }

  addClient(scanId, res) {
    const scan = this.scans.get(scanId);
    if (!scan) return false;
    scan.clients.add(res);
    // Replay all past events
    for (const evt of scan.events) {
      try { res.write(`data: ${JSON.stringify(evt)}\n\n`); } catch {}
    }
    return true;
  }

  removeClient(scanId, res) {
    const scan = this.scans.get(scanId);
    if (scan) scan.clients.delete(res);
  }

  listScans() {
    return [...this.scans.values()].map(({ scanId, domain, status, startedAt, progress }) =>
      ({ scanId, domain, status, startedAt, progress })
    );
  }

  getResults(scanId) {
    const scan = this.scans.get(scanId);
    if (!scan) return null;
    return { scanId: scan.scanId, domain: scan.domain, status: scan.status, result: scan.result };
  }
}

module.exports = new ScanManager();
