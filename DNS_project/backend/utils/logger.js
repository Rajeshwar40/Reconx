'use strict';

const fs   = require('fs');
const path = require('path');

/**
 * Append a timestamped line to a log file and optionally broadcast via SSE.
 */
function createLogger(logFile, sseBroadcast) {
  fs.mkdirSync(path.dirname(logFile), { recursive: true });

  function log(level, msg) {
    const ts   = new Date().toISOString();
    const line = `[${ts}] [${level.toUpperCase()}] ${msg}`;
    fs.appendFileSync(logFile, line + '\n');
    if (sseBroadcast) sseBroadcast({ type: 'log', level, msg, ts });
  }

  return {
    info:  (m) => log('info', m),
    warn:  (m) => log('warn', m),
    error: (m) => log('error', m),
    success: (m) => log('success', m),
  };
}

module.exports = { createLogger };
