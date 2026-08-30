/**
 * Process Runner - Safe child_process wrapper with streaming, timeout, retry
 */

const { spawn } = require("child_process");
const { getEnv } = require("./toolDetector");
const { appendLog } = require("./fileUtils");

/**
 * Run a command and collect stdout lines
 * @param {object} opts
 * @param {string} opts.cmd - Command path
 * @param {string[]} opts.args - Arguments
 * @param {string} opts.domain - Domain for logging
 * @param {function} opts.onLine - Called for each stdout line
 * @param {function} opts.onLog - Called for each log line (stderr/info)
 * @param {number} opts.timeout - Timeout in ms (default 300000 = 5min)
 * @param {string} opts.cwd - Working directory
 * @returns {Promise<string[]>} - Collected output lines
 */
function runCommand(opts) {
  const {
    cmd,
    args = [],
    domain,
    onLine,
    onLog,
    timeout = 300000,
    cwd,
  } = opts;

  return new Promise((resolve, reject) => {
    const lines = [];
    let killed = false;

    const log = (msg) => {
      if (onLog) onLog(msg);
      if (domain) appendLog(domain, msg).catch(() => {});
    };

    if (!cmd) {
      log(`[SKIP] Tool not found, skipping step`);
      return resolve([]);
    }

    const cmdName = cmd.split("/").pop();
    log(`[RUN] ${cmdName} ${args.join(" ")}`);

    let proc;
    try {
      proc = spawn(cmd, args, {
        env: getEnv(),
        shell: false,
        cwd: cwd || process.cwd(),
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      log(`[ERROR] Failed to spawn ${cmdName}: ${err.message}`);
      return resolve([]);
    }

    // Timeout handler
    const timer = setTimeout(() => {
      if (!killed) {
        killed = true;
        log(`[TIMEOUT] ${cmdName} exceeded ${timeout / 1000}s, killing`);
        try {
          proc.kill("SIGTERM");
          setTimeout(() => {
            try {
              proc.kill("SIGKILL");
            } catch {}
          }, 2000);
        } catch {}
      }
    }, timeout);

    // Buffer for partial lines
    let stdoutBuf = "";
    let stderrBuf = "";

    proc.stdout.on("data", (chunk) => {
      stdoutBuf += chunk.toString();
      const parts = stdoutBuf.split("\n");
      stdoutBuf = parts.pop(); // Keep incomplete line
      for (const line of parts) {
        const trimmed = line.trim();
        if (trimmed) {
          lines.push(trimmed);
          if (onLine) onLine(trimmed);
        }
      }
    });

    proc.stderr.on("data", (chunk) => {
      stderrBuf += chunk.toString();
      const parts = stderrBuf.split("\n");
      stderrBuf = parts.pop();
      for (const line of parts) {
        const trimmed = line.trim();
        if (trimmed) {
          log(`[${cmdName}] ${trimmed}`);
        }
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      log(`[ERROR] ${cmdName}: ${err.message}`);
      resolve(lines);
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      // Flush remaining buffer
      if (stdoutBuf.trim()) {
        lines.push(stdoutBuf.trim());
        if (onLine) onLine(stdoutBuf.trim());
      }
      log(`[DONE] ${cmdName} exited with code ${code}, got ${lines.length} lines`);
      resolve(lines);
    });
  });
}

/**
 * Run a command with retry on failure
 */
async function runWithRetry(opts, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    try {
      const result = await runCommand(opts);
      if (result.length > 0 || i === retries) return result;
    } catch (err) {
      if (i === retries) return [];
      await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    }
  }
  return [];
}

/**
 * Run multiple commands in parallel with concurrency limit
 */
async function runParallel(tasks, concurrency = 4) {
  const results = [];
  const queue = [...tasks];
  const active = new Set();

  async function runNext() {
    if (queue.length === 0) return;
    const task = queue.shift();
    active.add(task);
    try {
      const result = await task();
      results.push(result);
    } catch (err) {
      results.push([]);
    } finally {
      active.delete(task);
      await runNext();
    }
  }

  const workers = Array(Math.min(concurrency, tasks.length))
    .fill(null)
    .map(() => runNext());

  await Promise.all(workers);
  return results;
}

module.exports = { runCommand, runWithRetry, runParallel };
