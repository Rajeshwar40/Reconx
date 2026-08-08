/**
 * Resolution Service
 * DNS resolution via dnsx + HTTP probing via httpx
 */

const path = require("path");
const fs = require("fs-extra");
const { detectTool } = require("../utils/toolDetector");
const { runCommand } = require("../utils/processRunner");
const {
  getDomainDir,
  ensureReconDir,
  readLines,
  writeLines,
  appendLog,
} = require("../utils/fileUtils");
const { sanitizeForShell } = require("../utils/validator");

/**
 * DNS resolution using dnsx
 * Returns array of resolved hostnames
 */
async function resolveDNS(domain, emitLog) {
  const dir = await ensureReconDir(domain);
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  const dnsx = detectTool("dnsx");
  if (!dnsx) {
    log(`[WARN] dnsx not found, skipping DNS resolution`);
    // Fall back to using all_subdomains.txt as live.txt
    const allSubsFile = path.join(dir, "all_subdomains.txt");
    const liveFile = path.join(dir, "live.txt");
    const subs = await readLines(allSubsFile);
    await writeLines(liveFile, subs);
    return subs;
  }

  const allSubsFile = path.join(dir, "all_subdomains.txt");
  const liveFile = path.join(dir, "live.txt");
  const resolvedSubs = [];

  log(`[DNS] Resolving subdomains with dnsx...`);

  await runCommand({
    cmd: dnsx,
    args: [
      "-l", allSubsFile,
      "-silent",
      "-resp",
      "-t", "100",
      "-retry", "2",
      "-timeout", "5",
      "-a",
      "-aaaa",
      "-cname",
    ],
    domain,
    onLine: (line) => {
      // dnsx output: subdomain [IP]
      const parts = line.split(/\s+/);
      const hostname = parts[0];
      if (hostname && hostname.length > 0) {
        resolvedSubs.push(hostname.trim().toLowerCase());
      }
    },
    onLog: log,
    timeout: 300000,
  });

  const unique = [...new Set(resolvedSubs)];
  await writeLines(liveFile, unique);
  log(`[DNS] ${unique.length} subdomains resolved`);
  return unique;
}

/**
 * HTTP probing using httpx
 * Returns array of enriched host objects
 */
async function probeHTTP(domain, emitLog) {
  const dir = await ensureReconDir(domain);
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  const httpx = detectTool("httpx");
  if (!httpx) {
    log(`[WARN] httpx not found, skipping HTTP probing`);
    return [];
  }

  const liveFile = path.join(dir, "live.txt");
  const finalJsonFile = path.join(dir, "final.json");
  const results = [];

  log(`[HTTP] Probing live subdomains with httpx...`);

  await runCommand({
    cmd: httpx,
    args: [
      "-l", liveFile,
      "-silent",
      "-json",
      "-status-code",
      "-title",
      "-tech-detect",
      "-ip",
      "-cname",
      "-response-time",
      "-follow-redirects",
      "-timeout", "10",
      "-retries", "2",
      "-threads", "50",
      "-rate-limit", "100",
    ],
    domain,
    onLine: (line) => {
      try {
        const parsed = JSON.parse(line);
        if (parsed && parsed.url) {
          results.push(normalizeHttpxResult(parsed));
        }
      } catch {
        // Not JSON, skip
      }
    },
    onLog: log,
    timeout: 600000,
  });

  // Write JSONL
  const jsonLines = results.map((r) => JSON.stringify(r)).join("\n");
  await fs.writeFile(finalJsonFile, jsonLines + "\n", "utf8");
  log(`[HTTP] ${results.length} live HTTP hosts probed`);
  return results;
}

/**
 * Normalize httpx JSON result to our schema
 */
function normalizeHttpxResult(raw) {
  return {
    url: raw.url || "",
    host: raw.host || extractHost(raw.url),
    ip: raw.host_ip || raw.a?.[0] || "",
    status_code: raw.status_code || 0,
    title: raw.title || "",
    tech: Array.isArray(raw.technologies)
      ? raw.technologies
      : Array.isArray(raw.tech)
      ? raw.tech
      : [],
    cname: Array.isArray(raw.cnames) ? raw.cnames : raw.cname ? [raw.cname] : [],
    response_time: raw.response_time || "",
    content_length: raw.content_length || 0,
    webserver: raw.webserver || "",
    scheme: raw.scheme || "https",
    port: raw.port || (raw.scheme === "http" ? 80 : 443),
    takeover: false,
    takeover_details: null,
    scanned_at: new Date().toISOString(),
  };
}

function extractHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "";
  }
}

module.exports = { resolveDNS, probeHTTP };
