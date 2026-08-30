/**
 * Enumeration Service
 * Runs passive + active subdomain discovery in parallel
 */

const path = require("path");
const { detectTool } = require("../utils/toolDetector");
const { runCommand, runWithRetry } = require("../utils/processRunner");
const {
  getDomainDir,
  ensureReconDir,
  appendLines,
  writeLines,
  appendLog,
  ensureResolvers,
} = require("../utils/fileUtils");
const { sanitizeForShell } = require("../utils/validator");

/**
 * Run passive enumeration (subfinder, assetfinder, amass passive)
 * All run in parallel
 */
async function runPassiveEnum(domain, emitLog) {
  const safeDomain = sanitizeForShell(domain);
  const dir = await ensureReconDir(domain);
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  log(`[PASSIVE] Starting passive enumeration for ${safeDomain}`);

  const passiveTasks = [];
  const allSubs = [];

  // Subfinder
  const subfinder = detectTool("subfinder");
  if (subfinder) {
    passiveTasks.push(
      runWithRetry({
        cmd: subfinder,
        args: ["-silent", "-d", safeDomain, "-timeout", "30", "-t", "50"],
        domain,
        onLine: (line) => {
          if (isValidSubdomain(line, safeDomain)) allSubs.push(line.trim().toLowerCase());
        },
        onLog: log,
        timeout: 180000,
      })
    );
  } else {
    log(`[WARN] subfinder not found, skipping`);
  }

  // Assetfinder
  const assetfinder = detectTool("assetfinder");
  if (assetfinder) {
    passiveTasks.push(
      runWithRetry({
        cmd: assetfinder,
        args: ["--subs-only", safeDomain],
        domain,
        onLine: (line) => {
          if (isValidSubdomain(line, safeDomain)) allSubs.push(line.trim().toLowerCase());
        },
        onLog: log,
        timeout: 120000,
      })
    );
  } else {
    log(`[WARN] assetfinder not found, skipping`);
  }

  // Amass passive
  const amass = detectTool("amass");
  if (amass) {
    passiveTasks.push(
      runWithRetry({
        cmd: amass,
        args: ["enum", "-passive", "-d", safeDomain, "-timeout", "10"],
        domain,
        onLine: (line) => {
          if (isValidSubdomain(line, safeDomain)) allSubs.push(line.trim().toLowerCase());
        },
        onLog: log,
        timeout: 240000,
      })
    );
  } else {
    log(`[WARN] amass not found, skipping`);
  }

  // Run all passive in parallel
  await Promise.all(passiveTasks);

  const unique = [...new Set(allSubs)];
  log(`[PASSIVE] Found ${unique.length} unique subdomains from passive sources`);
  return unique;
}

/**
 * Run active enumeration (shuffledns brute-force + dnsx validation)
 */
async function runActiveEnum(domain, emitLog, wordlistPath) {
  const safeDomain = sanitizeForShell(domain);
  const dir = await ensureReconDir(domain);
  const resolversPath = await ensureResolvers();
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  const activeSubs = [];

  // ShuffleDNS (requires wordlist)
  const shuffledns = detectTool("shuffledns");
  if (shuffledns && wordlistPath) {
    log(`[ACTIVE] Running shuffledns brute force...`);
    const outputFile = path.join(dir, "shuffledns_out.txt");
    await runWithRetry({
      cmd: shuffledns,
      args: [
        "-d", safeDomain,
        "-w", wordlistPath,
        "-r", resolversPath,
        "-o", outputFile,
        "-silent",
        "-t", "500",
      ],
      domain,
      onLine: (line) => {
        if (isValidSubdomain(line, safeDomain)) activeSubs.push(line.trim().toLowerCase());
      },
      onLog: log,
      timeout: 600000,
    });
  } else {
    log(`[SKIP] shuffledns or wordlist not available, skipping active brute force`);
  }

  log(`[ACTIVE] Found ${activeSubs.length} additional subdomains from active enum`);
  return activeSubs;
}

/**
 * Full enumeration pipeline
 */
async function enumerate(domain, emitLog, options = {}) {
  const safeDomain = sanitizeForShell(domain);
  const dir = await ensureReconDir(domain);
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  log(`[ENUM] Starting full enumeration for ${safeDomain}`);

  // Passive (always run)
  const passiveSubs = await runPassiveEnum(domain, emitLog);

  // Active (optional, based on wordlist availability)
  let activeSubs = [];
  if (options.activeEnum && options.wordlist) {
    activeSubs = await runActiveEnum(domain, emitLog, options.wordlist);
  }

  // Combine all
  const allSubs = [...new Set([...passiveSubs, ...activeSubs])];
  allSubs.sort();

  // Write to file
  const allSubsFile = path.join(dir, "all_subdomains.txt");
  await writeLines(allSubsFile, allSubs);

  log(`[ENUM] Total unique subdomains: ${allSubs.length}`);
  log(`[ENUM] Saved to ${allSubsFile}`);

  return { subdomains: allSubs, count: allSubs.length };
}

/**
 * Validate that a line looks like a subdomain of the target
 */
function isValidSubdomain(line, domain) {
  if (!line) return false;
  const trimmed = line.trim().toLowerCase();
  if (!trimmed) return false;
  if (trimmed.length > 253) return false;
  // Must end with the target domain
  if (!trimmed.endsWith(`.${domain}`) && trimmed !== domain) return false;
  // Basic domain format check
  if (!/^[a-zA-Z0-9.\-_]+$/.test(trimmed)) return false;
  return true;
}

module.exports = { enumerate, runPassiveEnum, runActiveEnum };
