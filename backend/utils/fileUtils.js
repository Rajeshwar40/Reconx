/**
 * File Utilities - Manages recon output directories and files
 */

const fs = require("fs-extra");
const path = require("path");

const RECON_BASE = path.join(process.env.HOME || "/tmp", "recon");

/**
 * Get the recon directory path for a domain
 */
function getDomainDir(domain) {
  return path.join(RECON_BASE, sanitizeDomainPath(domain));
}

/**
 * Sanitize domain for use as directory name
 */
function sanitizeDomainPath(domain) {
  return domain.replace(/[^a-zA-Z0-9.\-_]/g, "_");
}

/**
 * Ensure recon directory exists for a domain
 */
async function ensureReconDir(domain) {
  const dir = getDomainDir(domain);
  await fs.ensureDir(dir);
  return dir;
}

/**
 * Read file lines, deduplicating, filtering empty lines
 */
async function readLines(filePath) {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return [
      ...new Set(
        content
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
      ),
    ];
  } catch {
    return [];
  }
}

/**
 * Write deduplicated lines to a file
 */
async function writeLines(filePath, lines) {
  const unique = [...new Set(lines.filter(Boolean).map((l) => l.trim()))];
  unique.sort();
  await fs.writeFile(filePath, unique.join("\n") + "\n", "utf8");
  return unique;
}

/**
 * Append lines to file, maintaining uniqueness
 */
async function appendLines(filePath, newLines) {
  const existing = await readLines(filePath);
  const combined = [...existing, ...newLines];
  return writeLines(filePath, combined);
}

/**
 * Append a log entry
 */
async function appendLog(domain, message) {
  const dir = getDomainDir(domain);
  const logFile = path.join(dir, "logs.txt");
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] ${message}\n`;
  await fs.appendFile(logFile, entry, "utf8");
}

/**
 * Get all recon domains
 */
async function getAllDomains() {
  await fs.ensureDir(RECON_BASE);
  const items = await fs.readdir(RECON_BASE);
  const domains = [];
  for (const item of items) {
    const stat = await fs.stat(path.join(RECON_BASE, item));
    if (stat.isDirectory()) {
      domains.push(item);
    }
  }
  return domains;
}

/**
 * Auto-create a resolvers.txt if missing
 * Uses well-known public resolvers
 */
async function ensureResolvers() {
  const resolversPath = path.join(RECON_BASE, "resolvers.txt");
  if (await fs.pathExists(resolversPath)) {
    return resolversPath;
  }

  const resolvers = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "64.6.64.6",
    "64.6.65.6",
    "84.200.69.80",
    "84.200.70.40",
    "8.26.56.26",
    "8.20.247.20",
    "195.46.39.39",
    "195.46.39.40",
  ].join("\n");

  await fs.writeFile(resolversPath, resolvers + "\n", "utf8");
  return resolversPath;
}

/**
 * Read final.json results
 */
async function readResults(domain) {
  const dir = getDomainDir(domain);
  const jsonPath = path.join(dir, "final.json");
  try {
    const raw = await fs.readFile(jsonPath, "utf8");
    // Handle JSONL (one JSON per line) or JSON array
    const lines = raw
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    return lines;
  } catch {
    return [];
  }
}

/**
 * Get scan status file
 */
async function getScanStatus(domain) {
  const dir = getDomainDir(domain);
  const statusPath = path.join(dir, "status.json");
  try {
    return await fs.readJson(statusPath);
  } catch {
    return null;
  }
}

/**
 * Write scan status
 */
async function writeScanStatus(domain, status) {
  const dir = getDomainDir(domain);
  const statusPath = path.join(dir, "status.json");
  await fs.ensureDir(dir);
  await fs.writeJson(statusPath, status, { spaces: 2 });
}

module.exports = {
  RECON_BASE,
  getDomainDir,
  ensureReconDir,
  readLines,
  writeLines,
  appendLines,
  appendLog,
  getAllDomains,
  ensureResolvers,
  readResults,
  getScanStatus,
  writeScanStatus,
};
