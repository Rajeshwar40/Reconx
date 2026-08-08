/**
 * Results Routes - Fetch scan results
 */

const express = require("express");
const router = express.Router();
const path = require("path");
const { validateDomain } = require("../utils/validator");
const {
  getDomainDir,
  readLines,
  readResults,
  getScanStatus,
  getAllDomains,
  RECON_BASE,
} = require("../utils/fileUtils");
const fs = require("fs-extra");

/**
 * GET /api/results/:domain
 * Get full results for a domain
 */
router.get("/:domain", async (req, res, next) => {
  try {
    const { domain } = req.params;
    const validation = validateDomain(domain);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const dir = getDomainDir(validation.domain);

    if (!(await fs.pathExists(dir))) {
      return res.status(404).json({ error: "No scan results found for this domain" });
    }

    const [allSubs, liveSubs, httpResults, status] = await Promise.all([
      readLines(path.join(dir, "all_subdomains.txt")),
      readLines(path.join(dir, "live.txt")),
      readResults(validation.domain),
      getScanStatus(validation.domain),
    ]);

    // Separate takeover findings
    const takeovers = httpResults.filter((r) => r.takeover === true);

    // Status code distribution
    const statusDist = {};
    for (const r of httpResults) {
      const code = String(r.status_code || "unknown");
      statusDist[code] = (statusDist[code] || 0) + 1;
    }

    // Tech distribution
    const techDist = {};
    for (const r of httpResults) {
      for (const tech of r.tech || []) {
        techDist[tech] = (techDist[tech] || 0) + 1;
      }
    }

    res.json({
      domain: validation.domain,
      summary: {
        total_subdomains: allSubs.length,
        live_count: liveSubs.length,
        dead_count: allSubs.length - liveSubs.length,
        http_probed: httpResults.length,
        takeover_count: takeovers.length,
        status_distribution: statusDist,
        tech_distribution: techDist,
        scan_status: status?.status || "unknown",
        scanned_at: status?.startTime || null,
        completed_at: status?.endTime || null,
      },
      subdomains: httpResults,
      takeovers,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/results/:domain/raw
 * Get raw file list for a domain
 */
router.get("/:domain/raw/:file", async (req, res, next) => {
  try {
    const { domain, file } = req.params;
    const validation = validateDomain(domain);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Only allow specific files
    const allowedFiles = [
      "all_subdomains.txt",
      "live.txt",
      "final.json",
      "takeover.txt",
      "logs.txt",
      "status.json",
    ];

    if (!allowedFiles.includes(file)) {
      return res.status(403).json({ error: "File not allowed" });
    }

    const filePath = path.join(getDomainDir(validation.domain), file);
    if (!(await fs.pathExists(filePath))) {
      return res.status(404).json({ error: "File not found" });
    }

    const content = await fs.readFile(filePath, "utf8");
    res.setHeader("Content-Type", "text/plain");
    res.send(content);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/results
 * List all domains with previous scans
 */
router.get("/", async (req, res, next) => {
  try {
    const domains = await getAllDomains();
    const summaries = [];

    for (const d of domains) {
      try {
        const status = await getScanStatus(d);
        const liveFile = path.join(getDomainDir(d), "live.txt");
        const liveCount = (await readLines(liveFile)).length;
        summaries.push({
          domain: d,
          status: status?.status || "unknown",
          subdomains: status?.subdomainCount || 0,
          live: liveCount,
          takeovers: status?.takeoverCount || 0,
          scanned_at: status?.startTime || null,
        });
      } catch {}
    }

    res.json({ domains: summaries, count: summaries.length });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
