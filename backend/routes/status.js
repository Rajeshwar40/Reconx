/**
 * Status Routes - System and scan status
 */

const express = require("express");
const router = express.Router();
const { checkAllTools } = require("../utils/toolDetector");
const { getScanStatus } = require("../utils/fileUtils");
const { validateDomain } = require("../utils/validator");
const os = require("os");

/**
 * GET /api/status/system
 * Get system status including tool availability
 */
router.get("/system", async (req, res) => {
  const tools = checkAllTools();
  const availableCount = Object.values(tools).filter((t) => t.available).length;

  res.json({
    status: "online",
    platform: process.platform,
    arch: process.arch,
    node_version: process.version,
    hostname: os.hostname(),
    uptime: process.uptime(),
    tools,
    tools_available: availableCount,
    tools_total: Object.keys(tools).length,
    ready: availableCount >= 2,
    powered_by: "Rajeshwar Singh",
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/status/scan/:domain
 * Get current scan status for a domain
 */
router.get("/scan/:domain", async (req, res, next) => {
  try {
    const { domain } = req.params;
    const validation = validateDomain(domain);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const status = await getScanStatus(validation.domain);
    if (!status) {
      return res.status(404).json({ error: "No scan status found" });
    }

    res.json(status);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
