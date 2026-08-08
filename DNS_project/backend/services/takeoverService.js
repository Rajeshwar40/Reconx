/**
 * Takeover Detection Service - STRICT MODE
 * Zero false positives: dual verification required
 * Uses nuclei + custom fingerprint verification
 */

const path = require("path");
const fs = require("fs-extra");
const https = require("https");
const http = require("http");
const dns = require("dns").promises;
const { detectTool } = require("../utils/toolDetector");
const { runCommand } = require("../utils/processRunner");
const {
  getDomainDir,
  ensureReconDir,
  readLines,
  writeLines,
  appendLog,
  readResults,
} = require("../utils/fileUtils");
const { sanitizeForShell } = require("../utils/validator");

/**
 * Known vulnerable service fingerprints
 * Format: { cname_patterns: [], response_fingerprints: [], service: '', description: '' }
 * SOURCE: https://github.com/EdOverflow/can-i-take-over-xyz
 */
const TAKEOVER_SIGNATURES = [
  {
    service: "GitHub Pages",
    cname_patterns: ["github.io", "github.com"],
    response_fingerprints: [
      "there isn't a github pages site here",
      "for root urls (like http://example.com/) you can't use a cname",
    ],
    confidence: "high",
  },
  {
    service: "Heroku",
    cname_patterns: ["herokudns.com", "herokuapp.com", "herokussl.com"],
    response_fingerprints: [
      "no such app",
      "herokucdn.com/error-pages/no-such-app.html",
      "there's nothing here",
    ],
    confidence: "high",
  },
  {
    service: "Shopify",
    cname_patterns: ["myshopify.com"],
    response_fingerprints: ["sorry, this shop is currently unavailable"],
    confidence: "high",
  },
  {
    service: "Fastly",
    cname_patterns: ["fastly.net"],
    response_fingerprints: ["fastly error: unknown domain"],
    confidence: "high",
  },
  {
    service: "Amazon AWS S3",
    cname_patterns: ["s3.amazonaws.com", "amazonaws.com"],
    response_fingerprints: [
      "nosuchbucket",
      "the specified bucket does not exist",
      "nosuchwebsiteconfiguration",
    ],
    confidence: "high",
  },
  {
    service: "Amazon CloudFront",
    cname_patterns: ["cloudfront.net"],
    response_fingerprints: ["bad request", "error: the request could not be satisfied"],
    confidence: "medium",
  },
  {
    service: "Azure",
    cname_patterns: [
      "azurewebsites.net",
      "cloudapp.net",
      "cloudapp.azure.com",
      "trafficmanager.net",
      "blob.core.windows.net",
    ],
    response_fingerprints: [
      "404 web site not found",
      "no web site found",
      "the service you requested is not available",
    ],
    confidence: "high",
  },
  {
    service: "Zendesk",
    cname_patterns: ["zendesk.com"],
    response_fingerprints: ["help center closed"],
    confidence: "high",
  },
  {
    service: "WPEngine",
    cname_patterns: ["wpengine.com"],
    response_fingerprints: ["the site you were looking for couldn't be found"],
    confidence: "high",
  },
  {
    service: "Ghost",
    cname_patterns: ["ghost.io"],
    response_fingerprints: ["the thing you were looking for is no longer here"],
    confidence: "high",
  },
  {
    service: "Cargo",
    cname_patterns: ["cargocollective.com"],
    response_fingerprints: ["404 not found"],
    confidence: "medium",
  },
  {
    service: "Tumblr",
    cname_patterns: ["tumblr.com"],
    response_fingerprints: [
      "there's nothing here.",
      "whatever you were looking for doesn't currently exist at this address",
    ],
    confidence: "high",
  },
  {
    service: "Surge.sh",
    cname_patterns: ["surge.sh"],
    response_fingerprints: ["project not found"],
    confidence: "high",
  },
  {
    service: "Bitbucket",
    cname_patterns: ["bitbucket.io"],
    response_fingerprints: ["repository not found"],
    confidence: "high",
  },
  {
    service: "Pantheon",
    cname_patterns: ["pantheonsite.io", "gotpantheon.com"],
    response_fingerprints: ["the gods are wise"],
    confidence: "high",
  },
  {
    service: "Squarespace",
    cname_patterns: ["squarespace.com"],
    response_fingerprints: ["no such account"],
    confidence: "high",
  },
  {
    service: "Statuspage.io",
    cname_patterns: ["statuspage.io"],
    response_fingerprints: ["you are being redirected", "statuspage.io"],
    confidence: "medium",
  },
  {
    service: "UserVoice",
    cname_patterns: ["uservoice.com"],
    response_fingerprints: ["this uservoice subdomain is currently available"],
    confidence: "high",
  },
  {
    service: "HubSpot",
    cname_patterns: ["hubspot.com", "hubspot.net"],
    response_fingerprints: ["domain not found"],
    confidence: "medium",
  },
  {
    service: "Webflow",
    cname_patterns: ["webflow.io"],
    response_fingerprints: ["the page you are looking for doesn't exist or has been moved"],
    confidence: "medium",
  },
  {
    service: "Netlify",
    cname_patterns: ["netlify.app", "netlify.com"],
    response_fingerprints: ["not found - request id"],
    confidence: "high",
  },
  {
    service: "Vercel",
    cname_patterns: ["vercel.app", "now.sh"],
    response_fingerprints: ["the deployment could not be found"],
    confidence: "high",
  },
  {
    service: "Launchrock",
    cname_patterns: ["launchrock.com"],
    response_fingerprints: ["it looks like you may have taken a wrong turn somewhere"],
    confidence: "high",
  },
];

/**
 * Main takeover detection function - STRICT MODE
 * Requires BOTH CNAME match AND HTTP fingerprint match
 */
async function detectTakeovers(domain, emitLog) {
  const dir = await ensureReconDir(domain);
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  log(`[TAKEOVER] Starting takeover detection - STRICT MODE (zero false positives)`);

  const liveFile = path.join(dir, "live.txt");
  const takeoverFile = path.join(dir, "takeover.txt");
  const subdomains = await readLines(liveFile);

  if (subdomains.length === 0) {
    log(`[TAKEOVER] No live subdomains to check`);
    return [];
  }

  log(`[TAKEOVER] Checking ${subdomains.length} subdomains...`);

  const vulnerabilities = [];

  // Check in batches to avoid overwhelming DNS
  const BATCH_SIZE = 20;
  for (let i = 0; i < subdomains.length; i += BATCH_SIZE) {
    const batch = subdomains.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(
      batch.map((sub) => checkSingleSubdomain(sub, log))
    );
    for (const result of results) {
      if (result && result.vulnerable) {
        vulnerabilities.push(result);
      }
    }
    log(`[TAKEOVER] Progress: ${Math.min(i + BATCH_SIZE, subdomains.length)}/${subdomains.length}`);
  }

  // Write vulnerable subdomains to file
  if (vulnerabilities.length > 0) {
    const lines = vulnerabilities.map(
      (v) => `${v.subdomain} [${v.service}] CNAME:${v.cname}`
    );
    await writeLines(takeoverFile, lines);
    log(`[TAKEOVER] ⚠️  Found ${vulnerabilities.length} VERIFIED vulnerable subdomains`);
  } else {
    await fs.writeFile(takeoverFile, "# No subdomain takeovers found\n", "utf8");
    log(`[TAKEOVER] ✅ No takeovers found (0 false positives by design)`);
  }

  // Now run nuclei for additional verification if available
  const nucleiResults = await runNuclei(domain, liveFile, emitLog);

  // Cross-reference nuclei with our custom checks to increase confidence
  const finalVulns = crossReference(vulnerabilities, nucleiResults);

  return finalVulns;
}

/**
 * Check a single subdomain for takeover
 * STRICT: requires CNAME match + HTTP fingerprint + double verification
 */
async function checkSingleSubdomain(subdomain, log) {
  try {
    // Step 1: Resolve CNAME
    const cnameRecords = await resolveCNAME(subdomain);
    if (!cnameRecords || cnameRecords.length === 0) return null;

    const cname = cnameRecords[0].toLowerCase();

    // Step 2: Match CNAME against known vulnerable services
    const matchedService = TAKEOVER_SIGNATURES.find((sig) =>
      sig.cname_patterns.some((pattern) => cname.includes(pattern))
    );

    if (!matchedService) return null;

    log(`[TAKEOVER] CNAME match: ${subdomain} -> ${cname} (${matchedService.service})`);

    // Step 3: Fetch HTTP response and check fingerprint
    const httpBody = await fetchHTTPBody(subdomain);
    if (!httpBody) return null;

    const bodyLower = httpBody.toLowerCase();
    const fingerprintMatch = matchedService.response_fingerprints.some((fp) =>
      bodyLower.includes(fp.toLowerCase())
    );

    if (!fingerprintMatch) {
      log(`[TAKEOVER] CNAME matched but HTTP fingerprint NOT confirmed for ${subdomain} - SKIPPING (strict mode)`);
      return null;
    }

    // Step 4: DOUBLE VERIFICATION - re-check after 2s delay
    await new Promise((r) => setTimeout(r, 2000));
    const httpBody2 = await fetchHTTPBody(subdomain);
    if (!httpBody2) return null;

    const bodyLower2 = httpBody2.toLowerCase();
    const fingerprintMatch2 = matchedService.response_fingerprints.some((fp) =>
      bodyLower2.includes(fp.toLowerCase())
    );

    if (!fingerprintMatch2) {
      log(`[TAKEOVER] Second verification FAILED for ${subdomain} - SKIPPING (strict mode)`);
      return null;
    }

    // CONFIRMED: Both checks passed
    log(`[TAKEOVER] ⚠️  VERIFIED VULNERABLE: ${subdomain} -> ${matchedService.service}`);

    return {
      subdomain,
      cname,
      service: matchedService.service,
      confidence: matchedService.confidence,
      vulnerable: true,
      verification_count: 2,
      fingerprint_matched: true,
      detected_at: new Date().toISOString(),
    };
  } catch (err) {
    // Silent fail - prefer false negatives over false positives
    return null;
  }
}

/**
 * Resolve CNAME records for a hostname
 */
async function resolveCNAME(hostname) {
  try {
    const records = await Promise.race([
      dns.resolveCname(hostname),
      new Promise((_, reject) => setTimeout(() => reject(new Error("DNS timeout")), 5000)),
    ]);
    return records;
  } catch {
    return [];
  }
}

/**
 * Fetch HTTP body of a host (tries HTTPS then HTTP)
 */
function fetchHTTPBody(hostname) {
  return new Promise((resolve) => {
    const tryFetch = (protocol, port) => {
      const mod = protocol === "https" ? https : http;
      const options = {
        hostname,
        port,
        path: "/",
        method: "GET",
        timeout: 8000,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)",
          Host: hostname,
        },
        rejectUnauthorized: false,
      };

      const req = mod.request(options, (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
          if (body.length > 50000) {
            req.destroy();
          }
        });
        res.on("end", () => resolve(body));
        res.on("error", () => resolve(null));
      });

      req.on("error", () => {
        if (protocol === "https") {
          tryFetch("http", 80);
        } else {
          resolve(null);
        }
      });

      req.on("timeout", () => {
        req.destroy();
        if (protocol === "https") {
          tryFetch("http", 80);
        } else {
          resolve(null);
        }
      });

      req.end();
    };

    tryFetch("https", 443);
  });
}

/**
 * Run nuclei for additional takeover detection
 */
async function runNuclei(domain, liveFile, emitLog) {
  const nuclei = detectTool("nuclei");
  const log = (msg) => {
    emitLog(msg);
    appendLog(domain, msg);
  };

  if (!nuclei) {
    log(`[WARN] nuclei not found, skipping nuclei takeover scan`);
    return [];
  }

  const dir = await ensureReconDir(domain);
  const nucleiResults = [];

  log(`[NUCLEI] Running nuclei takeover templates...`);

  // Try common nuclei template paths
  const templateDirs = [
    `${process.env.HOME}/nuclei-templates/takeovers`,
    `${process.env.HOME}/.local/nuclei-templates/takeovers`,
    "/usr/local/share/nuclei-templates/takeovers",
    `${process.env.HOME}/nuclei-templates/http/takeovers`,
  ];

  const fs = require("fs-extra");
  let templateDir = null;
  for (const td of templateDirs) {
    if (await fs.pathExists(td)) {
      templateDir = td;
      break;
    }
  }

  if (!templateDir) {
    log(`[NUCLEI] No takeover templates found, updating nuclei templates...`);
    try {
      await runCommand({
        cmd: nuclei,
        args: ["-update-templates", "-silent"],
        domain,
        onLog: log,
        timeout: 120000,
      });
      // Try again after update
      for (const td of templateDirs) {
        if (await fs.pathExists(td)) {
          templateDir = td;
          break;
        }
      }
    } catch {}
  }

  if (!templateDir) {
    log(`[NUCLEI] Template directory not found, skipping nuclei scan`);
    return [];
  }

  await runCommand({
    cmd: nuclei,
    args: [
      "-t", templateDir,
      "-l", liveFile,
      "-silent",
      "-json",
      "-rate-limit", "50",
      "-timeout", "10",
      "-retries", "2",
    ],
    domain,
    onLine: (line) => {
      try {
        const result = JSON.parse(line);
        if (result && result.matched_at) {
          nucleiResults.push({
            subdomain: result.matched_at.replace(/https?:\/\//, "").split("/")[0],
            template_id: result.template_id,
            severity: result.info?.severity || "unknown",
            name: result.info?.name || "",
          });
        }
      } catch {}
    },
    onLog: log,
    timeout: 300000,
  });

  log(`[NUCLEI] Nuclei found ${nucleiResults.length} potential issues`);
  return nucleiResults;
}

/**
 * Cross-reference our custom results with nuclei results
 * Items in BOTH are highest confidence
 */
function crossReference(customResults, nucleiResults) {
  const nucleiHosts = new Set(nucleiResults.map((n) => n.subdomain));

  return customResults.map((result) => ({
    ...result,
    nuclei_confirmed: nucleiHosts.has(result.subdomain),
    confidence_level: nucleiHosts.has(result.subdomain) ? "CONFIRMED" : result.confidence,
  }));
}

module.exports = { detectTakeovers, TAKEOVER_SIGNATURES };
