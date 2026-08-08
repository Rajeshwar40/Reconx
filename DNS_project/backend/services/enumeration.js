'use strict';

const { spawn }         = require('child_process');
const https             = require('https');
const http              = require('http');
const fs                = require('fs');
const path              = require('path');
const os                = require('os');
const { ENRICHED_PATH } = require('../utils/toolPaths');

const TOOL_ENV = { ...process.env, PATH: ENRICHED_PATH };

// ── Helpers ───────────────────────────────────────────────────────────────────

function runCollect(bin, args, timeoutMs = 5 * 60 * 1000) {
  return new Promise((resolve) => {
    const lines = [];
    let proc;
    try {
      proc = spawn(bin, args, { env: TOOL_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      console.error(`[spawn] ${bin}: ${e.message}`);
      return resolve(lines);
    }
    proc.stdout.on('data', d =>
      d.toString().split('\n').forEach(l => { const t = l.trim(); if (t) lines.push(t); })
    );
    proc.on('error', () => resolve(lines));
    const timer = setTimeout(() => { try { proc.kill(); } catch {} resolve(lines); }, timeoutMs);
    proc.on('close', () => { clearTimeout(timer); resolve(lines); });
  });
}

function httpGet(url, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'ReconX/1.0' }, timeout: timeoutMs }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ ok: res.statusCode < 400, status: res.statusCode, body }));
    });
    req.on('error', () => resolve({ ok: false, body: '' }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, body: '' }); });
  });
}

function reconDir(domain) {
  const dir = path.join(os.homedir(), 'recon', domain);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function ensureResolvers(dir) {
  const p = path.join(dir, 'resolvers.txt');
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, ['1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9',
      '149.112.112.112','208.67.222.222','208.67.220.220','64.6.64.6','64.6.65.6'].join('\n'));
  }
  return p;
}

function dedup(list, domain) {
  return [...new Set(list.map(s => s.trim().toLowerCase()).filter(s =>
    s && (s === domain || s.endsWith(`.${domain}`)) && !s.includes('*')
  ))];
}

// ── Passive sources ───────────────────────────────────────────────────────────

async function fromCrtSh(domain, logger) {
  logger.info('crt.sh: querying certificate transparency…');
  const r = await httpGet(`https://crt.sh/?q=%.${domain}&output=json`);
  if (!r.ok) { logger.warn('crt.sh: no response'); return []; }
  try {
    const data = JSON.parse(r.body);
    const names = data.flatMap(e =>
      (e.name_value || '').split('\n').map(n => n.trim().replace(/^\*\./, ''))
    );
    const uniq = dedup(names, domain);
    logger.info(`crt.sh: ${uniq.length} subdomains`);
    return uniq;
  } catch { logger.warn('crt.sh: parse error'); return []; }
}

async function fromHackerTarget(domain, logger) {
  logger.info('HackerTarget: querying hostsearch…');
  const r = await httpGet(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
  if (!r.ok || r.body.includes('error')) { logger.warn('HackerTarget: no data'); return []; }
  const subs = r.body.split('\n').map(l => l.split(',')[0].trim()).filter(Boolean);
  const uniq = dedup(subs, domain);
  logger.info(`HackerTarget: ${uniq.length} subdomains`);
  return uniq;
}

async function fromAlienVault(domain, logger) {
  logger.info('AlienVault OTX: querying passive DNS…');
  const r = await httpGet(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`);
  if (!r.ok) { logger.warn('AlienVault: no response'); return []; }
  try {
    const data = JSON.parse(r.body);
    const subs = (data.passive_dns || []).map(e => e.hostname).filter(Boolean);
    const uniq = dedup(subs, domain);
    logger.info(`AlienVault: ${uniq.length} subdomains`);
    return uniq;
  } catch { return []; }
}

async function fromRapidDNS(domain, logger) {
  logger.info('RapidDNS: querying…');
  const r = await httpGet(`https://rapiddns.io/subdomain/${domain}?full=1#result`);
  if (!r.ok) { logger.warn('RapidDNS: no response'); return []; }
  const matches = r.body.match(/>[a-z0-9._-]+\.[a-z]{2,}<\/td>/gi) || [];
  const subs = matches.map(m => m.replace(/^>|<\/td>$/gi, '').trim());
  const uniq = dedup(subs, domain);
  logger.info(`RapidDNS: ${uniq.length} subdomains`);
  return uniq;
}

async function fromBufferOver(domain, logger) {
  logger.info('BufferOver: querying…');
  const r = await httpGet(`https://dns.bufferover.run/dns?q=.${domain}`);
  if (!r.ok) { logger.warn('BufferOver: no response'); return []; }
  try {
    const data = JSON.parse(r.body);
    const rdns = (data.RDNS || []).concat(data.FDNS_A || []);
    const subs = rdns.map(e => e.split(',').pop()).filter(Boolean);
    const uniq = dedup(subs, domain);
    logger.info(`BufferOver: ${uniq.length} subdomains`);
    return uniq;
  } catch { return []; }
}

async function fromUrlScan(domain, logger) {
  logger.info('urlscan.io: querying…');
  const r = await httpGet(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=200`);
  if (!r.ok) { logger.warn('urlscan.io: no response'); return []; }
  try {
    const data = JSON.parse(r.body);
    const subs = (data.results || []).map(e => e.page?.domain).filter(Boolean);
    const uniq = dedup(subs, domain);
    logger.info(`urlscan.io: ${uniq.length} subdomains`);
    return uniq;
  } catch { return []; }
}

// subfinder's default provider-config location differs by OS (and has been
// observed to silently resolve to an empty file on macOS) — pin it explicitly
// rather than trusting subfinder's own default resolution.
function resolveSubfinderConfig() {
  const candidates = [
    path.join(os.homedir(), '.config', 'subfinder', 'provider-config.yaml'),
    path.join(os.homedir(), 'Library', 'Application Support', 'subfinder', 'provider-config.yaml'),
  ];
  return candidates.find(p => fs.existsSync(p)) || null;
}
const SUBFINDER_CONFIG = resolveSubfinderConfig();

async function fromSubfinderTool(domain, tools, logger) {
  if (!tools.subfinder) { logger.warn('subfinder: not installed'); return []; }
  logger.info('subfinder: running…');
  const args = ['-silent', '-d', domain];
  if (SUBFINDER_CONFIG) args.push('-pc', SUBFINDER_CONFIG);
  const lines = await runCollect(tools.subfinder, args, 3 * 60 * 1000);
  logger.info(`subfinder: ${lines.length} results`);
  if (lines.length < 20) {
    logger.warn(`subfinder: unusually low result count (${lines.length}) — check API keys in ${SUBFINDER_CONFIG || 'provider-config.yaml'}`);
  }
  return lines;
}

async function fromAssetfinder(domain, tools, logger) {
  if (!tools.assetfinder) { logger.warn('assetfinder: not installed'); return []; }
  logger.info('assetfinder: running…');
  const lines = await runCollect(tools.assetfinder, ['--subs-only', domain], 2 * 60 * 1000);
  logger.info(`assetfinder: ${lines.length} results`);
  return lines;
}

async function fromAmass(domain, tools, logger) {
  if (!tools.amass) { logger.warn('amass: not installed'); return []; }
  logger.info('amass: running passive (3 min timeout)…');
  const lines = await runCollect(tools.amass, ['enum', '-passive', '-d', domain, '-timeout', '3'], 4 * 60 * 1000);
  logger.info(`amass: ${lines.length} results`);
  return lines;
}

// ── DNS record resolution ─────────────────────────────────────────────────────

async function resolveDNSRecords(subdomains, tools, logger) {
  if (!tools.dnsx) { logger.warn('dnsx: not installed — DNS records skipped'); return {}; }
  if (!subdomains.length) return {};

  const tmpFile = path.join(os.tmpdir(), `dnsx_input_${Date.now()}.txt`);
  fs.writeFileSync(tmpFile, subdomains.join('\n'));

  logger.info(`dnsx: resolving ${subdomains.length} subdomains for all record types…`);

  // Run dnsx for each record type
  const recordTypes = ['a', 'aaaa', 'cname', 'mx', 'txt', 'ns'];
  const recordMap = {}; // subdomain -> { A:[], AAAA:[], CNAME:[], MX:[], TXT:[], NS:[] }

  for (const rtype of recordTypes) {
    const lines = await runCollect(tools.dnsx, [
      '-l', tmpFile, '-silent', '-json', `-${rtype}`,
    ], 3 * 60 * 1000);

    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const host = obj.host || obj.input || '';
        if (!host) continue;
        if (!recordMap[host]) recordMap[host] = { A: [], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [], status: 'resolved' };
        const key = rtype.toUpperCase();
        const vals = obj[rtype] || obj[key] || [];
        if (Array.isArray(vals)) {
          recordMap[host][key] = [...new Set([...recordMap[host][key], ...vals])];
        } else if (vals) {
          recordMap[host][key] = [...new Set([...recordMap[host][key], String(vals)])];
        }
      } catch {}
    }
  }

  try { fs.unlinkSync(tmpFile); } catch {}
  logger.info(`dnsx: resolved records for ${Object.keys(recordMap).length} hosts`);
  return recordMap;
}

// ── HTTP probe ────────────────────────────────────────────────────────────────

async function httpxProbe(liveHosts, tools, logger) {
  if (!tools.httpx) { logger.warn('httpx: not installed — HTTP probe skipped'); return []; }
  if (!liveHosts.length) { logger.warn('httpx: no hosts to probe'); return []; }

  const tmpFile = path.join(os.tmpdir(), `httpx_input_${Date.now()}.txt`);
  fs.writeFileSync(tmpFile, liveHosts.join('\n'));

  logger.info(`httpx: probing ${liveHosts.length} hosts…`);
  const lines = await runCollect(tools.httpx, [
    '-l', tmpFile, '-silent', '-json',
    '-status-code', '-title', '-tech-detect',
    '-response-time', '-ip', '-follow-redirects',
    '-timeout', '10', '-threads', '50',
  ], 10 * 60 * 1000);

  try { fs.unlinkSync(tmpFile); } catch {}
  const parsed = lines.map(l => { try { return JSON.parse(l); } catch {} }).filter(Boolean);
  logger.info(`httpx: ${parsed.length} live HTTP hosts`);
  return parsed;
}

// ── Takeover scan ─────────────────────────────────────────────────────────────

async function takeoverScan(liveHosts, tools, logger) {
  if (!tools.nuclei) { logger.warn('nuclei: not installed — takeover scan skipped'); return []; }
  if (!liveHosts.length) return [];

  const tmpFile = path.join(os.tmpdir(), `nuclei_input_${Date.now()}.txt`);
  fs.writeFileSync(tmpFile, liveHosts.join('\n'));

  logger.info('nuclei: pass 1 takeover scan…');
  const run = f => runCollect(tools.nuclei, [
    '-l', f, '-t', 'takeovers/', '-silent', '-json', '-timeout', '10', '-retries', '2', '-rate-limit', '50',
  ], 10 * 60 * 1000);

  const p1 = (await run(tmpFile)).map(l => { try { return JSON.parse(l); } catch {} }).filter(Boolean);
  if (!p1.length) { try { fs.unlinkSync(tmpFile); } catch {}; logger.info('nuclei: no candidates'); return []; }

  logger.info(`nuclei: pass 1 → ${p1.length} candidates — verifying…`);
  const cFile = tmpFile.replace('.txt', '_candidates.txt');
  fs.writeFileSync(cFile, [...new Set(p1.map(r => r.host || r.matched_at || '').filter(Boolean))].join('\n'));

  const p2 = (await run(cFile)).map(l => { try { return JSON.parse(l); } catch {} }).filter(Boolean);
  const confirmed = p2.filter(r2 => p1.some(r1 =>
    (r1.host || r1.matched_at) === (r2.host || r2.matched_at) && r1['template-id'] === r2['template-id']
  ));

  try { fs.unlinkSync(tmpFile); fs.unlinkSync(cFile); } catch {}
  logger.success(`nuclei: ${confirmed.length} confirmed takeovers`);
  return confirmed;
}

// ── Bruteforce ────────────────────────────────────────────────────────────────

async function shuffleDNS(domain, resolversPath, tools, logger) {
  if (!tools.shuffledns) { logger.warn('shuffledns: not installed — bruteforce skipped'); return []; }
  const wl = path.join(os.tmpdir(), `wl_${domain}.txt`);
  fs.writeFileSync(wl, [
    'www','mail','ftp','smtp','admin','api','app','dev','staging','test','beta','alpha','uat',
    'blog','shop','store','cdn','static','assets','media','images','files','upload','uploads',
    'vpn','remote','portal','dashboard','secure','login','auth','oauth','sso','id','identity',
    'docs','wiki','support','help','forum','community','status','monitor','health','metrics',
    'grafana','jenkins','gitlab','github','bitbucket','jira','confluence','sonar','nexus',
    'mx','mx1','mx2','smtp','mail2','webmail','email','imap','pop','ns1','ns2','dns',
    'api2','api-v2','v2','v3','internal','intranet','corp','office','backend','srv',
    'aws','azure','gcp','cloud','k8s','prod','production','stage','sandbox','preview',
  ].join('\n'));
  logger.info('shuffledns: bruteforcing…');
  const lines = await runCollect(tools.shuffledns, ['-d', domain, '-w', wl, '-r', resolversPath, '-silent'], 5 * 60 * 1000);
  try { fs.unlinkSync(wl); } catch {}
  logger.info(`shuffledns: ${lines.length} results`);
  return lines;
}

// ── Main pipeline ─────────────────────────────────────────────────────────────

// Stage weights for progress bar (must sum to 100)
const STAGES = [
  { id: 'passive',   label: 'Passive Sources',    weight: 25 },
  { id: 'bruteforce',label: 'DNS Bruteforce',     weight: 10 },
  { id: 'dns',       label: 'DNS Records',        weight: 20 },
  { id: 'http',      label: 'HTTP Probe',         weight: 25 },
  { id: 'takeover',  label: 'Takeover Detection', weight: 20 },
];

function calcProgress(stageIdx, stageFraction = 0) {
  let done = STAGES.slice(0, stageIdx).reduce((s, x) => s + x.weight, 0);
  done += STAGES[stageIdx].weight * stageFraction;
  return Math.round(Math.min(done, 99));
}

async function runEnumeration(domain, tools, logger, broadcast, cancelToken) {
  const dir           = reconDir(domain);
  const resolversPath = ensureResolvers(dir);
  const allFile       = path.join(dir, 'all_subdomains.txt');
  const finalFile     = path.join(dir, 'final.json');

  const isCancelled = () => cancelToken && cancelToken.cancelled;

  const stageStart = (idx) => {
    const s = STAGES[idx];
    broadcast({ type: 'stage', stageId: s.id, stageLabel: s.label, stageIdx: idx, total: STAGES.length, progress: calcProgress(idx, 0) });
    logger.info(`▶ Stage ${idx + 1}/${STAGES.length}: ${s.label}`);
  };

  // ── Stage 1: Passive ──────────────────────────────────────────────────────
  stageStart(0);
  const passiveSources = await Promise.allSettled([
    fromSubfinderTool(domain, tools, logger),
    fromAssetfinder(domain, tools, logger),
    fromAmass(domain, tools, logger),
    fromCrtSh(domain, logger),
    fromHackerTarget(domain, logger),
    fromAlienVault(domain, logger),
    fromRapidDNS(domain, logger),
    fromBufferOver(domain, logger),
    fromUrlScan(domain, logger),
  ]);
  if (isCancelled()) { broadcast({ type: 'cancelled' }); return null; }

  const allPassive = dedup(passiveSources.flatMap(r => r.status === 'fulfilled' ? r.value : []), domain);
  broadcast({ type: 'progress', progress: calcProgress(0, 1) });
  broadcast({ type: 'count', key: 'passive', value: allPassive.length });
  logger.info(`Passive total (dedup): ${allPassive.length}`);

  // ── Stage 2: Bruteforce ───────────────────────────────────────────────────
  stageStart(1);
  const bruteResults = await shuffleDNS(domain, resolversPath, tools, logger);
  if (isCancelled()) { broadcast({ type: 'cancelled' }); return null; }

  const allSubdomains = dedup([...allPassive, ...bruteResults], domain);
  fs.writeFileSync(allFile, allSubdomains.join('\n'));
  broadcast({ type: 'progress', progress: calcProgress(1, 1) });
  broadcast({ type: 'count', key: 'total', value: allSubdomains.length });
  logger.info(`All subdomains (dedup): ${allSubdomains.length}`);

  // Stream subdomain list to frontend as they're found
  broadcast({ type: 'subdomains', list: allSubdomains });

  // ── Stage 3: DNS Records ──────────────────────────────────────────────────
  stageStart(2);
  broadcast({ type: 'progress', progress: calcProgress(2, 0.1) });
  const dnsRecords = await resolveDNSRecords(allSubdomains, tools, logger);
  if (isCancelled()) { broadcast({ type: 'cancelled' }); return null; }

  const liveHosts = Object.keys(dnsRecords);
  broadcast({ type: 'progress', progress: calcProgress(2, 1) });
  broadcast({ type: 'count', key: 'live', value: liveHosts.length });
  broadcast({ type: 'dns_records', records: dnsRecords });
  logger.info(`DNS resolved: ${liveHosts.length} live hosts`);

  // ── Stage 4: HTTP Probe ───────────────────────────────────────────────────
  stageStart(3);
  broadcast({ type: 'progress', progress: calcProgress(3, 0.1) });
  const httpxData = await httpxProbe(liveHosts, tools, logger);
  if (isCancelled()) { broadcast({ type: 'cancelled' }); return null; }

  // Build HTTP map
  const httpMap = {};
  for (const h of httpxData) {
    const key = (h.input || h.url || '').replace(/https?:\/\//, '').replace(/\/$/, '');
    httpMap[key] = h;
  }
  broadcast({ type: 'progress', progress: calcProgress(3, 1) });
  broadcast({ type: 'count', key: 'probed', value: httpxData.length });

  // ── Stage 5: Takeover ─────────────────────────────────────────────────────
  stageStart(4);
  const httpUrls = httpxData.map(h => h.url || h.input).filter(Boolean);
  const takeovers = await takeoverScan(httpUrls, tools, logger);
  if (isCancelled()) { broadcast({ type: 'cancelled' }); return null; }

  const takeoverMap = {};
  for (const t of takeovers) {
    const host = (t.host || t.matched_at || '').replace(/https?:\/\//, '').replace(/\/$/, '');
    takeoverMap[host] = t;
  }

  // ── Build final result set ─────────────────────────────────────────────────
  const finalData = allSubdomains.map(sub => {
    const dns  = dnsRecords[sub] || {};
    const http = httpMap[sub] || {};
    const to   = takeoverMap[sub];

    // Determine CNAME chain
    const cnames = dns.CNAME || [];
    const isWildcard = cnames.some(c => c.includes('*'));

    // 404 detection
    const statusCode = http['status-code'] || http.status_code || 0;
    const is404 = statusCode === 404;

    return {
      subdomain:    sub,
      url:          http.url || `https://${sub}`,
      ip:           (dns.A || []).join(', ') || (Array.isArray(http.host) ? http.host.join(', ') : http.host || ''),
      // DNS records
      records: {
        A:     dns.A     || [],
        AAAA:  dns.AAAA  || [],
        CNAME: dns.CNAME || [],
        MX:    dns.MX    || [],
        TXT:   dns.TXT   || [],
        NS:    dns.NS    || [],
      },
      // HTTP info
      status:       statusCode,
      title:        http.title || '',
      tech:         Array.isArray(http.tech) ? http.tech.join(', ') : (http.tech || ''),
      responseTime: http['response-time'] || '',
      // Flags
      is404,
      isWildcard,
      hasCname:   cnames.length > 0,
      cnameChain: cnames.join(' → '),
      // Takeover
      takeover:     !!to,
      takeoverInfo: to ? (to['template-id'] || 'takeover') : '',
      // Source tracking
      resolved: !!dns.status,
      probed:   !!http.url,
    };
  });

  fs.writeFileSync(finalFile, JSON.stringify(finalData, null, 2));

  broadcast({ type: 'progress', progress: 100 });
  broadcast({ type: 'count', key: 'takeovers', value: takeovers.length });
  broadcast({ type: 'results', data: finalData });
  logger.success(`Scan complete — ${allSubdomains.length} subdomains, ${liveHosts.length} live, ${httpxData.length} HTTP, ${takeovers.length} takeovers`);
  broadcast({ type: 'done', domain, stats: { total: allSubdomains.length, live: liveHosts.length, probed: httpxData.length, takeovers: takeovers.length } });

  return { finalData, stats: { total: allSubdomains.length, live: liveHosts.length, probed: httpxData.length, takeovers: takeovers.length } };
}

module.exports = { runEnumeration, STAGES };
