'use client';

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '/api';
const API_KEY  = process.env.NEXT_PUBLIC_API_KEY || '';
const API      = API_BASE;
const API_SSE  = API_BASE;
const API_STOP = API_BASE;

function apiFetch(url, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (API_KEY) headers['x-api-key'] = API_KEY;
  return fetch(url, { ...opts, headers });
}

function sseUrl(url) {
  if (!API_KEY) return url;
  return `${url}${url.includes('?') ? '&' : '?'}apiKey=${encodeURIComponent(API_KEY)}`;
}

// ── Palette ───────────────────────────────────────────────────────────────────
const C = {
  bg:      '#080c10', bg2: '#0d1117', bg3: '#161b22',
  border:  '#21262d', accent: '#00e5ff', accent2: '#7c3aed',
  danger:  '#ff4444', success: '#00c853', warn: '#ff9800',
  text:    '#e6edf3', muted:  '#8b949e', mono: 'Space Mono, monospace',
};

const statusColor = c => !c ? C.muted : c < 300 ? C.success : c < 400 ? C.warn : c < 500 ? C.accent : C.danger;
const levelColor  = { info: C.muted, warn: C.warn, error: C.danger, success: C.success };

// ── Mini components ───────────────────────────────────────────────────────────
const Badge = ({ children, color = C.accent, style = {} }) => (
  <span style={{ background: color + '22', color, border: `1px solid ${color}44`, borderRadius: 3, padding: '1px 7px', fontSize: 10, fontFamily: C.mono, fontWeight: 700, letterSpacing: '0.04em', ...style }}>{children}</span>
);

const Stat = ({ label, value, accent = C.accent, sub }) => (
  <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 8, padding: '14px 20px', minWidth: 120 }}>
    <div style={{ color: C.muted, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: C.mono, marginBottom: 4 }}>{label}</div>
    <div style={{ fontSize: 30, fontWeight: 700, color: accent, fontFamily: C.mono, lineHeight: 1 }}>{value ?? '—'}</div>
    {sub && <div style={{ color: C.muted, fontSize: 11, marginTop: 3 }}>{sub}</div>}
  </div>
);

const RecordPill = ({ type, values }) => {
  if (!values || !values.length) return null;
  const colors = { A: C.success, AAAA: '#06b6d4', CNAME: C.warn, MX: '#a78bfa', TXT: C.muted, NS: '#f97316' };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, marginRight: 4, marginBottom: 3 }}>
      <span style={{ background: (colors[type] || C.muted) + '22', color: colors[type] || C.muted, border: `1px solid ${(colors[type] || C.muted)}44`, borderRadius: 3, padding: '1px 5px', fontSize: 9, fontFamily: C.mono, fontWeight: 700 }}>{type}</span>
      <span style={{ fontSize: 10, color: C.text, fontFamily: C.mono }}>{values.slice(0, 2).join(', ')}{values.length > 2 ? ` +${values.length - 2}` : ''}</span>
    </span>
  );
};

// ── Progress bar ──────────────────────────────────────────────────────────────
const STAGE_LABELS = ['Passive Sources', 'DNS Bruteforce', 'DNS Records', 'HTTP Probe', 'Takeover Scan'];

function ProgressBar({ progress, stageIdx, stageLabel, status }) {
  return (
    <div style={{ background: C.bg2, borderBottom: `1px solid ${C.border}`, padding: '14px 32px' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        {/* Stage dots */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
          {STAGE_LABELS.map((s, i) => {
            const done = i < stageIdx;
            const active = i === stageIdx;
            return (
              <div key={s} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, flex: 1 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', border: `2px solid ${done || active ? C.accent : C.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontFamily: C.mono, color: done || active ? C.accent : C.muted, background: done ? C.accent + '22' : 'transparent', transition: 'all 0.3s' }}>
                  {done ? '✓' : i + 1}
                </div>
                <span style={{ fontSize: 9, fontFamily: C.mono, color: active ? C.accent : done ? C.success : C.muted, textTransform: 'uppercase', letterSpacing: '0.05em', textAlign: 'center', maxWidth: 80 }}>{s}</span>
              </div>
            );
          })}
        </div>
        {/* Progress bar */}
        <div style={{ height: 4, background: C.border, borderRadius: 2, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${progress}%`, background: `linear-gradient(90deg, ${C.accent}, ${C.accent2})`, borderRadius: 2, transition: 'width 0.6s ease', boxShadow: `0 0 8px ${C.accent}` }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
          <span style={{ fontSize: 11, fontFamily: C.mono, color: C.accent }}>{stageLabel || (status === 'done' ? 'Complete' : '')}</span>
          <span style={{ fontSize: 11, fontFamily: C.mono, color: C.muted }}>{progress}%</span>
        </div>
      </div>
    </div>
  );
}

// ── Export helper ─────────────────────────────────────────────────────────────
function exportHTML(scanId) {
  window.open(`${API}/scan/${scanId}/export`, '_blank');
}

function exportCSV(data, domain) {
  const headers = ['Subdomain','IP','CNAME','Status','Title','Tech','RTT','MX','404','Takeover'];
  const rows = data.map(r => [
    r.subdomain, (r.records?.A||[]).join(' '), r.cnameChain||'',
    r.status||'', r.title||'', r.tech||'', r.responseTime||'',
    (r.records?.MX||[]).join(' '), r.is404?'yes':'', r.takeover?r.takeoverInfo:'',
  ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(','));
  const blob = new Blob([headers.join(',') + '\n' + rows.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `reconx-${domain}-${Date.now()}.csv`; a.click();
}

function exportJSON(data, domain) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `reconx-${domain}-${Date.now()}.json`; a.click();
}

// ── Main app ──────────────────────────────────────────────────────────────────
export default function Home() {
  const [domain, setDomain]         = useState('');
  const [scanId, setScanId]         = useState(null);
  const [status, setStatus]         = useState('idle');
  const [logs, setLogs]             = useState([]);
  const [counts, setCounts]         = useState({});
  const [progress, setProgress]     = useState(0);
  const [stageIdx, setStageIdx]     = useState(-1);
  const [stageLabel, setStageLabel] = useState('');
  const [allSubdomains, setAllSubdomains] = useState([]);  // all found subdomains
  const [dnsRecords, setDnsRecords] = useState({});        // host -> {A,AAAA,CNAME,...}
  const [results, setResults]       = useState([]);        // final enriched rows
  const [toolCheck, setToolCheck]   = useState(null);
  const [tab, setTab]               = useState('scan');
  const [error, setError]           = useState('');
  const [online, setOnline]         = useState(true);
  const [scanTime, setScanTime]     = useState(0);
  const [startTs, setStartTs]       = useState(null);
  // Filters
  const [subFilter, setSubFilter]   = useState('');
  const [dnsTypeFilter, setDnsTypeFilter] = useState('ALL');
  const [resultFilter, setResultFilter]   = useState('');
  const [statusFilter, setStatusFilter]   = useState('ALL');
  const [sort, setSort]             = useState({ key: 'status', dir: 'desc' });

  const logRef   = useRef(null);
  const esRef    = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    apiFetch(`${API}/tools/check`).then(r => r.json()).then(setToolCheck).catch(() => {});
    apiFetch(`${API}/connectivity`).then(r => r.json()).then(d => setOnline(d.online)).catch(() => {});
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  useEffect(() => {
    if (status === 'running' && startTs) {
      timerRef.current = setInterval(() => setScanTime(Math.floor((Date.now() - startTs) / 1000)), 1000);
    } else clearInterval(timerRef.current);
    return () => clearInterval(timerRef.current);
  }, [status, startTs]);

  const fmtTime = s => s < 60 ? `${s}s` : `${Math.floor(s/60)}m ${s%60}s`;

  const connectSSE = useCallback((id) => {
    if (esRef.current) esRef.current.close();
    let es;
    try { es = new EventSource(sseUrl(`${API_SSE}/scan/${id}/events`)); }
    catch (e) { setError(`SSE failed: ${e.message}`); return; }
    esRef.current = es;

    es.onopen = () => addLog('success', 'Connected to scan stream');

    es.onmessage = (evt) => {
      if (!evt.data || !evt.data.trim()) return;
      try {
        const d = JSON.parse(evt.data);
        switch (d.type) {
          case 'log':
            addLog(d.level, d.msg, d.ts); break;
          case 'stage':
            setStageIdx(d.stageIdx ?? -1);
            setStageLabel(d.stageLabel || '');
            setProgress(d.progress ?? 0);
            addLog('info', `▶ [${d.stageLabel}] started`, null); break;
          case 'progress':
            setProgress(d.progress); break;
          case 'count':
            setCounts(prev => ({ ...prev, [d.key]: d.value })); break;
          case 'subdomains':
            setAllSubdomains(d.list || []); break;
          case 'dns_records':
            setDnsRecords(d.records || {}); break;
          case 'results':
            setResults(d.data || []);
            setTab('results'); break;
          case 'done':
            setStatus('done'); setProgress(100);
            setStageLabel('Scan complete');
            apiFetch(`${API}/scan/${id}/results`).then(r => r.json()).then(rd => {
              if (rd.result?.finalData) setResults(rd.result.finalData);
            });
            es.close(); break;
          case 'cancelled':
            setStatus('cancelled'); es.close(); break;
          case 'status':
            if (d.status === 'error') { setStatus('error'); setError(d.msg || 'Scan failed'); es.close(); }
            else if (d.status === 'done') { setStatus('done'); setProgress(100); es.close(); }
            else if (d.status === 'cancelled') { setStatus('cancelled'); es.close(); }
            break;
          case 'error':
            setError(d.msg); break;
        }
      } catch (e) { console.error('SSE parse:', e); }
    };

    es.onerror = () => addLog('error', 'Stream error — backend may be busy, will retry…');
  }, []);

  const addLog = (level, msg, ts) => {
    setLogs(prev => [...prev.slice(-999), { level, msg, ts: ts || new Date().toISOString() }]);
  };

  const startScan = async () => {
    if (!domain.trim() || status === 'running') return;
    setError(''); setLogs([]); setCounts({}); setProgress(0);
    setAllSubdomains([]); setDnsRecords([]); setResults([]);
    setStageIdx(-1); setStageLabel(''); setScanTime(0); setStartTs(Date.now());
    try {
      const r = await apiFetch(`${API}/scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });
      const d = await r.json();
      if (!r.ok) { setError(d.error || 'Failed'); return; }
      setScanId(d.scanId);
      setStatus('running');
      setTab('logs');
      connectSSE(d.scanId);
    } catch { setError('Cannot reach backend'); }
  };

  const stopScan = async () => {
    if (!scanId) return;
    try {
      await apiFetch(`${API_STOP}/scan/${scanId}/stop`, { method: 'POST' });
      setStatus('stopping');
    } catch {}
  };

  // ── Filtered data ─────────────────────────────────────────────────────────
  const filteredSubdomains = useMemo(() => {
    if (!subFilter) return allSubdomains;
    return allSubdomains.filter(s => s.includes(subFilter.toLowerCase()));
  }, [allSubdomains, subFilter]);

  const filteredDNS = useMemo(() => {
    return Object.entries(dnsRecords).filter(([host, rec]) => {
      if (subFilter && !host.includes(subFilter.toLowerCase())) return false;
      if (dnsTypeFilter !== 'ALL') {
        const vals = rec[dnsTypeFilter] || [];
        if (!vals.length) return false;
      }
      return true;
    });
  }, [dnsRecords, subFilter, dnsTypeFilter]);

  const filteredResults = useMemo(() => {
    return results.filter(r => {
      if (resultFilter && !r.subdomain?.includes(resultFilter) && !r.ip?.includes(resultFilter) && !r.title?.includes(resultFilter)) return false;
      if (statusFilter === '404' && !r.is404) return false;
      if (statusFilter === 'CNAME' && !r.hasCname) return false;
      if (statusFilter === 'TAKEOVER' && !r.takeover) return false;
      if (statusFilter === '2xx' && (r.status < 200 || r.status >= 300)) return false;
      if (statusFilter === '3xx' && (r.status < 300 || r.status >= 400)) return false;
      if (statusFilter === '5xx' && (r.status < 500)) return false;
      return true;
    }).sort((a, b) => {
      const av = a[sort.key] ?? '', bv = b[sort.key] ?? '';
      return sort.dir === 'asc' ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });
  }, [results, resultFilter, statusFilter, sort]);

  const toggleSort = k => setSort(p => p.key === k ? { k, dir: p.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: 'asc' });

  const isRunning = status === 'running' || status === 'stopping';
  const takeovers = results.filter(r => r.takeover);
  const is404s    = results.filter(r => r.is404);
  const hasCnames = results.filter(r => r.hasCname);

  // ── Tabs ──────────────────────────────────────────────────────────────────
  const TABS = [
    { id: 'scan',      label: 'Scan' },
    { id: 'findings',  label: `Findings (${allSubdomains.length})` },
    { id: 'dns',       label: `DNS Records (${Object.keys(dnsRecords).length})` },
    { id: 'results',   label: `HTTP Results (${results.length})` },
    { id: 'logs',      label: `Logs (${logs.length})` },
    { id: 'takeovers', label: `Takeovers (${takeovers.length})`, danger: takeovers.length > 0 },
  ];

  const Th = ({ k, label }) => (
    <th onClick={() => toggleSort(k)} style={{ padding: '9px 12px', textAlign: 'left', fontFamily: C.mono, fontSize: 10, color: sort.key === k ? C.accent : C.muted, textTransform: 'uppercase', letterSpacing: '0.08em', cursor: 'pointer', whiteSpace: 'nowrap', userSelect: 'none', background: C.bg3, borderBottom: `1px solid ${C.border}` }}>
      {label} {sort.key === k ? (sort.dir === 'asc' ? '↑' : '↓') : ''}
    </th>
  );

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: C.bg }}>

      {/* Header */}
      <header style={{ borderBottom: `1px solid ${C.border}`, background: C.bg2, padding: '0 24px', height: 52, display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 100 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <svg width="26" height="26" viewBox="0 0 28 28" fill="none">
            <circle cx="14" cy="14" r="13" stroke={C.accent} strokeWidth="1.5"/>
            <circle cx="14" cy="14" r="8" stroke={C.accent} strokeWidth="1" strokeDasharray="3 2"/>
            <circle cx="14" cy="14" r="3" fill={C.accent}/>
            <line x1="14" y1="1" x2="14" y2="5" stroke={C.accent} strokeWidth="1.5"/>
            <line x1="14" y1="23" x2="14" y2="27" stroke={C.accent} strokeWidth="1.5"/>
            <line x1="1" y1="14" x2="5" y2="14" stroke={C.accent} strokeWidth="1.5"/>
            <line x1="23" y1="14" x2="27" y2="14" stroke={C.accent} strokeWidth="1.5"/>
          </svg>
          <span style={{ fontFamily: C.mono, fontWeight: 700, fontSize: 15, color: C.accent, letterSpacing: '0.06em' }}>RECONX</span>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: C.mono }}>//&nbsp;subdomain intelligence v2</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: online ? C.success : C.danger, display: 'inline-block', boxShadow: online ? `0 0 6px ${C.success}` : 'none' }}/>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: C.mono }}>{online ? 'ONLINE' : 'OFFLINE'}</span>
          {isRunning && <span style={{ fontFamily: C.mono, fontSize: 11, color: C.accent }}>⏱ {fmtTime(scanTime)}</span>}
          {(status === 'done' || status === 'cancelled') && scanId && (
            <div style={{ display: 'flex', gap: 6 }}>
              <button onClick={() => exportHTML(scanId)} style={{ background: C.accent + '22', border: `1px solid ${C.accent}44`, color: C.accent, borderRadius: 4, padding: '4px 10px', fontSize: 10, fontFamily: C.mono, cursor: 'pointer' }}>⬇ HTML</button>
              <button onClick={() => exportCSV(results, domain)} style={{ background: C.success + '22', border: `1px solid ${C.success}44`, color: C.success, borderRadius: 4, padding: '4px 10px', fontSize: 10, fontFamily: C.mono, cursor: 'pointer' }}>⬇ CSV</button>
              <button onClick={() => exportJSON(results, domain)} style={{ background: '#a78bfa22', border: '1px solid #a78bfa44', color: '#a78bfa', borderRadius: 4, padding: '4px 10px', fontSize: 10, fontFamily: C.mono, cursor: 'pointer' }}>⬇ JSON</button>
            </div>
          )}
        </div>
      </header>

      {/* Progress bar — always visible when running */}
      {isRunning && <ProgressBar progress={progress} stageIdx={stageIdx} stageLabel={stageLabel} status={status} />}
      {status === 'done' && <ProgressBar progress={100} stageIdx={4} stageLabel="Scan complete ✓" status="done" />}

      {/* Stats row */}
      {(isRunning || status === 'done' || status === 'cancelled') && (
        <div style={{ background: C.bg, borderBottom: `1px solid ${C.border}`, padding: '16px 24px' }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <Stat label="Passive Found" value={counts.passive} accent={C.accent} sub="from 9 sources" />
            <Stat label="Total (dedup)" value={counts.total}   accent={C.accent} sub="all subdomains" />
            <Stat label="DNS Live"      value={counts.live}    accent={C.success} sub="resolved" />
            <Stat label="HTTP Probed"   value={counts.probed}  accent={C.accent2} sub="httpx" />
            <Stat label="404 Responses" value={is404s.length}  accent={C.warn}    sub="potentially dead" />
            <Stat label="Has CNAME"     value={hasCnames.length} accent={C.warn}  sub="check takeover" />
            <Stat label="Takeovers"     value={takeovers.length} accent={takeovers.length > 0 ? C.danger : C.success} sub={takeovers.length > 0 ? '⚠ verified!' : 'clean'} />
            <Stat label="Status"        value={status.toUpperCase()} accent={status === 'done' ? C.success : status === 'error' ? C.danger : C.warn} sub={fmtTime(scanTime)} />
          </div>
        </div>
      )}

      {/* Takeover alert */}
      {takeovers.length > 0 && (
        <div style={{ background: 'rgba(255,68,68,0.07)', borderBottom: `1px solid rgba(255,68,68,0.3)`, padding: '10px 24px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 18 }}>🚨</span>
          <span style={{ color: '#ff6666', fontFamily: C.mono, fontSize: 12, fontWeight: 700 }}>{takeovers.length} TAKEOVER{takeovers.length > 1 ? 'S' : ''} DETECTED (double-verified)</span>
          <button onClick={() => setTab('takeovers')} style={{ marginLeft: 'auto', background: 'rgba(255,68,68,0.2)', border: '1px solid rgba(255,68,68,0.5)', borderRadius: 4, color: '#ff6666', padding: '3px 10px', fontSize: 11, fontFamily: C.mono, cursor: 'pointer' }}>VIEW →</button>
        </div>
      )}

      {/* Tab bar */}
      <div style={{ background: C.bg2, borderBottom: `1px solid ${C.border}`, padding: '0 24px', display: 'flex', gap: 0, overflowX: 'auto' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{ padding: '12px 18px', background: 'none', border: 'none', borderBottom: tab === t.id ? `2px solid ${C.accent}` : '2px solid transparent', color: tab === t.id ? C.accent : t.danger ? C.danger : C.muted, fontFamily: C.mono, fontSize: 11, cursor: 'pointer', letterSpacing: '0.04em', textTransform: 'uppercase', whiteSpace: 'nowrap', transition: 'color 0.2s' }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, padding: '24px', overflow: 'auto' }}>

        {/* ── SCAN TAB ─────────────────────────────────────────────────────── */}
        {tab === 'scan' && (
          <div className="scan-grid" style={{ maxWidth: 780, margin: '0 auto', padding: '40px 0' }}>
            <h1 className="glow" style={{ fontFamily: C.mono, fontSize: 'clamp(22px,3.5vw,38px)', fontWeight: 700, color: C.accent, marginBottom: 6, letterSpacing: '-0.02em' }}>Subdomain Recon Engine</h1>
            <p style={{ color: C.muted, fontSize: 13, marginBottom: 28 }}>9 passive sources · DNS A/AAAA/CNAME/MX/TXT · HTTP probing · Takeover detection</p>

            <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
              <div style={{ flex: 1, position: 'relative' }}>
                <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: C.accent, fontFamily: C.mono, fontSize: 13 }}>$</span>
                <input value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && startScan()}
                  placeholder="target.com" disabled={isRunning}
                  style={{ width: '100%', height: 46, background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 6, padding: '0 14px 0 34px', color: C.text, fontFamily: C.mono, fontSize: 13, outline: 'none', boxSizing: 'border-box' }}
                  onFocus={e => e.target.style.borderColor = C.accent}
                  onBlur={e => e.target.style.borderColor = C.border} />
              </div>
              <button onClick={startScan} disabled={isRunning || !domain.trim()} style={{ height: 46, padding: '0 24px', background: isRunning ? C.bg3 : C.accent, color: isRunning ? C.muted : '#000', border: 'none', borderRadius: 6, fontFamily: C.mono, fontWeight: 700, fontSize: 12, cursor: isRunning ? 'not-allowed' : 'pointer', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
                {isRunning ? '⟳ SCANNING…' : 'SCAN →'}
              </button>
              {isRunning && (
                <button onClick={stopScan} style={{ height: 46, padding: '0 16px', background: 'rgba(255,68,68,0.15)', color: C.danger, border: `1px solid ${C.danger}44`, borderRadius: 6, fontFamily: C.mono, fontSize: 11, cursor: 'pointer', letterSpacing: '0.05em' }}>
                  ■ STOP
                </button>
              )}
            </div>

            {error && <div style={{ background: 'rgba(255,68,68,0.1)', border: '1px solid rgba(255,68,68,0.3)', borderRadius: 6, padding: '10px 14px', color: '#ff6666', fontSize: 12, fontFamily: C.mono, marginBottom: 14 }}>✗ {error}</div>}

            {/* Tool badges */}
            {toolCheck && (
              <div style={{ marginBottom: 24 }}>
                <div style={{ color: C.muted, fontSize: 10, fontFamily: C.mono, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Installed tools</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {Object.entries(toolCheck.paths || {}).map(([tool, p]) => (
                    <Badge key={tool} color={p ? C.success : C.danger}>{p ? '✓' : '✗'} {tool}</Badge>
                  ))}
                </div>
                {toolCheck.missing?.length > 0 && <div style={{ color: C.warn, fontSize: 11, fontFamily: C.mono, marginTop: 8 }}>⚠ Missing: {toolCheck.missing.join(', ')}</div>}
              </div>
            )}

            {/* Source list */}
            <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16 }}>
              <div style={{ color: C.muted, fontSize: 10, fontFamily: C.mono, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>Passive sources (9)</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
                {['crt.sh','HackerTarget','AlienVault OTX','RapidDNS','BufferOver','urlscan.io','subfinder','assetfinder','amass'].map(s => (
                  <div key={s} style={{ fontSize: 11, fontFamily: C.mono, color: C.text, background: C.bg3, borderRadius: 4, padding: '4px 10px', border: `1px solid ${C.border}` }}>◆ {s}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── FINDINGS TAB ─────────────────────────────────────────────────── */}
        {tab === 'findings' && (
          <div>
            <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
              <input value={subFilter} onChange={e => setSubFilter(e.target.value)} placeholder="Filter subdomains…"
                style={{ flex: 1, maxWidth: 360, height: 34, background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 5, padding: '0 10px', color: C.text, fontFamily: C.mono, fontSize: 12, outline: 'none' }} />
              <span style={{ color: C.muted, fontSize: 11, fontFamily: C.mono }}>{filteredSubdomains.length} subdomains</span>
              {allSubdomains.length > 0 && (
                <button onClick={() => { const b = new Blob([allSubdomains.join('\n')], { type: 'text/plain' }); const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = `subdomains-${domain}.txt`; a.click(); }}
                  style={{ background: C.accent + '22', border: `1px solid ${C.accent}44`, color: C.accent, borderRadius: 4, padding: '4px 10px', fontSize: 10, fontFamily: C.mono, cursor: 'pointer' }}>⬇ TXT</button>
              )}
            </div>
            {allSubdomains.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0', color: C.muted, fontFamily: C.mono, fontSize: 13 }}>
                {isRunning ? '⟳ Waiting for passive enumeration…' : 'No subdomains found yet. Start a scan.'}
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 6 }}>
                {filteredSubdomains.map((s, i) => {
                  const dns = dnsRecords[s];
                  const result = results.find(r => r.subdomain === s);
                  return (
                    <div key={i} style={{ background: C.bg2, border: `1px solid ${result?.takeover ? 'rgba(255,68,68,0.4)' : C.border}`, borderRadius: 6, padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <a href={`https://${s}`} target="_blank" rel="noreferrer" style={{ color: result?.takeover ? C.danger : C.accent, fontFamily: C.mono, fontSize: 11, textDecoration: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{s}</a>
                        <div style={{ display: 'flex', gap: 4, marginLeft: 8, flexShrink: 0 }}>
                          {result?.takeover && <Badge color={C.danger}>⚠ TO</Badge>}
                          {result?.is404 && <Badge color={C.warn}>404</Badge>}
                          {result?.hasCname && <Badge color={C.warn}>CNAME</Badge>}
                          {result?.status && <Badge color={statusColor(result.status)}>{result.status}</Badge>}
                        </div>
                      </div>
                      {dns && (
                        <div style={{ display: 'flex', flexWrap: 'wrap' }}>
                          <RecordPill type="A" values={dns.A} />
                          <RecordPill type="CNAME" values={dns.CNAME} />
                          <RecordPill type="MX" values={dns.MX} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── DNS RECORDS TAB ──────────────────────────────────────────────── */}
        {tab === 'dns' && (
          <div>
            <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
              <input value={subFilter} onChange={e => setSubFilter(e.target.value)} placeholder="Filter host…"
                style={{ flex: 1, maxWidth: 300, height: 34, background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 5, padding: '0 10px', color: C.text, fontFamily: C.mono, fontSize: 12, outline: 'none' }} />
              {['ALL','A','AAAA','CNAME','MX','TXT','NS'].map(t => (
                <button key={t} onClick={() => setDnsTypeFilter(t)} style={{ background: dnsTypeFilter === t ? C.accent + '22' : C.bg2, border: `1px solid ${dnsTypeFilter === t ? C.accent : C.border}`, color: dnsTypeFilter === t ? C.accent : C.muted, borderRadius: 4, padding: '4px 10px', fontSize: 10, fontFamily: C.mono, cursor: 'pointer' }}>{t}</button>
              ))}
              <span style={{ color: C.muted, fontSize: 11, fontFamily: C.mono }}>{filteredDNS.length} hosts</span>
            </div>
            {filteredDNS.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0', color: C.muted, fontFamily: C.mono, fontSize: 13 }}>
                {isRunning ? '⟳ Waiting for DNS resolution…' : 'No DNS records yet.'}
              </div>
            ) : (
              <div style={{ overflowX: 'auto', borderRadius: 8, border: `1px solid ${C.border}` }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr>
                      {['Host','A','AAAA','CNAME','MX','TXT','NS'].map(h => (
                        <th key={h} style={{ padding: '9px 12px', textAlign: 'left', fontFamily: C.mono, fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.08em', background: C.bg3, borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDNS.map(([host, rec], i) => (
                      <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }} onMouseEnter={e => e.currentTarget.style.background = C.bg2} onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        <td style={{ padding: '7px 12px', fontFamily: C.mono, fontSize: 11, color: C.accent, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{host}</td>
                        {['A','AAAA','CNAME','MX','TXT','NS'].map(rt => (
                          <td key={rt} style={{ padding: '7px 12px', fontSize: 10, color: rt === 'CNAME' ? C.warn : C.text, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {(rec[rt] || []).join(', ') || <span style={{ color: C.border }}>—</span>}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── HTTP RESULTS TAB ─────────────────────────────────────────────── */}
        {tab === 'results' && (
          <div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
              <input value={resultFilter} onChange={e => setResultFilter(e.target.value)} placeholder="Filter subdomain, IP, title…"
                style={{ flex: 1, maxWidth: 320, height: 34, background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 5, padding: '0 10px', color: C.text, fontFamily: C.mono, fontSize: 12, outline: 'none' }} />
              {['ALL','2xx','3xx','404','5xx','CNAME','TAKEOVER'].map(f => (
                <button key={f} onClick={() => setStatusFilter(f)} style={{ background: statusFilter === f ? C.accent + '22' : C.bg2, border: `1px solid ${statusFilter === f ? C.accent : C.border}`, color: statusFilter === f ? C.accent : C.muted, borderRadius: 4, padding: '4px 10px', fontSize: 10, fontFamily: C.mono, cursor: 'pointer' }}>{f}</button>
              ))}
              <span style={{ color: C.muted, fontSize: 11, fontFamily: C.mono }}>{filteredResults.length} rows</span>
            </div>
            {results.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0', color: C.muted, fontFamily: C.mono, fontSize: 13 }}>
                {isRunning ? '⟳ Waiting for HTTP probe…' : 'No HTTP results yet.'}
              </div>
            ) : (
              <div style={{ overflowX: 'auto', borderRadius: 8, border: `1px solid ${C.border}` }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr>
                      <Th k="subdomain" label="Subdomain" />
                      <Th k="ip" label="IP" />
                      <Th k="status" label="Status" />
                      <Th k="title" label="Title" />
                      <Th k="tech" label="Tech" />
                      <Th k="responseTime" label="RTT" />
                      <th style={{ padding: '9px 12px', textAlign: 'left', fontFamily: C.mono, fontSize: 10, color: C.muted, textTransform: 'uppercase', background: C.bg3, borderBottom: `1px solid ${C.border}` }}>CNAME</th>
                      <th style={{ padding: '9px 12px', textAlign: 'left', fontFamily: C.mono, fontSize: 10, color: C.muted, textTransform: 'uppercase', background: C.bg3, borderBottom: `1px solid ${C.border}` }}>Flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResults.map((r, i) => (
                      <tr key={i} style={{ borderBottom: `1px solid ${C.border}`, background: r.takeover ? 'rgba(255,68,68,0.04)' : 'transparent' }}
                        onMouseEnter={e => !r.takeover && (e.currentTarget.style.background = C.bg2)}
                        onMouseLeave={e => !r.takeover && (e.currentTarget.style.background = 'transparent')}>
                        <td style={{ padding: '7px 12px', fontFamily: C.mono, fontSize: 11, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <a href={r.url || `https://${r.subdomain}`} target="_blank" rel="noreferrer" style={{ color: r.takeover ? C.danger : C.accent, textDecoration: 'none' }}>{r.subdomain}</a>
                        </td>
                        <td style={{ padding: '7px 12px', fontFamily: C.mono, fontSize: 10, color: C.muted }}>{r.ip || '—'}</td>
                        <td style={{ padding: '7px 12px' }}>{r.status ? <Badge color={statusColor(r.status)}>{r.status}</Badge> : <span style={{ color: C.muted }}>—</span>}</td>
                        <td style={{ padding: '7px 12px', fontSize: 11, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.title || '—'}</td>
                        <td style={{ padding: '7px 12px', fontSize: 10 }}>
                          {r.tech ? r.tech.split(',').slice(0,3).map((t, ti) => (
                            <span key={ti} style={{ background: '#7c3aed22', color: '#a78bfa', border: '1px solid #7c3aed33', borderRadius: 3, padding: '1px 5px', fontSize: 9, fontFamily: C.mono, marginRight: 3 }}>{t.trim()}</span>
                          )) : '—'}
                        </td>
                        <td style={{ padding: '7px 12px', fontFamily: C.mono, fontSize: 10, color: C.muted }}>{r.responseTime || '—'}</td>
                        <td style={{ padding: '7px 12px', fontSize: 10, color: C.warn, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.cnameChain || '—'}</td>
                        <td style={{ padding: '7px 12px' }}>
                          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                            {r.takeover && <Badge color={C.danger}>⚠ {r.takeoverInfo || 'TAKEOVER'}</Badge>}
                            {r.is404 && <Badge color={C.warn}>404</Badge>}
                            {r.hasCname && <Badge color={C.warn}>CNAME</Badge>}
                            {r.isWildcard && <Badge color="#a78bfa">WILDCARD</Badge>}
                            {!r.takeover && !r.is404 && !r.hasCname && !r.isWildcard && <Badge color={C.success}>CLEAN</Badge>}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── LOGS TAB ─────────────────────────────────────────────────────── */}
        {tab === 'logs' && (
          <div>
            <div ref={logRef} style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 8, padding: 14, height: 'calc(100vh - 300px)', minHeight: 300, overflowY: 'auto', fontFamily: C.mono, fontSize: 11 }}>
              {logs.length === 0 ? (
                <div style={{ color: C.muted, textAlign: 'center', paddingTop: 40 }}>{isRunning ? '⟳ Waiting for logs…' : 'No logs.'}</div>
              ) : logs.map((l, i) => (
                <div key={i} style={{ marginBottom: 2, display: 'flex', gap: 10, lineHeight: 1.5 }}>
                  <span style={{ color: '#333', flexShrink: 0, width: 75 }}>{new Date(l.ts).toLocaleTimeString()}</span>
                  <span style={{ color: levelColor[l.level] || C.muted, flexShrink: 0, width: 58 }}>[{(l.level||'info').toUpperCase()}]</span>
                  <span style={{ color: C.text }}>{l.msg}</span>
                </div>
              ))}
              {isRunning && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, color: C.accent }}>
                  <span className="spinner" style={{ display: 'inline-block', width: 9, height: 9, border: `2px solid ${C.accent}`, borderTopColor: 'transparent', borderRadius: '50%' }}/>
                  <span>Scanning in progress… {progress}%</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── TAKEOVERS TAB ────────────────────────────────────────────────── */}
        {tab === 'takeovers' && (
          <div>
            {takeovers.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0' }}>
                <div style={{ fontSize: 42, marginBottom: 12 }}>✅</div>
                <div style={{ color: C.success, fontFamily: C.mono, fontSize: 13 }}>No takeovers detected</div>
                <div style={{ color: C.muted, fontSize: 11, marginTop: 6 }}>All subdomains passed double-verification</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {takeovers.map((t, i) => (
                  <div key={i} style={{ background: 'rgba(255,68,68,0.06)', border: '1px solid rgba(255,68,68,0.3)', borderRadius: 8, padding: '16px 20px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                      <div>
                        <span style={{ fontFamily: C.mono, fontSize: 13, color: '#ff6666', fontWeight: 700 }}>⚠ SUBDOMAIN TAKEOVER</span>
                        <div><a href={t.url || `https://${t.subdomain}`} target="_blank" rel="noreferrer" style={{ fontFamily: C.mono, fontSize: 12, color: C.danger }}>{t.subdomain}</a></div>
                      </div>
                      <Badge color={C.danger}>{t.takeoverInfo}</Badge>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 8, marginTop: 8 }}>
                      <div><div style={{ color: C.muted, fontSize: 10, marginBottom: 2 }}>IP (A records)</div><div style={{ fontFamily: C.mono, fontSize: 11 }}>{(t.records?.A || []).join(', ') || t.ip || '—'}</div></div>
                      <div><div style={{ color: C.muted, fontSize: 10, marginBottom: 2 }}>CNAME chain</div><div style={{ fontFamily: C.mono, fontSize: 11, color: C.warn }}>{t.cnameChain || '—'}</div></div>
                      <div><div style={{ color: C.muted, fontSize: 10, marginBottom: 2 }}>HTTP Status</div><div>{t.status ? <Badge color={statusColor(t.status)}>{t.status}</Badge> : '—'}</div></div>
                      <div><div style={{ color: C.muted, fontSize: 10, marginBottom: 2 }}>Title</div><div style={{ fontSize: 11 }}>{t.title || '—'}</div></div>
                      <div><div style={{ color: C.muted, fontSize: 10, marginBottom: 2 }}>Tech</div><div style={{ fontSize: 11 }}>{t.tech || '—'}</div></div>
                    </div>
                    <div style={{ marginTop: 12, padding: '8px 12px', background: 'rgba(255,68,68,0.06)', borderRadius: 4, fontSize: 11, fontFamily: C.mono, color: C.muted }}>
                      ⚠ Confirmed via nuclei double-scan. Verify manually before reporting.
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <footer style={{ borderTop: `1px solid ${C.border}`, padding: '10px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: C.bg2 }}>
        <span style={{ color: C.muted, fontSize: 11, fontFamily: C.mono }}>Powered by <span style={{ color: C.accent }}>Rajeshwar Singh</span></span>
        <span style={{ color: C.muted, fontSize: 10, fontFamily: C.mono }}>ReconX v2.0 · Bug Bounty Edition · 9 Sources · Zero False Positives</span>
      </footer>
    </div>
  );
}
