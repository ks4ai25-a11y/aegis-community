import React, {Component, useEffect, useMemo, useRef, useState, type ReactNode} from 'react';
import {createRoot} from 'react-dom/client';
import {Activity, ArrowRight, ChevronRight, Clock3, Command, Eye, FileCheck2, FileSearch, FolderLock, Globe, Layers3, LayoutDashboard, LockKeyhole, LogOut, Menu, Moon, Radio, RefreshCw, RotateCcw, Search, Settings, Shield, ShieldCheck, Sun, Terminal, X, Zap} from 'lucide-react';
import {Sites} from './Sites';
import {Exposure} from './Exposure';
import {Assessment, AIPage, Proposals} from './Assessment';
import {api, setCSRF, key, short} from './client';
import './style.css';
import {Report} from './Report';
import {Verification} from './Verification';
import {Repositories} from './Repositories';
import {Scans} from './Scans';
import {Catalogue} from './Catalogue';

type Page = 'Overview' | 'Sites' | 'Live activity' | 'Incidents' | 'Endpoints' | 'Policies' | 'Verify' | 'Repositories' | 'Scans' | 'Findings' | 'AI Apps' | 'Settings';
type Icon = typeof Shield;
const groups: {label: string; items: [Page, Icon][]}[] = [
  {label: 'Defend', items: [['Overview', LayoutDashboard], ['Sites', Globe], ['Live activity', Activity], ['Incidents', Layers3], ['Endpoints', Radio], ['Policies', Shield]]},
  {label: 'Research', items: [['Verify', FileCheck2], ['Repositories', FolderLock], ['Scans', Terminal], ['Findings', FileSearch]]},
  {label: 'Platform', items: [['AI Apps', Zap], ['Settings', Settings]]},
];
const subtitles: Record<Page, string> = {
  'Overview': 'A clear view of your gateway, observations and tested controls.',
  'Sites': 'Applications behind this gateway, each with its own host names, origin and mode.',
  'Live activity': 'Sanitized records from your real gateway. Each decision retains its source.',
  'Incidents': 'Evidence-backed observations. A match does not establish successful exploitation.',
  'Endpoints': 'Bounded route inventory derived from retained request metadata.',
  'Policies': 'Structured controls. Review, validate, explicitly approve and roll back.',
  'Verify': 'Run fixed synthetic inputs inside the isolated bundled fixture.',
  'Repositories': 'Inspect provisioned read-only source and its declared application map.',
  'Scans': 'Queue offline tools and review static evidence without claiming complete coverage.',
  'Findings': 'Browse retained static observations with exact scan and source provenance.',
  'AI Apps': 'Optional, local and advisory: assess incidents with or without a model.',
  'Settings': 'Local configuration, privacy and operational health.',
};
const number = (v: unknown) => typeof v === 'number' ? v.toLocaleString() : '—';

type Theme = 'dark' | 'light';
function initialTheme(): Theme {
  try { const t = localStorage.getItem('aegis-theme'); if (t === 'dark' || t === 'light') return t; } catch {}
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

// A page that throws must not blank the whole console.
class Boundary extends Component<{page: string; children: ReactNode}, {error?: string}> {
  state: {error?: string} = {};
  static getDerivedStateFromError(e: Error) { return {error: e.message}; }
  componentDidUpdate(prev: {page: string}) { if (prev.page !== this.props.page && this.state.error) this.setState({error: undefined}); }
  render() {
    if (!this.state.error) return this.props.children;
    return <section className="card"><div role="alert" className="alert error">This view could not be displayed: {this.state.error}. Other pages keep working.</div><button className="button light" onClick={() => this.setState({error: undefined})}><RotateCcw size={15}/>Try again</button></section>;
  }
}

function App() {
  const [session, setSession] = useState(false), [loading, setLoading] = useState(true), [page, setPage] = useState<Page>('Overview'), [initialScan, setInitialScan] = useState('');
  const [status, setStatus] = useState<any>(), [error, setError] = useState(''), [busy, setBusy] = useState(false), [refresh, setRefresh] = useState(0), [toast, setToast] = useState('');
  const [site, setSite] = useState('site_demo'), [sites, setSites] = useState<any[]>([]), [drawer, setDrawer] = useState(false), [palette, setPalette] = useState(false), [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem('aegis-theme', theme); } catch {} }, [theme]);
  useEffect(() => { api('/auth/session').then(v => { setCSRF(v.csrf_token); setSession(true); }).catch(() => {}).finally(() => setLoading(false)); }, []);
  useEffect(() => {
    if (!session) return;
    api('/sites').then(v => {
      if (!Array.isArray(v.items) || !v.items.every((x: any) => x && typeof x.site_id === 'string' && typeof x.display_name === 'string')) throw new Error('Invalid site catalogue');
      setSites(v.items);
      if (!v.items.some((x: any) => x.site_id === site)) setSite('site_demo');
    }).catch(() => {});
  }, [session, refresh]);
  useEffect(() => {
    if (!session) return;
    let stopped = false;
    const update = () => api('/system/status').then(v => { if (!stopped) { setStatus(v); setError(''); } }).catch(e => { if (!stopped) setError(e.message); });
    update();
    const t = setInterval(update, 5000);
    return () => { stopped = true; clearInterval(t); };
  }, [session, refresh]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(p => !p); } };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  useEffect(() => { if (!toast) return; const t = setTimeout(() => setToast(''), 6000); return () => clearTimeout(t); }, [toast]);
  async function action(work: () => Promise<any>, message?: string) {
    setBusy(true); setError('');
    try { const value = await work(); if (message) setToast(message); setRefresh(x => x + 1); return value; }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  const go = (p: Page) => { setPage(p); setInitialScan(''); setToast(''); setDrawer(false); setPalette(false); window.scrollTo?.(0, 0); };

  if (loading) return <div className="loading"><span className="brand-mark large"><Shield size={28}/></span><p>Opening local console…</p></div>;
  if (!session) return <Auth onSuccess={v => { setCSRF(v); setSession(true); }}/>;
  const protect = status?.mode === 'protect';
  return <div className={'shell' + (drawer ? ' drawer-open' : '')}>
    <aside aria-label="Sidebar">
      <div className="brand"><span className="brand-mark"><Shield size={20}/></span><span className="brand-name">Aegis<small>Community</small></span><button className="icon only-mobile" aria-label="Close navigation" onClick={() => setDrawer(false)}><X size={18}/></button></div>
      <div className="workspace">
        <span className="workspace-avatar">L</span>
        <span className="workspace-text"><strong>Local workspace</strong><small>Single node · self-hosted</small></span>
      </div>
      {sites.length > 1 && <label className="site-picker">Site<select aria-label="Selected site" value={site} onChange={e => setSite(e.target.value)}>{sites.map(x => <option key={x.site_id} value={x.site_id}>{x.display_name}</option>)}</select></label>}
      <nav aria-label="Main navigation">
        {groups.map(g => <div className="nav-group" key={g.label}>
          <div className="nav-label">{g.label}</div>
          {g.items.map(([n, Icon]) => <button aria-label={n} aria-current={page === n ? 'page' : undefined} className={page === n ? 'nav active' : 'nav'} onClick={() => go(n)} key={n}>
            <Icon size={17}/><span>{n}</span>{n === 'Incidents' && status?.open_incidents > 0 && <span className="count" aria-hidden="true">{status.open_incidents}</span>}
          </button>)}
        </div>)}
      </nav>
      <div className="aside-bottom">
        <div className="health"><span className={'dot ' + (status?.gateway_healthy ? 'ok' : 'warn')}/>{status?.gateway_healthy ? 'Gateway healthy' : 'Gateway unconfirmed'}</div>
        <div className="aside-note"><LockKeyhole size={13}/>Local-first. No external services.</div>
        <small>{status?.version || 'Connecting…'} · internal alpha</small>
      </div>
    </aside>
    {drawer && <div className="scrim" onClick={() => setDrawer(false)}/>}
    <main>
      <header>
        <button className="icon only-mobile" aria-label="Open navigation" onClick={() => setDrawer(true)}><Menu size={18}/></button>
        <div className="breadcrumb"><span className="crumb-root">Workspace</span><ChevronRight size={13}/><span>{page}</span></div>
        <button className="search" onClick={() => setPalette(true)} aria-label="Search pages"><Search size={15}/><span>Jump to…</span><kbd><Command size={11}/>K</kbd></button>
        <div className="header-right">
          <span className={'mode-chip ' + (protect ? 'protect' : 'observe')}><span className="dot"/>{protect ? 'Protect' : 'Observe'}</span>
          <button aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} className="icon" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun size={16}/> : <Moon size={16}/>}</button>
          <button aria-label="Refresh status" className="icon" onClick={() => setRefresh(x => x + 1)}><RefreshCw size={16}/></button>
          <button className="avatar" aria-label="Sign out" title="Sign out" onClick={() => action(async () => { await api('/auth/logout', {}); setSession(false); })}><LogOut size={15}/></button>
        </div>
      </header>
      <div className="content">
        <div className="page-heading">
          <div>
            {page === 'Overview' ? <><div className="eyebrow">Defence, with evidence</div><h1>Your security, in focus.</h1></> : <h1>{page}</h1>}
            <p>{subtitles[page]}</p>
          </div>
          {site === 'site_demo' && page !== 'Repositories' && page !== 'Scans' && page !== 'Findings' && <span className="pill">Bundled demo · synthetic data</span>}
        </div>
        {error && <div role="alert" className="alert error">{error}<button onClick={() => setError('')} aria-label="Dismiss error"><X size={14}/></button></div>}
        {toast && <div role="status" className="alert success">{toast}<button onClick={() => setToast('')} aria-label="Dismiss message"><X size={14}/></button></div>}
        <Boundary page={page}>
          {page === 'Overview' && <Overview status={status} site={site} refresh={refresh} busy={busy} go={go} action={action}/>}
          {page === 'Sites' && <Sites action={action} busy={busy} refresh={refresh} onSelect={id => { setSite(id); go('Live activity'); }}/>}
          {page === 'Live activity' && <Events site={site} refresh={refresh}/>}
          {page === 'Incidents' && <Incidents site={site} refresh={refresh}/>}
          {page === 'Endpoints' && <><Exposure site={site}/><Collection path={'/sites/' + site + '/endpoints'} title="Observed endpoints" refresh={refresh} columns={['method', 'route_template', 'requests_retained']} footnote="Observed route patterns are inventory hints. A generic WAF cannot reliably prevent BOLA without application ownership context."/></>}
          {page === 'Policies' && <Policies site={site} action={action} busy={busy} refresh={refresh}/>}
          {page === 'Verify' && <Verification action={action} busy={busy} status={status}/>}
          {page === 'Repositories' && <Repositories action={action} busy={busy}/>}
          {page === 'Scans' && <Scans action={action} busy={busy} initialJob={initialScan}/>}
          {page === 'Findings' && <Catalogue onOpenScan={id => { go('Scans'); setInitialScan(id); }}/>}
          {page === 'AI Apps' && <AIPage/>}
          {page === 'Settings' && <SettingsPage refresh={refresh} theme={theme} setTheme={setTheme}/>}
        </Boundary>
        <footer><Shield size={13}/>Aegis Community<span>Evidence speaks. Claims stay precise.</span></footer>
      </div>
    </main>
    {palette && <Palette onClose={() => setPalette(false)} onGo={go}/>}
  </div>;
}

function Palette({onClose, onGo}: {onClose: () => void; onGo: (p: Page) => void}) {
  const [q, setQ] = useState(''), [index, setIndex] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const all = groups.flatMap(g => g.items.map(([n, Icon]) => ({n, Icon, group: g.label})));
  const shown = all.filter(x => (x.n + ' ' + x.group + ' ' + subtitles[x.n]).toLowerCase().includes(q.toLowerCase()));
  useEffect(() => { input.current?.focus(); }, []);
  useEffect(() => setIndex(0), [q]);
  return <div className="palette-backdrop" onMouseDown={onClose}>
    <div className="palette" role="dialog" aria-modal="true" aria-label="Jump to a page" onMouseDown={e => e.stopPropagation()}>
      <div className="palette-input"><Search size={16}/><input ref={input} value={q} onChange={e => setQ(e.target.value)} placeholder="Jump to a page…" aria-label="Search pages" role="combobox" aria-expanded="true" aria-controls="palette-list"
        onKeyDown={e => {
          if (e.key === 'Escape') onClose();
          if (e.key === 'ArrowDown') { e.preventDefault(); setIndex(i => Math.min(i + 1, shown.length - 1)); }
          if (e.key === 'ArrowUp') { e.preventDefault(); setIndex(i => Math.max(i - 1, 0)); }
          if (e.key === 'Enter' && shown[index]) onGo(shown[index].n);
        }}/><kbd>Esc</kbd></div>
      <ul id="palette-list" role="listbox" aria-label="Pages">
        {shown.map((x, i) => <li key={x.n} role="option" aria-selected={i === index} className={i === index ? 'selected' : ''} onMouseEnter={() => setIndex(i)} onClick={() => onGo(x.n)}>
          <x.Icon size={16}/><span><strong>{x.n}</strong><small>{subtitles[x.n]}</small></span><em>{x.group}</em>
        </li>)}
        {!shown.length && <li className="palette-empty">No matching page</li>}
      </ul>
    </div>
  </div>;
}

function Overview({status, site, refresh, busy, go, action}: {status: any; site: string; refresh: number; busy: boolean; go: (p: Page) => void; action: (w: () => Promise<any>, m?: string) => Promise<any>}) {
  const [items, setItems] = useState<any[]>([]), [incidents, setIncidents] = useState<any[]>([]);
  useEffect(() => {
    let live = true;
    const read = () => api('/sites/' + site + '/events?limit=100').then(v => { if (live && Array.isArray(v.items)) setItems(v.items); }).catch(() => {});
    read();
    api('/sites/' + site + '/incidents').then(v => { if (live && Array.isArray(v.items)) setIncidents(v.items); }).catch(() => {});
    const t = setInterval(read, 5000);
    return () => { live = false; clearInterval(t); };
  }, [site, refresh]);
  const protect = status?.mode === 'protect';
  const decisions = useMemo(() => {
    const c: Record<string, number> = {allowed: 0, observed: 0, blocked_waf: 0, other: 0};
    for (const {event: e} of items) c[e?.decision in c ? e.decision : 'other']++;
    return c;
  }, [items]);
  const total = items.length || 1;
  const buckets = useMemo(() => {
    const times = items.map(x => Date.parse(x.event?.observed_at)).filter(n => !Number.isNaN(n));
    if (!times.length) return [] as number[];
    const max = Math.max(...times), span = 30 * 60 * 1000, n = 24, out = Array(n).fill(0);
    for (const t of times) { const i = Math.floor((max - t) / (span / n)); if (i >= 0 && i < n) out[n - 1 - i]++; }
    return out;
  }, [items]);
  return <>
    <section className={'hero ' + (protect ? 'protected' : '')}>
      <div className="hero-icon">{protect ? <ShieldCheck size={26}/> : <Eye size={26}/>}</div>
      <div className="hero-text">
        <div className="eyebrow">Current gateway mode</div>
        <h2>{protect ? 'Protect is active' : 'Observe is active'}</h2>
        <p>{protect ? 'Approved CRS rules can deny matching requests.' : 'Traffic is inspected for rule matches. WAF matches do not block traffic.'}</p>
      </div>
      <div className="hero-actions">
        <button className="button light" onClick={() => go('Policies')}>Review protection<ArrowRight size={15}/></button>
      </div>
    </section>
    <div className="stats">
      <Stat label="Retained source records" value={number(status?.requests_retained)} note="Access and WAF records counted separately" icon={Activity} spark={buckets}/>
      <Stat label="Open observations" value={number(status?.open_incidents)} note="Rule matches requiring review" icon={Layers3} tone={status?.open_incidents > 0 ? 'warn' : undefined}/>
      <Stat label="Dropped telemetry" value={number(status?.events_dropped_total)} note="Missing records are not allowed requests" icon={Radio} tone={status?.events_dropped_total > 0 ? 'danger' : undefined}/>
      <Stat label="Gateway" value={status?.gateway_healthy ? 'Healthy' : 'Unknown'} note={'Revision ' + short(status?.gateway_revision) + (status?.canary ? ' · live canary ' + status.canary.outcome.toLowerCase() + ' ' + new Date(status.canary.checked_at).toLocaleTimeString() : ' · live canary pending')} icon={ShieldCheck} tone={status?.gateway_healthy ? 'ok' : 'warn'}/>
    </div>
    <div className="grid-3">
      <section className="card span-2">
        <div className="card-heading"><h2>Traffic decisions</h2><span className="muted small">Last {items.length} retained records</span></div>
        <div className="decision-bar" role="img" aria-label={`Allowed ${decisions.allowed}, observed ${decisions.observed}, blocked ${decisions.blocked_waf}, other ${decisions.other}`}>
          {(['allowed', 'observed', 'blocked_waf', 'other'] as const).map(k => decisions[k] > 0 && <span key={k} className={'seg ' + k} style={{width: (100 * decisions[k] / total) + '%'}}/>)}
        </div>
        <div className="legend">
          {([['allowed', 'Allowed'], ['observed', 'Observed match'], ['blocked_waf', 'Blocked by WAF'], ['other', 'Other']] as const).map(([k, label]) => <div key={k}><span className={'swatch ' + k}/>{label}<strong>{decisions[k]}</strong></div>)}
        </div>
        <div className="subhead"><h3>Open incidents</h3><button className="text-link" onClick={() => go('Incidents')}>View all<ArrowRight size={13}/></button></div>
        {incidents.length === 0 ? <p className="muted small">No observations to review.</p> : <ul className="incident-mini">{incidents.slice(0, 4).map(i => <li key={i.incident_id}><span className={'sev ' + i.severity}/>{i.summary}<small>{i.detector_id} · {new Date(i.opened_at).toLocaleString()}</small></li>)}</ul>}
      </section>
      <section className="card">
        <div className="card-heading"><h2>System health</h2><ShieldCheck size={18}/></div>
        <div className="system-row"><span>Gateway & ruleset</span><span className="status-text">{status?.gateway_healthy ? 'Healthy' : 'Unconfirmed'}</span></div>
        <div className="system-row"><span>Control plane</span><span className="status-text">Connected</span></div>
        <div className="system-row"><span>Storage</span><span>{status ? ((status.database_bytes / 1048576).toFixed(1) + ' MiB') : '—'}</span></div>
        <div className="system-row"><span>External services</span><span className="muted">None required</span></div>
        <div className="note"><LockKeyhole size={16}/><p>The gateway keeps its last approved configuration if the console, controller or AI app stops.</p></div>
      </section>
    </div>
    <section className="card">
      <div className="card-heading"><h2>Start with something verifiable.</h2><span className="step-label">Getting started</span></div>
      <div className="journeys">
        <div className="journey"><span className="step-num">1</span><div><strong>Observe a real rule match</strong><p>Run ordinary and synthetic negative requests.</p></div></div>
        <div className="journey"><span className="step-num">2</span><div><strong>Review and activate Protect</strong><p>Validate the candidate, then approve blocking.</p></div></div>
        <div className="journey"><span className="step-num">3</span><div><strong>Inspect the evidence</strong><p>Compare baseline and candidate in an isolated fixture.</p></div></div>
      </div>
      <button disabled={busy} className="button primary" onClick={() => action(() => api('/demo/traffic', {}), 'Demo requests sent. Inspect Live activity for actual records.')}>{busy ? 'Running…' : 'Run safe demo traffic'}<ArrowRight size={15}/></button>
    </section>
    <Events site={site} refresh={refresh} compact/>
  </>;
}

function Auth({onSuccess}: {onSuccess: (csrf: string) => void}) {
  const [setup, setSetup] = useState(false), [token, setToken] = useState(''), [password, setPassword] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  return <div className="auth-page">
    <div className="auth-art">
      <div className="brand"><span className="brand-mark"><Shield size={20}/></span><span className="brand-name">Aegis<small>Community</small></span></div>
      <div>
        <div className="eyebrow">Self-hosted web defence</div>
        <h1>Protection you<br/>can inspect.</h1>
        <p>Observe real traffic. Review your controls. Verify exactly what the evidence proves.</p>
        <ul className="auth-points"><li><ShieldCheck size={16}/>Pinned Caddy, Coraza and OWASP CRS gateway</li><li><FileCheck2 size={16}/>Every decision keeps its source record</li><li><LockKeyhole size={16}/>No account, model or paid service required</li></ul>
      </div>
      <small>Local-first. Your data stays on this host.</small>
    </div>
    <form className="auth-form" onSubmit={async e => {
      e.preventDefault(); setBusy(true);
      try { const v = await api(setup ? '/auth/bootstrap' : '/auth/login', {password, ...(setup ? {token} : {})}); onSuccess(v.csrf_token); }
      catch (e) { setError((e as Error).message); }
      finally { setBusy(false); }
    }}>
      <span className="brand-mark large"><Shield size={26}/></span>
      <h2>{setup ? 'Enroll the first owner' : 'Welcome back.'}</h2>
      <p className="muted">{setup ? 'Use the short-lived bootstrap token printed in the local controller logs.' : 'Sign in to your local Aegis console.'}</p>
      {error && <div role="alert" className="alert error">{error}</div>}
      {setup && <label>Bootstrap token<input required value={token} onChange={e => setToken(e.target.value)} autoComplete="off"/></label>}
      <label>Owner passphrase<input type="password" minLength={setup ? 14 : 1} maxLength={256} required value={password} onChange={e => setPassword(e.target.value)} autoComplete={setup ? 'new-password' : 'current-password'}/></label>
      <button disabled={busy} className="button primary">{busy ? 'Checking…' : setup ? 'Enroll owner' : 'Sign in'}<ArrowRight size={16}/></button>
      <button type="button" className="text-button" onClick={() => { setSetup(!setup); setError(''); }}>{setup ? 'Already enrolled? Sign in' : 'First installation? Enroll owner'}</button>
      <div className="note"><LockKeyhole size={15}/><p>Keep administration on loopback or a trusted private tunnel. New installations start in Observe.</p></div>
    </form>
  </div>;
}

function Spark({values}: {values: number[]}) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 1), w = 120, h = 32;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - (v / max) * (h - 4) - 2}`).join(' ');
  return <svg className="spark" viewBox={`0 0 ${w} ${h}`} aria-hidden="true" preserveAspectRatio="none"><polyline points={pts}/><polygon points={`0,${h} ${pts} ${w},${h}`}/></svg>;
}

function Stat({label, value, note, icon: Icon, tone, spark}: {label: string; value: ReactNode; note: string; icon: Icon; tone?: 'ok' | 'warn' | 'danger'; spark?: number[]}) {
  return <section className={'stat' + (tone ? ' ' + tone : '')}>
    <div className="stat-label">{label}<Icon size={16}/></div>
    <strong>{value ?? '—'}</strong>
    {spark && <Spark values={spark}/>}
    <small>{note}</small>
  </section>;
}

function Events({site = 'site_demo', refresh, compact = false}: {site?: string; refresh: number; compact?: boolean}) {
  const [items, setItems] = useState<any[]>([]), [filter, setFilter] = useState('all'), [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    const read = () => api('/sites/' + site + '/events?limit=100').then(v => { if (live) { setItems(Array.isArray(v.items) ? v.items : []); setError(''); } }).catch(e => { if (live) setError(e.message); });
    read();
    const t = setInterval(read, 2500);
    return () => { live = false; clearInterval(t); };
  }, [site, refresh]);
  const shown = items.filter(x => filter === 'all' || x.event.decision === filter).slice().reverse().slice(0, compact ? 7 : 100);
  return <section className="card activity">
    <div className="card-heading"><h2>Gateway activity</h2><div className="live-label"><span className="dot ok pulse"/>Live · every 2.5s</div></div>
    {!compact && <label className="filter">Decision<select value={filter} onChange={e => setFilter(e.target.value)}>{['all', 'observed', 'allowed', 'blocked_waf', 'upstream_error', 'unknown'].map(v => <option key={v}>{v}</option>)}</select></label>}
    {error && <div role="alert" className="alert error">Telemetry unavailable: {error}. Previous records may be stale.</div>}
    <div className="table-wrap"><table>
      <thead><tr><th>Observed at</th><th>Request / route</th><th>Source</th><th>Decision</th><th>Rule / status</th><th>Revision</th></tr></thead>
      <tbody>{shown.map(({event: e}) => <tr key={e.event_id}>
        <td className="mono" title={e.observed_at}>{new Date(e.observed_at).toLocaleTimeString()}</td>
        <td><span className="method">{e.method || 'WAF'}</span><span className="mono">{e.route_template || short(e.request_id)}</span></td>
        <td>{e.source}</td>
        <td><span className={'badge ' + (e.decision === 'blocked_waf' ? 'blocked' : e.decision === 'observed' ? 'observed' : e.decision === 'allowed' ? 'allowed' : '')}>{e.decision.replaceAll('_', ' ')}</span></td>
        <td className="mono">{e.rule_ids?.join(', ') || e.http_status || 'Unknown'}</td>
        <td className="mono muted">{short(e.gateway_revision)}</td>
      </tr>)}</tbody>
    </table>{!shown.length && <Empty title="Waiting for gateway evidence" text="Run safe demo traffic to generate actual, sanitized source records."/>}</div>
    <p className="table-note">Access and WAF records are separate sources. Missing telemetry never implies an allowed request.</p>
  </section>;
}

function Empty({title, text}: {title: string; text: string}) {
  return <div className="empty"><span className="empty-icon"><Radio size={22}/></span><h3>{title}</h3><p>{text}</p></div>;
}

function Collection({path, refresh, columns, footnote, title}: {path: string; refresh: number; columns: string[]; footnote?: string; title?: string}) {
  const [data, setData] = useState<any[]>([]), [error, setError] = useState('');
  useEffect(() => { api(path).then(v => setData(Array.isArray(v.items) ? v.items : [])).catch(e => setError(e.message)); }, [path, refresh]);
  return <section className="card">
    {title && <div className="card-heading"><h2>{title}</h2><span className="muted small">{data.length} retained</span></div>}
    {error && <div className="alert error">{error}</div>}
    <div className="table-wrap"><table>
      <thead><tr>{columns.map(c => <th key={c}>{c.replaceAll('_', ' ')}</th>)}</tr></thead>
      <tbody>{data.map((v, i) => <tr key={i}>{columns.map(c => <td key={c} className={/hash|digest/.test(c) ? 'mono' : ''}>{typeof v[c] === 'object' ? JSON.stringify(v[c]) : typeof v[c] === 'number' ? v[c].toLocaleString() : String(v[c] ?? '—')}</td>)}</tr>)}</tbody>
    </table>{!data.length && <Empty title="No retained records yet" text="Generate synthetic demo traffic, then refresh."/>}</div>
    {footnote && <div className="note"><Eye size={16}/><p>{footnote}</p></div>}
  </section>;
}

function Incidents({site, refresh}: {site: string; refresh: number}) {
  const [items, setItems] = useState<any[]>([]), [detail, setDetail] = useState<any>(), [error, setError] = useState('');
  useEffect(() => { setDetail(undefined); api('/sites/' + site + '/incidents').then(v => setItems(Array.isArray(v.items) ? v.items : [])).catch(e => setError(e.message)); }, [site, refresh]);
  return <>
    {error && <div className="alert error">{error}</div>}
    <section className="card">
      {!items.length && <Empty title="No observations to review" text="The safe demo can generate a genuine CRS pattern match."/>}
      {items.map(v => <button className={'incident-row' + (detail?.incident_id === v.incident_id ? ' selected' : '')} key={v.incident_id} onClick={() => api('/incidents/' + encodeURIComponent(v.incident_id)).then(setDetail).catch(e => setError(e.message))}>
        <span className={'incident-icon ' + v.severity}><Layers3 size={18}/></span>
        <span className="incident-text"><strong>{v.summary}</strong><small>{v.detector_id} · {new Date(v.opened_at).toLocaleString()} · {v.synthetic ? 'synthetic · ' : ''}{v.state}</small></span>
        <span className={'badge sev-' + v.severity}>{v.severity} impact</span><ChevronRight size={16}/>
      </button>)}
    </section>
    {detail && <section className="card detail">
      <div className="card-heading"><h2>{detail.summary}</h2><span className="badge">Pattern confidence: {detail.confidence}</span></div>
      <p className="mono muted">{detail.incident_id}</p>
      {detail.detector && <div className="note"><Eye size={16}/><p><strong>{detail.detector.detector_id}</strong> v{detail.detector.detector_version}{detail.detector.threshold ? <> · observed {detail.detector.observed} against threshold {detail.detector.threshold} in {detail.detector.window_seconds}s</> : null} · record only, no automatic blocking.{detail.detector.assumption ? <><br/>{detail.detector.assumption}</> : null}</p></div>}
      <h3>What remains unknown</h3>{(detail.unknowns || []).map((x: string) => <p className="muted" key={x}>{x}</p>)}
      <h3>Retained evidence</h3>{(detail.evidence || []).map((e: any) => <div className="evidence" key={e.event_id}><span className="mono">{e.event_id}</span><span>{e.rule_ids?.length ? 'CRS ' + e.rule_ids.join(', ') : (e.method || '') + ' ' + (e.route_template || '') + ' · ' + (e.http_status ?? '')} · {e.decision}</span></div>)}
    </section>}
    {detail && <Assessment incident={detail.incident_id}/>}
    {detail && <Proposals incident={detail.incident_id} onChanged={() => setDetail(undefined)}/>}
  </>;
}

function Policies({site, action, busy, refresh}: {site: string; action: (w: () => Promise<any>, m?: string) => Promise<any>; busy: boolean; refresh: number}) {
  const [current, setCurrent] = useState<any>(), [history, setHistory] = useState<any[]>([]), [mode, setMode] = useState('protect'), [reason, setReason] = useState('Enable Protect after isolated fixture review'), [ack, setAck] = useState(false), [preview, setPreview] = useState<any>(), [error, setError] = useState('');
  useEffect(() => {
    api('/sites/' + site + '/policy').then(setCurrent).catch(e => setError(e.message));
    api('/sites/' + site + '/policies/history').then(v => setHistory(Array.isArray(v.items) ? v.items : [])).catch(e => setError(e.message));
  }, [site, refresh]);
  const target = site === 'site_demo' ? current?.policy : current?.policy.sites?.find((x: any) => x.site_id === site);
  const candidate = !current || !target ? null : site === 'site_demo'
    ? {...current.policy, parent_revision: current.digest, requested_mode: mode, metadata: {rationale: reason, requested_by: 'local-owner'}}
    : {...current.policy, parent_revision: current.digest, sites: current.policy.sites.map((x: any) => x.site_id === site ? {...x, requested_mode: mode} : x), metadata: {rationale: reason, requested_by: 'local-owner'}};
  return <>
    {error && <div className="alert error">{error}</div>}
    <section className="card">
      <div className="card-heading"><h2>Review a policy change</h2><span className="badge">{site} · current: {target?.requested_mode || 'Loading'}</span></div>
      <p className="mono muted">Active revision: {current?.digest || 'Unavailable'}</p>
      <div className="form-grid">
        <label>Candidate mode<select value={mode} onChange={e => { setMode(e.target.value); setPreview(undefined); setAck(false); }}><option value="protect">Protect · CRS may block matching requests</option><option value="observe">Observe · record matches without WAF blocking</option></select></label>
        <label>Reason<input value={reason} minLength={5} maxLength={512} onChange={e => { setReason(e.target.value); setPreview(undefined); }}/></label>
      </div>
      <div className="note"><Shield size={16}/><p>CRS PL1 · anomaly threshold 5. Validation uses the pinned gateway. The shadow test runs only in the bundled isolated fixture.</p></div>
      <button disabled={busy || !candidate || reason.length < 5} className="button primary" onClick={() => action(async () => { const p = await api('/sites/' + site + '/policies/validate', candidate); setPreview({...p, policy: candidate}); return p; })}>{busy ? 'Validating & testing…' : 'Validate and preview'}<ArrowRight size={15}/></button>
    </section>
    {preview && <section className="card">
      <div className="card-heading"><h2>Candidate preview</h2><span className={'badge ' + (preview.fixture_result === 'PASS' ? 'allowed' : 'blocked')}>{preview.fixture_result}</span></div>
      <div className="system-row"><span>Candidate digest</span><span className="mono">{short(preview.candidate_digest)}</span></div>
      <div className="system-row"><span>Mode transition</span><strong>{target?.requested_mode} → {mode}</strong></div>
      <Report report={preview.report}/>
      <label className="checkbox"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I understand that legitimate traffic may be interrupted.</label>
      <button disabled={busy || !ack || preview.fixture_result !== 'PASS'} className="button primary" onClick={() => action(async () => {
        await api('/sites/' + site + '/policies', preview.policy);
        await api('/sites/' + site + '/policies/' + encodeURIComponent(preview.candidate_digest) + '/activate', {reason, acknowledge_disruption_risk: true}, {'If-Match': '"' + current.digest + '"', 'Idempotency-Key': key()});
        setPreview(undefined); setAck(false);
      }, 'Gateway activation confirmed.')}>Approve and activate<ShieldCheck size={16}/></button>
    </section>}
    <section className="card">
      <div className="card-heading"><h2>Revision history</h2><RotateCcw size={18}/></div>
      <ol className="timeline">{history.map(p => <li className={'history-row ' + p.state.toLowerCase()} key={p.digest}>
        <div><strong>{p.policy.requested_mode} <span className={'badge ' + (p.state === 'ACTIVE' ? 'allowed' : '')}>{p.state}</span></strong><p className="mono muted">{short(p.digest)} · {new Date(p.created_at).toLocaleString()}</p></div>
        {p.state === 'SUPERSEDED' && <button disabled={busy} className="button light" onClick={() => {
          if (window.confirm('Restore this prior policy? Traffic behavior may change. An isolated test will run first.')) action(() => api('/sites/' + site + '/policies/' + encodeURIComponent(p.digest) + '/rollback', {reason: 'Owner-approved rollback to prior policy', acknowledge_disruption_risk: true}, {'If-Match': '"' + current.digest + '"', 'Idempotency-Key': key()}), 'Rollback confirmed.');
        }}>Rollback<RotateCcw size={14}/></button>}
      </li>)}</ol>
    </section>
  </>;
}

function SettingsPage({refresh, theme, setTheme}: {refresh: number; theme: Theme; setTheme: (t: Theme) => void}) {
  return <>
    <section className="card">
      <div className="card-heading"><h2>Appearance</h2></div>
      <div className="segmented" role="radiogroup" aria-label="Theme">
        {(['dark', 'light'] as const).map(t => <button key={t} role="radio" aria-checked={theme === t} className={theme === t ? 'active' : ''} onClick={() => setTheme(t)}>{t === 'dark' ? <Moon size={15}/> : <Sun size={15}/>}{t === 'dark' ? 'Dark' : 'Light'}</button>)}
      </div>
    </section>
    <Collection path="/audit" title="Audit chain" refresh={refresh} columns={['seq', 'hash', 'previous_hash']} footnote="The local audit chain detects individual record changes under stated trust assumptions. It cannot prevent a host administrator replacing the entire chain."/>
    <section className="card">
      <h2>Default privacy</h2>
      <div className="system-row"><span>Raw bodies / secret headers</span><span>Never stored by default</span></div>
      <div className="system-row"><span>Query values</span><span>Omitted</span></div>
      <div className="system-row"><span>Detailed events</span><span>7 days / 50,000 record cap</span></div>
      <div className="system-row"><span>Background model calls / updates / telemetry</span><span>Disabled</span></div>
      <div className="note"><Clock3 size={16}/><p>Backups contain sensitive owner and session state. Follow the local backup and recovery guide before upgrades.</p></div>
    </section>
  </>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
