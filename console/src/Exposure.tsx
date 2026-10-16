import {useEffect, useState} from 'react';
import {GitCompareArrows} from 'lucide-react';
import {api} from './client';

// Declared (repository) versus observed (gateway) routes for the selected site.
export function Exposure({site}: {site: string}) {
  const [repos, setRepos] = useState<any[]>([]);
  const [repo, setRepo] = useState('');
  const [data, setData] = useState<any>();
  const [error, setError] = useState('');
  useEffect(() => { api('/repositories').then(v => { const items = Array.isArray(v.items) ? v.items : []; setRepos(items); if (items[0]) setRepo(items[0].repository_id); }).catch(() => setRepos([])); }, []);
  useEffect(() => { setData(undefined); setError(''); if (repo) api('/sites/' + site + '/exposure?repository_id=' + encodeURIComponent(repo)).then(setData).catch(e => setError(e.message)); }, [site, repo]);
  if (!repos.length) return null;
  return <section className="card">
    <div className="card-heading"><h2>Declared versus observed routes</h2><GitCompareArrows size={18}/></div>
    <label className="filter">Repository<select value={repo} onChange={e => setRepo(e.target.value)}>{repos.map(r => <option key={r.repository_id} value={r.repository_id}>{r.asset_id || r.repository_id}</option>)}</select></label>
    {error && <div role="alert" className="alert error">{error}</div>}
    {data && <>
      <div className="system-row"><span>Seen but not declared</span><strong>{data.counts.observed_only}</strong></div>
      <div className="system-row"><span>Declared and seen</span><strong>{data.counts.both}</strong></div>
      <div className="system-row"><span>Declared, not seen</span><strong>{data.counts.declared_only}</strong></div>
      <div className="table-wrap"><table><thead><tr><th>Route</th><th>Category</th><th>Methods</th><th>Requests</th><th>Source</th></tr></thead><tbody>
        {data.entries.map((e: any) => <tr key={e.category + e.route}><td className="mono">{e.route}</td><td><span className={'badge ' + (e.category === 'observed_only' ? 'blocked' : '')}>{e.category.replace('_', ' ')}</span></td><td>{e.observed_methods.join(', ') || '—'}</td><td>{e.requests_retained || '—'}</td><td className="mono muted">{e.source_path || e.note || ''}</td></tr>)}
      </tbody></table></div>
      {data.limitations.map((l: string) => <p key={l} className="small muted">{l}</p>)}
    </>}
  </section>;
}
