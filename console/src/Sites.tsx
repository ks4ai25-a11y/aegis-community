import {useEffect, useState} from 'react';
import {ArrowRight, Globe, Plus, ShieldCheck, Trash2} from 'lucide-react';
import {api, key, short} from './client';
import {Report} from './Report';

export type Site = {site_id: string; display_name: string; hostnames: string[]; origin_url: string; mode: string; synthetic: boolean};

const defaultCRS = {blocking_paranoia: 1, executing_paranoia: 1, inbound_anomaly_threshold: 5};

// Every site change is one new gateway revision: preview in the isolated fixture,
// save the exact candidate, then activate it against the current revision.
async function previewCandidate(site: string, candidate: any) {
  const p = await api('/sites/' + site + '/policies/validate', candidate);
  return {...p, policy: candidate};
}
export async function activateCandidate(site: string, preview: any, parent: string, reason: string) {
  await api('/sites/' + site + '/policies', preview.policy);
  await api('/sites/' + site + '/policies/' + encodeURIComponent(preview.candidate_digest) + '/activate', {reason, acknowledge_disruption_risk: true}, {'If-Match': '"' + parent + '"', 'Idempotency-Key': key()});
}

export function withSites(policy: any, sites: any[], parent: string, reason: string) {
  return {...policy, schema_version: sites.length || policy.schema_version === '1.1' ? '1.1' : '1.0', sites: sites.length ? sites : undefined, parent_revision: parent, metadata: {rationale: reason, requested_by: 'local-owner'}};
}

export function Sites({action, busy, refresh, onSelect}: {action: (w: () => Promise<any>, m?: string) => Promise<any>; busy: boolean; refresh: number; onSelect: (id: string) => void}) {
  const [sites, setSites] = useState<Site[]>([]);
  const [current, setCurrent] = useState<any>();
  const [error, setError] = useState('');
  const [form, setForm] = useState({id: '', name: '', hosts: '', origin: ''});
  const [preview, setPreview] = useState<any>();
  const [ack, setAck] = useState(false);
  const [reason, setReason] = useState('');

  useEffect(() => {
    api('/sites').then(v => setSites(v.items)).catch(e => setError(e.message));
    api('/sites/site_demo/policy').then(setCurrent).catch(e => setError(e.message));
  }, [refresh]);

  const registered: any[] = current?.policy.sites || [];
  const siteID = 'site_' + form.id.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const hostnames = form.hosts.split(/[\s,]+/).map(h => h.trim().toLowerCase()).filter(Boolean);
  const ready = form.id && form.name && hostnames.length && form.origin;

  function stage(sites: any[], why: string) {
    if (!current) return;
    const candidate = withSites(current.policy, sites, current.digest, why);
    setReason(why);
    setAck(false);
    return action(async () => setPreview(await previewCandidate('site_demo', candidate)));
  }

  return <>
    {error && <div role="alert" className="alert error">{error}</div>}
    <section className="card">
      <div className="card-heading"><h2>Protected applications</h2><span className="badge">{sites.length} site{sites.length === 1 ? '' : 's'}</span></div>
      <p className="muted">Every site shares one gateway revision. A new site always starts in Observe; Protect can be enabled only after Aegis has observed its traffic.</p>
      <div className="table-wrap"><table><thead><tr><th>Site</th><th>Host names</th><th>Origin</th><th>Mode</th><th></th></tr></thead><tbody>
        {sites.map(s => <tr key={s.site_id}>
          <td><strong>{s.display_name}</strong><div className="mono muted">{s.site_id}</div></td>
          <td className="mono">{s.hostnames.join(', ')}</td>
          <td className="mono">{s.origin_url}</td>
          <td><span className={'badge ' + (s.mode === 'protect' ? 'blocked' : '')}>{s.mode}</span>{s.synthetic && <span className="badge">synthetic</span>}</td>
          <td className="actions">
            <button className="button light" onClick={() => onSelect(s.site_id)}>View activity<ArrowRight size={14}/></button>
            {!s.synthetic && <button disabled={busy} className="button light" aria-label={'Remove ' + s.display_name} onClick={() => {
              if (window.confirm('Remove ' + s.display_name + ' from the gateway? Requests to its host names will receive 421 after activation.'))
                stage(registered.filter(r => r.site_id !== s.site_id), 'Remove ' + s.site_id + ' from the gateway');
            }}><Trash2 size={14}/></button>}
          </td>
        </tr>)}
      </tbody></table></div>
    </section>

    <section className="card">
      <div className="card-heading"><h2>Register an application</h2><Globe size={18}/></div>
      <div className="form-grid">
        <label>Site ID<input value={form.id} maxLength={32} placeholder="shop" onChange={e => setForm({...form, id: e.target.value})}/><small className="muted mono">{form.id ? siteID : 'site_…'}</small></label>
        <label>Display name<input value={form.name} maxLength={64} placeholder="Shop" onChange={e => setForm({...form, name: e.target.value})}/></label>
        <label>Host names<input value={form.hosts} placeholder="shop.example.com www.shop.example.com" onChange={e => setForm({...form, hosts: e.target.value})}/><small className="muted">The DNS names clients use. Up to eight.</small></label>
        <label>Private origin<input value={form.origin} placeholder="shop-app:3000" onChange={e => setForm({...form, origin: e.target.value})}/><small className="muted">host:port reachable from the gateway network. Loopback and metadata addresses are refused.</small></label>
      </div>
      <button disabled={busy || !ready || !current} className="button primary" onClick={() => stage([...registered, {site_id: siteID, display_name: form.name.trim(), hostnames, origin: form.origin.trim(), requested_mode: 'observe', crs: defaultCRS, exclusions: []}], 'Register ' + siteID + ' in Observe mode')}>
        <Plus size={15}/>{busy ? 'Validating & testing…' : 'Validate and preview'}
      </button>
    </section>

    {preview && <section className="card">
      <div className="card-heading"><h2>Candidate preview</h2><span className="badge">{preview.fixture_result}</span></div>
      <div className="system-row"><span>Change</span><strong>{reason}</strong></div>
      <div className="system-row"><span>Candidate digest</span><span className="mono">{short(preview.candidate_digest)}</span></div>
      <div className="note"><ShieldCheck size={18}/><p>The isolated fixture verifies the bundled demo controls with this exact revision. It does not test your application; start in Observe and review its traffic first.</p></div>
      <Report report={preview.report}/>
      <label className="checkbox"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I understand that gateway routing for these host names changes on activation.</label>
      <button disabled={busy || !ack || preview.fixture_result !== 'PASS'} className="button primary" onClick={() => action(async () => {
        await activateCandidate('site_demo', preview, current.digest, reason);
        setPreview(undefined);
        setForm({id: '', name: '', hosts: '', origin: ''});
      }, 'Gateway activation confirmed.')}>Approve and activate<ShieldCheck size={16}/></button>
    </section>}
  </>;
}
