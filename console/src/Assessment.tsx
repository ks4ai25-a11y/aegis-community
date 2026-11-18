// SPDX-License-Identifier: BUSL-1.1
import {useCallback, useEffect, useState} from 'react';
import {Bot, Cpu, ShieldAlert} from 'lucide-react';
import {api, short, human} from './client';
import {activateCandidate} from './Sites';
import {Report} from './Report';
import {DesktopPairing} from './DesktopPairing';

export function useAIStatus() {
  const [status, setStatus] = useState<any>();
  useEffect(() => { api('/ai/status').then(setStatus).catch(() => setStatus({provider: 'none'})); }, []);
  return status;
}

function assessmentResponse(value: any, incident: string) {
  return value?.incident_id === incident && value.advisory_only === true &&
    typeof value?.provenance?.assessor === 'string' &&
    ['observed_facts', 'hypotheses', 'recommendations', 'recommended_tests', 'uncertainties']
      .every(key => Array.isArray(value[key]));
}

// Advisory only: an assessment never changes policy. The model, when configured,
// receives only the incident dossier built from sanitized evidence.
export function Assessment({incident}: {incident: string}) {
  const ai = useAIStatus();
  const [result, setResult] = useState<any>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let current = true;
    setResult(undefined);
    setError('');
    api('/incidents/' + encodeURIComponent(incident) + '/assessment').then(value => {
      if (current && assessmentResponse(value, incident)) setResult(value);
    }).catch(() => {});
    return () => { current = false; };
  }, [incident]);
  async function run(useModel: boolean) {
    setBusy(true); setError('');
    try {
      const value = await api('/incidents/' + encodeURIComponent(incident) + '/assessment', {use_model: useModel});
      if (!assessmentResponse(value, incident)) throw new Error('Assessment response unavailable');
      setResult(value);
    }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  return <section className="card">
    <div className="card-heading"><h2>Assessment</h2><span className="badge">Advisory only</span></div>
    <p className="muted">Summarises the retained evidence and proposes next steps. Nothing here changes your gateway.</p>
    <div className="actions-row">
      <button disabled={busy} className="button light" onClick={() => run(false)}><ShieldAlert size={15}/>Deterministic assessment</button>
      {ai?.provider && ai.provider !== 'none' && <button disabled={busy} className="button primary" onClick={() => run(true)}><Bot size={15}/>{busy ? 'Assessing…' : 'Assess with ' + ai.model}</button>}
    </div>
    {error && <div role="alert" className="alert error">{error}</div>}
    {result && <>
      <div className="system-row"><span>Assessor</span><span className="mono">{result.provenance.assessor}{result.provenance.model ? ' · ' + result.provenance.model : ''}</span></div>
      {result.provenance.fallback_reason && <div className="note"><Cpu size={16}/><p>Used the deterministic assessor: {result.provenance.fallback_reason}</p></div>}
      <h3>Observed facts</h3>{result.observed_facts.map((f: string, i: number) => <p key={i}>{f}</p>)}
      <h3>Hypotheses</h3>{result.hypotheses.map((h: any, i: number) => <p key={i}><span className="badge">{h.confidence}</span> {h.statement} <span className="mono muted">{h.evidence_refs.length} evidence refs</span></p>)}
      <h3>Proposed next steps</h3>{result.recommendations.map((r: any, i: number) => <p key={i}><span className="badge">{r.kind}</span> {r.action} <span className="muted">· risk {r.risk_of_action}</span></p>)}
      {result.recommended_tests.length > 0 && <><h3>Suggested tests</h3>{result.recommended_tests.map((t: string, i: number) => <p key={i} className="muted">{t}</p>)}</>}
      <h3>Uncertainties</h3>{result.uncertainties.map((u: string, i: number) => <p key={i} className="muted">{u}</p>)}
      <p className="mono muted small">Dossier {result.provenance.dossier_digest}</p>
    </>}
  </section>;
}

// Proposals are complete candidate revisions. They go through the same pinned
// validation, isolated fixture preview and explicit approval as any policy change.
export function Proposals({incident, onChanged}: {incident: string; onChanged: () => void}) {
  const [data, setData] = useState<any>();
  const [preview, setPreview] = useState<any>();
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [done, setDone] = useState('');
  useEffect(() => {
    let current = true;
    setPreview(undefined);
    setData(undefined);
    setDone('');
    setError('');
    api('/incidents/' + encodeURIComponent(incident) + '/proposals').then(value => {
      if (!current) return;
      if (Array.isArray(value?.proposals) && Array.isArray(value?.not_proposed)) setData(value);
      else setError('Mitigation proposals are unavailable.');
    }).catch(e => { if (current) setError(e.message); });
    return () => { current = false; };
  }, [incident]);
  async function work(f: () => Promise<any>) { setBusy(true); setError(''); try { await f(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); } }
  if (!data) return error ? <section className="card">
    <h2>Mitigation proposals</h2>
    <p role="status" className="muted">{error}</p>
  </section> : null;
  return <section className="card">
    <div className="card-heading"><h2>Mitigation proposals</h2><span className="badge">{data.proposals.length} proposed</span></div>
    {error && <div role="alert" className="alert error">{error}</div>}
    {done && <div role="status" className="alert success">{done}</div>}
    {data.proposals.map((p: any) => <div className="history-row" key={p.proposal_id}>
      <div><strong>{p.title} <span className="badge">{p.kind}</span> <span className="badge">{p.priority}</span></strong>
        <p className="muted">{p.rationale}</p>
        {p.side_effects.map((x: string) => <p className="small muted" key={x}>· {x}</p>)}</div>
      <button disabled={busy} className="button light" onClick={() => work(async () => { setAck(false); const r = await api('/sites/' + p.site_id + '/policies/validate', p.candidate_policy); setPreview({...r, policy: p.candidate_policy, proposal: p}); })}>Validate and preview</button>
    </div>)}
    {data.not_proposed.map((x: string) => <p className="small muted" key={x}>Not proposed: {x}</p>)}
    {preview && <div className="detail">
      <div className="card-heading"><h3>Preview: {preview.proposal.title}</h3><span className="badge">{preview.fixture_result}</span></div>
      <div className="system-row"><span>Candidate digest</span><span className="mono">{short(preview.candidate_digest)}</span></div>
      <Report report={preview.report}/>
      <label className="checkbox"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)}/>I reviewed the side effects and understand legitimate traffic may be affected.</label>
      <button disabled={busy || !ack || preview.fixture_result !== 'PASS'} className="button primary" onClick={() => work(async () => { await activateCandidate(preview.proposal.site_id, preview, preview.policy.parent_revision, preview.proposal.title); setPreview(undefined); setDone('Gateway activation confirmed. The incident stays open for your review.'); })}>Approve and activate</button>
    </div>}
  </section>;
}

type AssistantConnection = {
  connector_id: string;
  name: string;
  scope: string;
  state: string;
  expires_unix: number;
  last_used_unix: number;
};

function Connectors() {
  const [items, setItems] = useState<AssistantConnection[]>();
  const [name, setName] = useState('Claude Desktop');
  const [hours, setHours] = useState(168);
  const [issued, setIssued] = useState<{connector: AssistantConnection; token: string}>();
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [working, setWorking] = useState(false);
  const [renewal, setRenewal] = useState<{id: string; name: string; until: number}>();
  const load = useCallback(() => api<{items: AssistantConnection[]}>('/connectors').then(v => setItems(v.items)).catch(e => setError(e.message)), []);
  useEffect(() => { load(); }, []);
  const config = issued ? JSON.stringify({mcpServers: {aegis: {command: '/path/to/aegis-mcp', env: {AEGIS_URL: location.origin, AEGIS_CONNECTOR_TOKEN_FILE: '/path/to/aegis-connector-token'}}}}, null, 2) : '';
  async function createConnection() {
    setWorking(true);
    setError('');
    setNotice('');
    try {
      const response = await api<{connector: AssistantConnection; token: string}>('/connectors', {name, lifetime_hours: hours});
      setIssued(response);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Connection creation failed.');
    } finally {
      setWorking(false);
    }
  }

  async function changeConnection(connection: AssistantConnection, action: 'renew' | 'revoke') {
    const id = connection.connector_id;
    setWorking(true);
    setError('');
    setNotice('');
    if (action === 'renew') setRenewal(undefined);
    try {
      const response = await api('/connectors/' + encodeURIComponent(id) + '/' + action, {});
      if (action === 'renew') {
        if (response.connector_id !== id || !Number.isSafeInteger(response.approval_expires_unix)) {
          throw new Error('Renewal approval could not be confirmed.');
        }
        setRenewal({id, name: connection.name, until: response.approval_expires_unix});
      } else {
        if (response.state !== 'revoked') throw new Error('Revocation could not be confirmed.');
        setIssued(current => current?.connector.connector_id === id ? undefined : current);
        setRenewal(current => current?.id === id ? undefined : current);
        setItems(current => current?.map(item => item.connector_id === id ? {...item, state: 'revoked'} : item));
        setNotice(connection.name + ' was revoked.');
        await load();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Connection update failed.');
    } finally {
      setWorking(false);
    }
  }
  return <><DesktopPairing onPaired={load}/><section className="card">
    <div className="card-heading"><h2>Assistant connections</h2></div>
    {error && <div role="alert" className="alert error">{error}</div>}
    {notice && <p role="status" className="muted">{notice}</p>}
    {renewal && <div role="status" className="note"><div>
      <strong>Renewal approved for {renewal.name}</strong>
      <p>Before {new Date(renewal.until * 1000).toLocaleTimeString()}, run <code>aegis-mcp renew</code> for a private file or <code>aegis-mcp-keychain renew</code> for macOS Keychain. Use the device’s existing Aegis URL and credential setting, then restart its desktop session.</p>
    </div></div>}
    <details><summary>Advanced manual connector</summary><p className="muted">Let a desktop AI app (Claude, Codex, Kimi or any MCP client) read sites, incidents, assessments and proposals through the local <span className="mono">aegis-mcp</span> bridge. A connection can never change policy, start jobs or read scanner channels. The app uses its own subscription; Aegis never receives its credentials.</p>
    <div className="form-grid">
      <label>Name<input value={name} maxLength={64} onChange={e => setName(e.target.value)}/></label>
      <label>Lifetime (hours)<input type="number" min={1} max={720} value={hours} onChange={e => setHours(Number(e.target.value))}/></label>
    </div>
    <button className="button primary" disabled={!name.trim() || working} onClick={createConnection}>Create connection</button>
    {issued && <div className="note"><div>
      <p><strong>Copy this token now; it is shown once.</strong> Save it to a file readable only by you (<span className="mono">chmod 600</span>).</p>
      <pre className="mono">{issued.token}</pre>
      <p>Then add the bridge to your app's MCP configuration:</p>
      <pre className="mono">{config}</pre>
    </div></div>}
    </details>
    {items?.length === 0 && <p className="muted">No assistant connections yet.</p>}
    {!!items?.length && <div className="table-wrap"><table className="assistant-connections">
      <thead><tr><th scope="col">Name</th><th scope="col">Access</th><th scope="col">State</th>
        <th scope="col">Expires</th><th scope="col">Last used</th><th scope="col">Actions</th></tr></thead>
      <tbody>{items.map(connection => {
        const paired = connection.scope === 'desktop_handoff_v1';
        const active = connection.state === 'active';
        return <tr key={connection.connector_id}>
          <th scope="row">{connection.name}</th>
          <td>{paired ? 'Approved handoffs' : 'Manual connector'}</td>
          <td><span className={'badge' + (active ? ' allowed' : '')}>{human(connection.state)}</span></td>
          <td>{new Date(connection.expires_unix * 1000).toLocaleString()}</td>
          <td>{connection.last_used_unix ? new Date(connection.last_used_unix * 1000).toLocaleString() : 'Never'}</td>
          <td>{active && <div className="connection-actions">
            {paired && <button className="button light" disabled={working} onClick={() => changeConnection(connection, 'renew')}>Approve 60-minute renewal</button>}
            <button className="button light" disabled={working} onClick={() => changeConnection(connection, 'revoke')}>Revoke</button>
          </div>}</td>
        </tr>;
      })}</tbody>
    </table></div>}
  </section></>;
}

export function AIPage() {
  const ai = useAIStatus();
  return <>
    <section className="card">
      <div className="card-heading"><h2>Incident assessment</h2><span className="badge">{ai?.provider === 'none' || !ai ? 'Deterministic only' : 'Local model: ' + ai.model}</span></div>
      <p className="muted">Every incident can be assessed deterministically with no model, account or network access. Optionally, point Aegis at a model server you run yourself, such as Ollama or llama.cpp. Aegis never calls a model in the background and never lets one change policy.</p>
      <div className="system-row"><span>Provider</span><span>{ai ? (ai.provider === 'none' ? 'Not configured' : human(ai.provider)) : '…'}</span></div>
      {ai?.endpoint_host && <div className="system-row"><span>Endpoint</span><span className="mono">{ai.endpoint_host}</span></div>}
      <div className="system-row"><span>Background model calls</span><span>Never</span></div>
      <div className="system-row"><span>What the model sees</span><span>One sanitized incident dossier</span></div>
    </section>
    <section className="card">
      <h2>Enable a free local model</h2>
      <p className="muted">From the Aegis folder, run the quickstart with the local model overlay. It downloads the assessment and code models once (about 4 GB) in a separate job; the model server itself has no internet access.</p>
      <pre className="mono">scripts/quickstart.sh --ai</pre>
      <p className="muted">Or the two steps by hand:</p>
      <pre className="mono">docker compose -f deploy/compose.demo.yaml -f deploy/compose.ai-local.yaml --profile ai-pull run --rm ollama-pull{'\n'}docker compose -f deploy/compose.demo.yaml -f deploy/compose.ai-local.yaml up -d</pre>
      <p className="muted">See docs/operators/ai-assessment.md for llama.cpp and other OpenAI-compatible servers.</p>
    </section>
    <Connectors/>
  </>;
}
