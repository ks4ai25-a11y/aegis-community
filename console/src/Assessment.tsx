import {useEffect, useState} from 'react';
import {Bot, Cpu, ShieldAlert} from 'lucide-react';
import {api, short} from './client';
import {activateCandidate} from './Sites';
import {Report} from './Report';

export function useAIStatus() {
  const [status, setStatus] = useState<any>();
  useEffect(() => { api('/ai/status').then(setStatus).catch(() => setStatus({provider: 'none'})); }, []);
  return status;
}

// Advisory only: an assessment never changes policy. The model, when configured,
// receives only the incident dossier built from sanitized evidence.
export function Assessment({incident}: {incident: string}) {
  const ai = useAIStatus();
  const [result, setResult] = useState<any>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { setResult(undefined); setError(''); api('/incidents/' + encodeURIComponent(incident) + '/assessment').then(setResult).catch(() => {}); }, [incident]);
  async function run(useModel: boolean) {
    setBusy(true); setError('');
    try { setResult(await api('/incidents/' + encodeURIComponent(incident) + '/assessment', {use_model: useModel})); }
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
  const [error, setError] = useState('');
  useEffect(() => { setPreview(undefined); api('/incidents/' + encodeURIComponent(incident) + '/proposals').then(setData).catch(e => setError(e.message)); }, [incident]);
  async function work(f: () => Promise<any>) { setBusy(true); setError(''); try { await f(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); } }
  if (!data) return null;
  return <section className="card">
    <div className="card-heading"><h2>Mitigation proposals</h2><span className="badge">{data.proposals.length} proposed</span></div>
    {error && <div role="alert" className="alert error">{error}</div>}
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
      <button disabled={busy || !ack || preview.fixture_result !== 'PASS'} className="button primary" onClick={() => work(async () => { await activateCandidate(preview.proposal.site_id, preview, preview.policy.parent_revision, preview.proposal.title); setPreview(undefined); onChanged(); })}>Approve and activate</button>
    </div>}
  </section>;
}

export function AIPage() {
  const ai = useAIStatus();
  return <>
    <section className="card">
      <div className="card-heading"><h2>Incident assessment</h2><span className="badge">{ai?.provider === 'none' || !ai ? 'Deterministic only' : 'Local model: ' + ai.model}</span></div>
      <p className="muted">Every incident can be assessed deterministically with no model, account or network access. Optionally, point Aegis at a model server you run yourself, such as Ollama or llama.cpp. Aegis never calls a model in the background and never lets one change policy.</p>
      <div className="system-row"><span>Provider</span><span className="mono">{ai?.provider || '…'}</span></div>
      {ai?.endpoint_host && <div className="system-row"><span>Endpoint</span><span className="mono">{ai.endpoint_host}</span></div>}
      <div className="system-row"><span>Background model calls</span><span>Never</span></div>
      <div className="system-row"><span>What the model sees</span><span>One sanitized incident dossier</span></div>
    </section>
    <section className="card">
      <h2>Enable a free local model</h2>
      <p className="muted">Start the bundled Ollama overlay and pull a small model once:</p>
      <pre className="mono">docker compose -f deploy/compose.demo.yaml -f deploy/compose.ai-local.yaml up -d{'\n'}docker compose -f deploy/compose.demo.yaml -f deploy/compose.ai-local.yaml exec ollama ollama pull llama3.2:3b</pre>
      <p className="muted">See docs/operators/ai-assessment.md for llama.cpp and other OpenAI-compatible servers.</p>
    </section>
  </>;
}
