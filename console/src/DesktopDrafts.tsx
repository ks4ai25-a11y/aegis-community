// SPDX-License-Identifier: BUSL-1.1
import {FileText, RefreshCw} from 'lucide-react';
import {useState} from 'react';
import {api} from './client';

type Draft = {
  draft_id: string;
  state: 'unverified' | 'dismissed';
  created_unix: number;
  connector_id: string;
  approved_bundle_digest: string;
  document: {
    client_label: string;
    claims: {claim: string; kind: 'observation' | 'hypothesis'; source_ids: string[]}[];
    limitations: string[];
    proposed_steps: {kind: string; text: string; requires_owner_approval: boolean}[];
  };
};

function isDraft(value: any): value is Draft {
  const d = value?.document;
  return typeof value?.draft_id === 'string' && ['unverified', 'dismissed'].includes(value.state) &&
    Number.isFinite(value.created_unix) && value.created_unix > 0 && value.created_unix < 10_000_000_000 &&
    typeof value.connector_id === 'string' && typeof value.approved_bundle_digest === 'string' &&
    typeof d?.client_label === 'string' && Array.isArray(d.claims) &&
    d.claims.every((claim: any) => typeof claim?.claim === 'string' && Array.isArray(claim.source_ids) &&
      claim.source_ids.every((source: unknown) => typeof source === 'string')) &&
    Array.isArray(d.limitations) && d.limitations.every((v: unknown) => typeof v === 'string') &&
    Array.isArray(d.proposed_steps) && d.proposed_steps.every((step: any) => typeof step?.text === 'string');
}

export function DesktopDrafts({incident}: {incident: string}) {
  const [drafts, setDrafts] = useState<Draft[]>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const load = () => api('/desktop/drafts?incident_id=' + encodeURIComponent(incident)).then(v => {
    if (!Array.isArray(v?.items) || v.items.length > 20 || !v.items.every(isDraft)) throw new Error('Investigation drafts are unavailable.');
    setDrafts(v.items);
  });
  async function run(work: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try { await work(); }
    catch (e) {setError(e instanceof Error ? e.message : 'Investigation drafts are unavailable.');}
    finally {setBusy(false);}
  }
  return <section className="card desktop-handoff" aria-labelledby="desktop-drafts-title">
    <div className="handoff-heading">
      <span className="handoff-symbol"><FileText size={17} aria-hidden="true"/></span>
      <div><h2 id="desktop-drafts-title">Investigation drafts</h2>
        <p>Assistant reports are unverified. Review their evidence before acting.</p></div>
    </div>
    <button className="button light handoff-preview-button" disabled={busy} onClick={() => run(load)}>
      <RefreshCw size={15} aria-hidden="true"/>{drafts ? 'Refresh drafts' : 'Check for drafts'}
    </button>
    {drafts?.length === 0 && <p className="muted">No desktop drafts for this incident.</p>}
    {drafts?.map(draft => <div className="handoff-preview desktop-draft" key={draft.draft_id}>
      <div className="handoff-preview-header">
        <strong>{draft.state === 'dismissed' ? 'Dismissed' : 'Unverified draft'}</strong>
        <time dateTime={new Date(draft.created_unix * 1000).toISOString()}>{new Date(draft.created_unix * 1000).toLocaleString()}</time>
      </div>
      <p className="handoff-meta">Client label: {draft.document.client_label} (self-reported) · Connector {draft.connector_id}</p>
      {draft.document.claims.map((claim, i) => <div className="draft-claim" key={i}>
        <strong>{claim.kind === 'observation' ? 'Reported observation' : 'Hypothesis'}</strong>
        <p>{claim.claim}</p>
        <details><summary>Evidence references ({claim.source_ids.length})</summary>
          <ul>{claim.source_ids.map(source => <li className="mono" key={source}>{source}</li>)}</ul>
        </details>
      </div>)}
      <h3>Limitations</h3><ul>{draft.document.limitations.map((limitation, i) => <li key={i}>{limitation}</li>)}</ul>
      {draft.document.proposed_steps.length > 0 && <>
        <h3>Suggested next steps</h3><ul>{draft.document.proposed_steps.map((step, i) => <li key={i}>
          {step.text}{step.requires_owner_approval && <span className="muted"> · Owner approval required</span>}
        </li>)}</ul>
      </>}
      <details><summary>Approved bundle digest</summary><p className="mono">{draft.approved_bundle_digest}</p></details>
      {draft.state === 'unverified' && <button className="button light" disabled={busy} onClick={() => run(async () => {
        await api('/desktop/drafts/' + encodeURIComponent(draft.draft_id) + '/dismiss', {});
        await load();
        setNotice('Draft dismissed.');
      })}>Dismiss draft</button>}
    </div>)}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
