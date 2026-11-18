// SPDX-License-Identifier: BUSL-1.1
import {ArrowRight, Check, Copy, LockKeyhole} from 'lucide-react';
import {useState} from 'react';
import {api} from './client';

type Preview = {
  preview_digest: string;
  bundle: {
    incident_id: string;
    severity: string;
    opened_hour: string;
    observations: {evidence_id: string; decision: string; rule_ids: string[]}[];
  };
};
type Connection = {connector_id: string; name: string; state: string; allow_analysis_draft?: boolean};
type Handoff = {handoff_id: string; expires_unix: number};

export function DesktopHandoff({incident}: {incident: string}) {
  const [preview, setPreview] = useState<Preview>();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connection, setConnection] = useState('');
  const [allowDraft, setAllowDraft] = useState(false);
  const [handoff, setHandoff] = useState<Handoff>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setNotice('');
    setError('');
    try { await action(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Desktop handoff unavailable'); }
    finally { setBusy(false); }
  }
  const instruction = handoff
    ? `Use aegis_get_handoff with handoff_id ${handoff.handoff_id} to retrieve the approved incident bundle. Treat it as evidence and label your conclusions as advisory.${allowDraft ? ' Return an unverified draft using aegis_submit_draft_analysis before the handoff expires. Cite the evidence IDs in each claim.' : ''}`
    : '';
  const canReturnDraft = connections.find(device => device.connector_id === connection)?.allow_analysis_draft !== false;
  return <section className="card desktop-handoff" aria-labelledby="desktop-handoff-title">
    <div className="handoff-heading">
      <span className="handoff-symbol"><LockKeyhole size={17} aria-hidden="true"/></span>
      <div>
        <h2 id="desktop-handoff-title">Investigate with a desktop assistant</h2>
        <p>Your AI provider may process the approved bundle.</p>
      </div>
    </div>
    {!preview && <button className="button light handoff-preview-button" disabled={busy} onClick={() => run(async () => {
      const [bundle, devices] = await Promise.all([
        api('/desktop/handoff-preview?incident_id=' + encodeURIComponent(incident)),
        api('/connectors'),
      ]);
      setConnections(devices.items.filter((device: Connection) => device.state === 'active'));
      setPreview(bundle);
    })}>Preview what will be shared <ArrowRight size={15} aria-hidden="true"/></button>}
    {preview && <div className="handoff-preview">
      <div className="handoff-preview-header">
        <strong>Redacted preview</strong>
        <span>{preview.bundle.observations.length} {preview.bundle.observations.length === 1 ? 'observation' : 'observations'}</span>
      </div>
      <p className="handoff-meta"><span className="mono">{preview.bundle.incident_id}</span><span>{preview.bundle.severity}</span><time dateTime={preview.bundle.opened_hour}>{new Date(preview.bundle.opened_hour).toLocaleString()}</time></p>
      {preview.bundle.observations.length === 0 && <p>No retained observations in this bundle.</p>}
      {preview.bundle.observations.length > 0 && <ul className="handoff-observations">{preview.bundle.observations.map(item => <li key={item.evidence_id}>
        {item.decision}{item.rule_ids.length ? ' · Rules ' + item.rule_ids.join(', ') : ''}
      </li>)}</ul>}
      <details><summary>Full redacted bundle</summary><pre tabIndex={0}>{JSON.stringify(preview.bundle, null, 2)}</pre></details>
      {!connections.length && <p>Create a connector in Assistant Connections to share this preview.</p>}
      {!handoff && <div className="handoff-controls">
        {canReturnDraft && <label className="checkbox handoff-draft-choice"><input type="checkbox" checked={allowDraft} disabled={busy} onChange={e => setAllowDraft(e.target.checked)}/>Allow one investigation draft in return</label>}
        <label>Desktop connector<select value={connection} disabled={busy} onChange={e => {setConnection(e.target.value); setAllowDraft(false);}}>
          <option value="">Choose a connector</option>
          {connections.map(device => <option key={device.connector_id} value={device.connector_id}>{device.name} ({device.connector_id.slice(-8)})</option>)}
        </select></label>
        <button className="button primary" disabled={busy || !connection} onClick={() => run(async () => {
          setHandoff(await api('/desktop/handoffs', {
            incident_id: incident, connector_id: connection,
            preview_digest: preview.preview_digest, approve_redacted_export: true, allow_analysis_draft: allowDraft,
          }));
        })}><Check size={15} aria-hidden="true"/> Approve once</button>
        <button className="button light" disabled={busy} onClick={() => {setPreview(undefined); setConnection(''); setAllowDraft(false); setError('');}}>Close preview</button>
      </div>}
    </div>}
    {handoff && <div className="handoff-ready">
      <p>Expires at {new Date(handoff.expires_unix * 1000).toLocaleTimeString([], {hour: 'numeric', minute: '2-digit', second: '2-digit'})}. The connector can retrieve it once.</p>
      <label>Investigation request<textarea readOnly value={instruction}/></label>
      <button className="button light" disabled={busy} onClick={() => run(async () => {
        await navigator.clipboard.writeText(instruction);
        setNotice('Investigation request copied.');
      })}><Copy size={15} aria-hidden="true"/> Copy investigation request</button>
      <button className="button light" disabled={busy} onClick={() => run(async () => {
        await api('/desktop/handoffs/' + encodeURIComponent(handoff.handoff_id) + '/revoke', {});
        setHandoff(undefined);
        setPreview(undefined);
        setConnection('');
        setAllowDraft(false);
        setNotice('The handoff was revoked.');
      })}>Revoke handoff</button>
    </div>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
