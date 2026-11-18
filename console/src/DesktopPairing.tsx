// SPDX-License-Identifier: BUSL-1.1
import {KeyRound} from 'lucide-react';
import {useEffect, useState} from 'react';
import {api} from './client';

type Pairing = {pairing_id: string; state: string; lifetime_minutes: number; expires_unix: number};

export function DesktopPairing({onPaired}: {onPaired: () => void}) {
  const [name, setName] = useState('');
  const [minutes, setMinutes] = useState(30);
  const [draft, setDraft] = useState(false);
  const [invite, setInvite] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [pairing, setPairing] = useState<Pairing>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const id = pairing?.pairing_id;
  const state = pairing?.state;
  useEffect(() => {
    if (!id || !['new', 'claimed', 'approved'].includes(state ?? '')) return;
    let current = true;
    let timeout: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      try {
        const value = await api('/desktop/pairing/' + encodeURIComponent(id));
        if (!current) return;
        if (value.pairing_id !== id || !['new', 'claimed', 'approved', 'redeemed', 'expired', 'cancelled'].includes(value.state)) {
          throw new Error('Pairing status is unavailable.');
        }
        if (value.state !== 'new') setInvite('');
        setPairing(value);
        if (value.state !== state) return;
      } catch (e) {
        if (current) setError(e instanceof Error ? e.message : 'Pairing status is unavailable.');
      }
      if (current) timeout = setTimeout(refresh, 2500);
    };
    timeout = setTimeout(refresh, 1500);
    return () => { current = false; clearTimeout(timeout); };
  }, [id, state]);

  useEffect(() => {
    if (state === 'redeemed') onPaired();
  }, [state, onPaired]);

  async function perform(work: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await work(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Pairing unavailable.'); }
    finally { setBusy(false); }
  }
  const active = ['new', 'claimed', 'approved'].includes(state ?? '');
  const config = JSON.stringify({mcpServers: {aegis: {
    command: '/absolute/path/to/aegis-mcp',
    env: {AEGIS_URL: location.origin, AEGIS_CONNECTOR_TOKEN_FILE: '/absolute/private/path/to/device-token'},
  }}}, null, 2);

  return <section className="card desktop-handoff" aria-labelledby="desktop-pairing-title">
    <div className="handoff-heading">
      <span className="handoff-symbol"><KeyRound size={17} aria-hidden="true"/></span>
      <div><h2 id="desktop-pairing-title">Pair a desktop assistant</h2>
      <p>Grant time-limited access to incident bundles you approve.</p></div>
    </div>
    {!active && <div className="handoff-preview">
      <div className="form-grid">
        <label>Device name<input value={name} maxLength={64} onChange={e => setName(e.target.value)} placeholder="Example: Work Mac"/></label>
        <label>Access duration<select value={minutes} onChange={e => setMinutes(Number(e.target.value))}>
          <option value={15}>15 minutes</option><option value={30}>30 minutes</option><option value={60}>60 minutes</option>
        </select></label>
      </div>
      <label className="checkbox"><input type="checkbox" checked={draft} onChange={e => setDraft(e.target.checked)}/>Let this device return drafts when I approve a handoff</label>
      <button className="button primary" disabled={!name.trim() || busy} onClick={() => perform(async () => {
        const v = await api('/desktop/pairing', {name, lifetime_minutes: minutes, allow_analysis_draft: draft});
        setPairing(v.pairing); setInvite(v.pairing.pairing_id + ':' + v.invite_code); setFingerprint('');
      })}>Create pairing invitation</button>
    </div>}
    {state === 'new' && <div className="handoff-preview">
      <h3>Connect the local bridge</h3>
      <p>Give this one-use invitation to <code>aegis-mcp pair</code> on the device. It expires after five minutes.</p>
      <label>Pairing invitation<textarea readOnly value={invite}/></label>
      <button className="button light" disabled={busy} onClick={() => perform(async () => {
        await navigator.clipboard.writeText(invite); setNotice('Pairing invitation copied.');
      })}>Copy pairing invitation</button>
    </div>}
    {state === 'claimed' && <div className="handoff-preview">
      <label>Fingerprint shown by the bridge<input value={fingerprint} onChange={e => setFingerprint(e.target.value)} maxLength={20} autoComplete="off" spellCheck={false}/></label>
      <button className="button primary" disabled={busy || !/^[a-fA-F0-9]{20}$/.test(fingerprint)} onClick={() => perform(async () => {
        await api('/desktop/pairing/' + encodeURIComponent(id!), {approve: true, fingerprint});
        setPairing(current => current && {...current, state: 'approved'});
      })}>Confirm fingerprint</button>
    </div>}
    {state === 'approved' && <p role="status">Approved. Waiting for the local bridge to finish pairing.</p>}
    {state === 'redeemed' && <p role="status">Paired. Open a new desktop assistant session and call <code>aegis_status</code>.</p>}
    {state === 'expired' && <p role="status">The invitation expired. Create another invitation to try again.</p>}
    {active && <button className="button light" disabled={busy} onClick={() => perform(async () => {
      await api('/desktop/pairing/' + encodeURIComponent(id!), {approve: false});
      setInvite(''); setFingerprint(''); setPairing(undefined); setNotice('Pairing invitation cancelled.');
    })}>Cancel pairing</button>}
    <details className="handoff-preview"><summary>Local MCP configuration</summary>
      <p>Set the same URL and new token file path when you run <code>aegis-mcp pair</code>. Use a private directory and the app’s local stdio configuration.</p>
      <pre>{config}</pre>
    </details>
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
