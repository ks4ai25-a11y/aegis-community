import {useState} from 'react';
import {Wrench} from 'lucide-react';
import {api} from './client';
import {useAIStatus} from './Assessment';

// Guidance and an optional local-model patch draft for one finding. Drafts are
// validated against the exact inventoried file and never applied by Aegis.
export function Remediation({finding}: {finding: any}) {
  const ai = useAIStatus();
  const [data, setData] = useState<any>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const body = (draft: boolean) => ({finding: {repository_id: finding.repository_id, category: finding.category, summary: finding.summary, path: finding.path || '', line: finding.line || 0, package_name: finding.package_name || '', installed_version: finding.installed_version || '', advisories: finding.advisories || [], rule_ids: (finding.provenance || []).map((p: any) => p.rule_id).filter(Boolean)}, draft_patch: draft});
  async function load(draft: boolean) { setBusy(true); setError(''); try { setData(await api('/findings/remediation', body(draft))); } catch (e) { setError((e as Error).message); } finally { setBusy(false); } }
  function download() {
    const blob = new Blob([data.remediation.patch_draft.unified_diff], {type: 'text/x-diff'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = (finding.path || 'fix').replaceAll('/', '_') + '.patch'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  if (finding.category === 'configuration_claim') return null;
  return <details className="remediation"><summary><Wrench size={13}/> How to fix</summary>
    <div className="actions-row">
      <button disabled={busy} className="button light" onClick={() => load(false)}>Show guidance</button>
      {finding.category === 'static_pattern' && ai?.provider && ai.provider !== 'none' && <button disabled={busy} className="button light" onClick={() => load(true)}>{busy ? 'Drafting…' : 'Draft a patch with ' + (ai.code_model || ai.model)}</button>}
    </div>
    {error && <div role="alert" className="alert error">{error}</div>}
    {data && <>
      <p><strong>{data.remediation.title}</strong> <span className="badge">{data.remediation.priority}</span></p>
      <ol>{data.remediation.steps.map((s: string) => <li key={s}>{s}</li>)}</ol>
      {data.excerpt && <pre className="mono">{data.excerpt.lines.map((l: string, i: number) => String(data.excerpt.start_line + i).padStart(4) + '  ' + l).join('\n')}</pre>}
      {data.remediation.patch_draft && <>
        <p className="small">Draft by {data.remediation.patch_draft.model}; applies cleanly to the inventoried file. Review it, apply it in your own checkout and run your tests. Aegis never writes to your repository.</p>
        <pre className="mono">{data.remediation.patch_draft.unified_diff}</pre>
        <p className="small muted">{data.remediation.patch_draft.explanation}</p>
        <button className="button light" onClick={download}>Download .patch</button>
      </>}
      {data.remediation.patch_draft_note && <p className="small muted">No patch draft: {data.remediation.patch_draft_note}</p>}
      {data.remediation.limitations.map((l: string) => <p className="small muted" key={l}>{l}</p>)}
    </>}
  </details>;
}
