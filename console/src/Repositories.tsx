// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useState} from 'react';
import {FolderLock,RefreshCw} from 'lucide-react';
import {api,human,short} from './client';
import {ScannerNotice} from './Scans';
import {Empty} from './ui';
import {connectRepository,listRepositories,listRepositoryAssets,getApplicationMap} from './generated/research-client';
import type {RepositoryV1,ApplicationMapV1} from './generated/contracts';

type Props={action:(work:()=>Promise<unknown>,message?:string)=>Promise<unknown>;busy:boolean};
export function Repositories({action,busy}:Props){
 const[assets,setAssets]=useState<string[]>([]),[asset,setAsset]=useState(''),[ack,setAck]=useState(false),[repos,setRepos]=useState<RepositoryV1[]>([]),[map,setMap]=useState<ApplicationMapV1>(),[error,setError]=useState(''),[loading,setLoading]=useState(true);
 async function reload(){const [catalogue,connected]=await Promise.all([listRepositoryAssets(),listRepositories()]);setAssets(catalogue.asset_ids);setRepos(connected.items);setAsset(previous=>catalogue.asset_ids.includes(previous)?previous:catalogue.asset_ids[0]||'')}
 useEffect(()=>{let live=true;reload().catch(e=>{if(live)setError(e.message)}).finally(()=>{if(live)setLoading(false)});return()=>{live=false}},[]);
 return <>
  {error&&<div role="alert" className="alert error">{error}</div>}
  <section className="card">
   <div className="card-heading"><h2>Connect a read-only repository</h2><span className="pill">Static inventory</span></div>
   <p className="muted">Choose a directory provisioned by the local operator. Connecting reads file references and declared routes (Next.js conventions; Express, FastAPI and Flask literal registrations). Source scripts and dependencies are never executed.</p>
   {loading?<p role="status">Loading provisioned mounts…</p>:assets.length===0?<p>No repository mounts are available. The operator must provision a read-only directory first.</p>:<>
    <label htmlFor="repository-asset">Provisioned repository</label>
    <select id="repository-asset" value={asset} onChange={e=>{setAsset(e.target.value);setAck(false)}}>{assets.map(a=><option key={a} value={a}>{a}</option>)}</select>
    <label className="checkbox"><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>I authorize read-only inventory of this provisioned repository.</label>
    <button className="button primary" disabled={busy||!ack||!asset} onClick={()=>action(async()=>{const repo=await connectRepository({app_id:'app_demo',asset_id:asset,acknowledge_read_only:true});setMap(await getApplicationMap(repo.repository_id));await reload();setAck(false)},'Read-only repository connected. No code was executed.')}><FolderLock size={16}/>Connect and inventory</button>
   </>}
  </section>
  <section className="card">
   <div className="card-heading"><h2>Connected repositories</h2><button disabled={busy} className="button light" onClick={()=>action(reload)}><RefreshCw size={15}/>Refresh</button></div>
   <ScannerNotice compact/>
   <p className="muted">Reconnect a mount to capture source changes. Maps retain prior content identities. With rescan on change enabled, Aegis re-reads the repository every few minutes and queues a scan with the chosen scanners when its content identity changes. No scan runs while one for that repository is queued or running, or while a scanner cleanup is held.</p>
   {repos.length===0?<Empty title="No repositories connected" text="Connect a provisioned folder above to see its routes and scan it." icon={<FolderLock size={22}/>}/>:<div className="table-wrap"><table><thead><tr><th>Repository</th><th>Mode</th><th>Map identity</th><th>Inspect</th><th>Rescan on change</th></tr></thead><tbody>{repos.map(r=><tr key={r.repository_id}><td>{r.asset_id}</td><td>{human(r.mode)}</td><td className="mono">{short(r.map_digest)}</td><td><button disabled={busy} className="button light" onClick={()=>action(async()=>setMap(await getApplicationMap(r.repository_id)))}>View map</button></td><td><RescanToggle repository={r.repository_id} action={action} busy={busy}/></td></tr>)}</tbody></table></div>}
  </section>
  {map&&<section className="card">
   <div className="card-heading"><h2>Application map</h2><span className="pill">Declared source facts</span></div>
   <div className="system-row"><span>Source reference</span><span>{map.source_ref}</span></div>
   <div className="system-row"><span>Included file references</span><span>{map.files.length}</span></div>
   <div className="system-row"><span>Commit metadata</span><span className="mono">{map.commit_sha||'Unavailable'}</span></div>
   <div className="system-row"><span>Framework manifests</span><span>{map.frameworks.join(', ')||'None recognized'}</span></div>
   <div className="system-row"><span>Extractors</span><span>{map.extractors.map(e=>e.id+' '+e.version).join(', ')}</span></div>
   <p className="mono muted">Content identity: {map.content_digest}</p>
   {map.routes.length>0?<div className="table-wrap"><table><thead><tr><th>Method</th><th>Declared route</th><th>Source location</th><th>Authorization signal</th><th>Confidence</th></tr></thead><tbody>{map.routes.map((r,i)=><tr key={i}><td className="mono">{r.method==='unknown'?'—':r.method}</td><td>{r.pattern}</td><td>{r.source_path}</td><td>{r.auth_signal==='auth_middleware_named'?'Auth-named middleware':'Not assessed'}</td><td>{r.confidence}</td></tr>)}</tbody></table></div>:<p>No route conventions recognized. This does not establish that the application has no routes.</p>}
   <ul>{map.unknowns.map(u=><li key={u}>{u}</li>)}</ul>
  </section>}
  {map&&<ResearchPlans repository={repos.find(r=>r.map_digest===map.content_digest)?.repository_id} action={action} busy={busy}/>}
 </>;
}

type Policy={enabled:boolean;tool_ids:string[];last_outcome?:string;last_checked_at?:string};
const RESCAN_TOOLS=['bandit','gitleaks','osv_v2','semgrep_ce','syft','trivy'];
function RescanToggle({repository,action,busy}:{repository:string}&Props){
 const[p,setP]=useState<Policy>(),[unavailable,setUnavailable]=useState(false);
 useEffect(()=>{let live=true;api<Policy>(`/repos/${repository}/rescan`).then(v=>{if(live)setP(v)}).catch(()=>{if(live)setUnavailable(true)});return()=>{live=false}},[repository]);
 if(unavailable)return <span className="muted">Scanner not provisioned</span>;
 if(!p)return <span className="muted">…</span>;
 const set=(enabled:boolean)=>action(async()=>setP(await api<Policy>(`/repos/${repository}/rescan`,{enabled,tool_ids:enabled?RESCAN_TOOLS:[],tool_timeout_seconds:enabled?120:0})),enabled?'Automatic rescans enabled for this repository.':'Automatic rescans disabled.');
 return <label className="checkbox" title={p.last_outcome?`Last check: ${p.last_outcome.replaceAll('_',' ')}`:undefined}><input type="checkbox" aria-label={`Rescan ${repository} on change`} disabled={busy} checked={p.enabled} onChange={e=>set(e.target.checked)}/>{p.enabled?(p.last_outcome?p.last_outcome.replaceAll('_',' '):'On'):'Off'}</label>;
}

type ResearchPlan={hypothesis_id:string;claim:string;source_refs:string[];test_template_id:string;security_requirement_id:string;runner:string;next_step:string;evidence_status:string;origin:string};
type PlanSet={plans:ResearchPlan[];planner:string;model?:string;fallback_reason?:string;rejected_model_output:string[];tool_log:{tool:string;argument?:string;result:string}[];limitations:string[];plan_set_digest:string};
function ResearchPlans({repository,action,busy}:{repository?:string}&Props){
 const[set,setSet]=useState<PlanSet>(),[ai,setAI]=useState(false);
 useEffect(()=>{api<{provider:string}>('/ai/status').then(s=>setAI(s.provider!=='none')).catch(()=>setAI(false))},[]);
 if(!repository)return null;
 const run=(use_model:boolean)=>action(async()=>setSet(await api<PlanSet>(`/repos/${repository}/research-plan`,{use_model})),'Research plan ready. Nothing was run.');
 return <section className="card">
  <div className="card-heading"><h2>Research plan</h2><span className="pill">Hypotheses only</span></div>
  <p className="muted">The planner reads this map and the latest findings and proposes what to test, using only a fixed catalogue of bundled fixture tests. It cannot run commands, contact hosts or change code.</p>
  <div className="actions-row"><button className="button light" disabled={busy} onClick={()=>run(false)}>Plan from inventory</button>{ai&&<button className="button light" disabled={busy} onClick={()=>run(true)}>Plan with local model</button>}</div>
  {set&&<>
   <div className="system-row"><span>Planner</span><span>{set.planner}{set.model?' · '+set.model:''}{set.fallback_reason?' (fallback: '+set.fallback_reason+')':''}</span></div>
   {set.plans.length===0?<p>No hypotheses. This does not mean the application has no weaknesses.</p>:<div className="table-wrap"><table><thead><tr><th>Hypothesis</th><th>Source</th><th>Test template</th><th>How to run</th></tr></thead><tbody>{set.plans.map(p=><tr key={p.hypothesis_id}><td>{p.claim}<div className="muted">{p.evidence_status.replaceAll('_',' ')} · {p.origin}</div></td><td className="mono">{p.source_refs.join(', ')}</td><td className="mono">{p.test_template_id}</td><td>{p.next_step}</td></tr>)}</tbody></table></div>}
   {set.rejected_model_output.length>0&&<details><summary>{set.rejected_model_output.length} model suggestions rejected</summary><ul>{set.rejected_model_output.map((r,i)=><li key={i}>{r}</li>)}</ul></details>}
   <ul>{set.limitations.map(l=><li key={l}>{l}</li>)}</ul>
  </>}
 </section>;
}
