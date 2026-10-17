import {useEffect,useState} from 'react';
import {FolderLock,RefreshCw} from 'lucide-react';
import {short} from './client';
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
   <p className="muted">Reconnect a mount to capture source changes. Maps retain prior content identities. Scanner execution and findings are not yet connected to this view.</p>
   {repos.length===0?<p>No repositories connected.</p>:<div className="table-wrap"><table><thead><tr><th>Repository</th><th>Mode</th><th>Map identity</th><th>Inspect</th></tr></thead><tbody>{repos.map(r=><tr key={r.repository_id}><td>{r.asset_id}</td><td>{r.mode}</td><td className="mono">{short(r.map_digest)}</td><td><button disabled={busy} className="button light" onClick={()=>action(async()=>setMap(await getApplicationMap(r.repository_id)))}>View map</button></td></tr>)}</tbody></table></div>}
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
 </>;
}
