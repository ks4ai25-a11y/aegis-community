// SPDX-License-Identifier: BUSL-1.1
import {useEffect,useRef,useState} from 'react';
import {api,setCSRF,short} from './client';
import {listFindingCatalogue,listRepositories} from './generated/research-client';
import type {FindingCataloguePageV1,RepositoryV1} from './generated/contracts';
import {FindingRecords,validateFindingPage} from './Findings';

export function Catalogue({onOpenScan}:{onOpenScan:(id:string)=>void}){
 const [owner,setOwner]=useState(''),[repos,setRepos]=useState<RepositoryV1[]>([]),[repository,setRepository]=useState(''),[category,setCategory]=useState(''),[severity,setSeverity]=useState(''),[limit,setLimit]=useState(20),[since,setSince]=useState(''),[until,setUntil]=useState(''),[page,setPage]=useState<FindingCataloguePageV1>(),[error,setError]=useState(''),[repoError,setRepoError]=useState(''),[busy,setBusy]=useState(false);
 const mounted=useRef(false),generation=useRef(0),identityRequest=useRef<Promise<{owner_id:string;csrf_token:string}>|undefined>(undefined);
 useEffect(()=>{
  mounted.current=true;let live=true;
  identityRequest.current??=api('/auth/session');
  identityRequest.current.then(v=>{if(!live)return;if(typeof v.owner_id!=='string'||!v.owner_id)throw new Error('Authenticated owner identity unavailable');setCSRF(v.csrf_token);setOwner(v.owner_id)}).catch(e=>{if(live)setError(e.message)});
  listRepositories().then(v=>{if(live)setRepos(v.items)}).catch(e=>{if(live)setRepoError(e.message)});
  return()=>{live=false;mounted.current=false;generation.current++};
 },[]);
 async function load(cursor='',prior?:FindingCataloguePageV1){
  if(!owner)return;
  const epoch=++generation.current;setBusy(true);setError('');setPage(undefined);
  try{
   const next=await listFindingCatalogue({limit,...(since?{since:new Date(since).toISOString()}:{}),...(until?{until:new Date(until).toISOString()}:{}),...(repository?{repository_id:repository}:{}),...(category?{category:category as 'static_pattern'|'secret_candidate'|'known_vulnerable_dependency'}:{}),...(severity?{severity:severity as 'critical'|'high'|'medium'|'low'|'informational'}:{}),...(cursor?{cursor}:{})});
   if(!mounted.current||epoch!==generation.current)return;
   if(next.schema_version!=='1.0'||next.owner_id!==owner||next.scope!=='retained_static_observations'||!/^sha256:[0-9a-f]{64}$/.test(next.result_set_digest)||![next.retained_result_count,next.jobs_without_result,next.result_index].every(Number.isInteger)||next.retained_result_count<0||next.retained_result_count>1000||next.jobs_without_result<0||next.jobs_without_result>1000||next.retained_result_count+next.jobs_without_result>1000||next.result_index<0||next.next_cursor.length>2048||cursor&&next.next_cursor===cursor||prior&&(next.result_set_digest!==prior.result_set_digest||next.retained_result_count!==prior.retained_result_count||next.result_index<prior.result_index||next.result_index>prior.result_index+1))throw new Error('Catalogue scope, result set or page position could not be confirmed');
   if(next.retained_result_count===0){if(next.result||next.findings||next.result_index!==0||next.next_cursor)throw new Error('Empty catalogue contains inconsistent evidence')}
   else{
    const result=next.result,findings=next.findings;
    if(!result||!findings||next.result_index>=next.retained_result_count||result.document.owner_id!==owner||result.document.evidence_tier!=='T0'||result.document.cleanup_required!==true||repository&&result.document.repository_id!==repository)throw new Error('Catalogue evidence does not match the selected owner or repository');
    if(findings.items.length>limit)throw new Error('Catalogue exceeds the selected page size');
    await validateFindingPage(findings,result,category,severity);
    if((findings.next_cursor!==''||next.result_index+1<next.retained_result_count)&&!next.next_cursor||!findings.next_cursor&&next.result_index+1===next.retained_result_count&&next.next_cursor)throw new Error('Catalogue continuation is incomplete');
   }
   if(mounted.current&&epoch===generation.current)setPage(next);
  }catch(e){if(mounted.current&&epoch===generation.current)setError((e as Error).message)}
  finally{if(mounted.current&&epoch===generation.current)setBusy(false)}
 }
 useEffect(()=>{setPage(undefined);if(owner)load();return()=>{generation.current++}},[owner,repository,category,severity,limit,since,until]);
 return <>
  <section className="card" aria-busy={busy}>
   <div className="card-heading"><h2>Retained finding observations</h2><span className="pill">Static evidence · T0</span></div>
   <p className="muted">Browse retained scan evidence across owned repositories. Each page belongs to one immutable scan. Repeated observations from different scans are kept separate; their counts are not added into a vulnerability total.</p>
   <div className="finding-filters"><label>Catalogue repository<select value={repository} onChange={e=>setRepository(e.target.value)}><option value="">All owned repositories</option>{repos.map(r=><option key={r.repository_id} value={r.repository_id}>{r.asset_id} · {short(r.repository_id)}</option>)}</select></label><label>Catalogue category<select value={category} onChange={e=>setCategory(e.target.value)}><option value="">All categories</option><option value="static_pattern">Static patterns</option><option value="secret_candidate">Secret candidates</option><option value="known_vulnerable_dependency">Dependency advisory claims</option></select></label><label>Catalogue severity<select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="">All claimed severities</option>{['critical','high','medium','low','informational'].map(s=><option key={s}>{s}</option>)}</select></label><label>Records per catalogue page<select value={limit} onChange={e=>setLimit(Number(e.target.value))}>{[2,10,20].map(n=><option key={n} value={n}>{n}</option>)}</select></label></div>
   <div className="finding-filters"><label>Results from (local time)<input type="datetime-local" value={since} onChange={e=>setSince(e.target.value)}/></label><label>Results before (local time)<input type="datetime-local" value={until} onChange={e=>setUntil(e.target.value)}/></label></div>
   {repoError&&<p role="alert">Repository filter unavailable: {repoError}</p>}
   {busy&&<p role="status">Revalidating retained finding evidence…</p>}
   {error&&<p className="alert error" role="alert">Catalogue evidence unavailable: {error}. No empty or clean result is inferred.</p>}
   <button className="button light" disabled={busy||!owner} onClick={()=>load()}>Refresh catalogue from first page</button>
  </section>
  {page&&<section className="card catalogue-results">
   <p>{page.retained_result_count} retained scan results · {page.jobs_without_result} jobs without an immutable result (all times in this repository selection).</p>
   {page.jobs_without_result>0&&<p className="note">Jobs without results have no finding or coverage conclusion. Queued, cancelled or failed execution is not a clean scan.</p>}
   {!page.result||!page.findings?<p>No immutable scanner results are available in this repository selection. This does not establish zero findings or complete coverage.</p>:<>
    <h2>Scan {page.result_index+1} of {page.retained_result_count}</h2>
    <p className="mono">Job: {page.findings.job_id}<br/>Repository: {page.result.document.repository_id}<br/>Snapshot: {page.findings.snapshot_digest}</p>
    <p>Observed result: {page.findings.status.replaceAll('_',' ')} · Partial: {page.findings.has_partial?'yes':'no'} · Stale database: {page.findings.has_stale_database?'yes':'no'} · Tool error: {page.findings.has_tool_error?'yes':'no'}</p>
    <p>{page.findings.tool_claims} tool claims · {page.findings.distinct_static_claims} distinct static records · {page.findings.matching_static_claims} match these filters in this scan.</p>
    {!page.findings.items.length&&<p>No records match in this scan. Other retained scans may contain matching observations; continue browsing. Coverage and error flags still apply.</p>}
    <button className="button light" onClick={()=>onOpenScan(page.findings!.job_id)}>Open this scan result</button>
    <FindingRecords key={page.result.result_digest} page={page.findings} result={page.result} onRecorded={(id,next)=>setPage(previous=>previous?.findings?{...previous,findings:{...previous.findings,items:previous.findings.items.map(entry=>entry.record_id===id&&(!entry.owner_review||entry.owner_review.document.revision<=next.document.revision)?{...entry,owner_review:next}:entry)}}:previous)}/>
   </>}
   <button className="button light" disabled={busy||!page.next_cursor} onClick={()=>load(page.next_cursor,page)}>Next retained observations</button>
   <p className="small mono muted">Result set: {page.result_set_digest}</p>
  </section>}
 </>;
}
