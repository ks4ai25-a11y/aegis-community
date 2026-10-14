import {useEffect,useRef,useState} from 'react';
import {ArrowRight,RefreshCw} from 'lucide-react';
import {listFindings} from './generated/research-client';
import type {FindingPageV1,FindingQueryV1,ScannerSuiteResultV1} from './generated/contracts';
import {short} from './client';

type Category=NonNullable<FindingQueryV1['category']>|'';
type Severity=NonNullable<FindingQueryV1['severity']>|'';
const label=(value:string)=>value.replaceAll('_',' ');
export function Findings({result}:{result:ScannerSuiteResultV1}){
 const [category,setCategory]=useState<Category>(''),[severity,setSeverity]=useState<Severity>(''),[page,setPage]=useState<FindingPageV1>(),[number,setNumber]=useState(1),[error,setError]=useState(''),[loading,setLoading]=useState(false);
 const generation=useRef(0),mounted=useRef(false);
 const d=result.document;
 async function load(cursor='',nextNumber=1){
  const request=++generation.current;setLoading(true);setError('');
  try{
   const next=await listFindings({job_id:d.job_id,limit:20,...(category?{category}:{}),...(severity?{severity}:{}),...(cursor?{cursor}:{})});
   if(!mounted.current||request!==generation.current)return;
   const refs=new Map<string,string>(d.tools.map(t=>[t.tool_id,t.receipt_digest]));
   if(next.job_id!==d.job_id||next.owner_id!==d.owner_id||next.request_digest!==d.request_digest||next.result_digest!==result.result_digest||next.snapshot_digest!==d.snapshot_digest||next.status!==d.status||next.tool_claims!==d.finding_claims||next.has_partial!==d.has_partial||next.has_stale_database!==d.has_stale_database||next.has_tool_error!==d.has_tool_error||next.distinct_static_claims>d.finding_claims||next.matching_static_claims>next.distinct_static_claims||[next.tool_claims,next.distinct_static_claims,next.matching_static_claims].some(n=>!Number.isInteger(n)||n<0||n>60000)||next.items.length>next.matching_static_claims||next.items.length>20||next.next_cursor.length>512||cursor&&next.next_cursor===cursor)throw new Error('Finding page does not match the selected immutable result');
   const ids=new Set<string>();
   for(const entry of next.items){
    const f=entry.finding;
    const receipts=[...new Set(f.provenance.map(p=>refs.get(p.tool_id)))].sort();
    if(!/^sha256:[0-9a-f]{64}$/.test(entry.record_id)||ids.has(entry.record_id)||f.app_id!==d.app_id||f.repository_id!==d.repository_id||f.evidence_tier!=='T0'||f.status!=='suspected'||f.confidence!=='low'||category&&f.category!==category||severity&&f.severity!==severity||f.provenance.length===0||f.provenance.some(p=>p.input_digest!==d.snapshot_digest)||receipts.includes(undefined)||JSON.stringify(receipts)!==JSON.stringify([...entry.receipt_digests].sort()))throw new Error('Finding provenance, filters or proof classification could not be confirmed');
    ids.add(entry.record_id);
   }
   setPage(next);setNumber(nextNumber);
  }catch(e){if(mounted.current&&request===generation.current){setPage(undefined);setError((e as Error).message)}}
  finally{if(mounted.current&&request===generation.current)setLoading(false)}
 }
 useEffect(()=>{mounted.current=true;setPage(undefined);load();return()=>{mounted.current=false;generation.current++}},[result.result_digest,category,severity]);
 return <section className="card finding-details" aria-busy={loading}>
  <div className="card-heading"><h2>Static finding details</h2><span className="pill">Suspected · T0</span></div>
  <p className="muted">Equivalent dependency coordinates and advisory/lockfile claims can share one record. Static rules from different tools remain separate unless equivalence is established. Every source and its claimed severity remain visible.</p>
  <div className="finding-filters"><label>Finding category<select value={category} onChange={e=>setCategory(e.target.value as Category)}><option value="">All categories</option><option value="static_pattern">Static patterns</option><option value="secret_candidate">Secret candidates</option><option value="known_vulnerable_dependency">Dependency advisory claims</option></select></label><label>Claimed severity<select value={severity} onChange={e=>setSeverity(e.target.value as Severity)}><option value="">All severities</option>{['informational','low','medium','high','critical'].map(v=><option key={v} value={v}>{v}</option>)}</select></label></div>
  {error&&<div className="alert error" role="alert">Finding evidence unavailable: {error}. No empty or clean result is inferred. <button className="button light" disabled={loading} onClick={()=>load()}>Retry from first page</button></div>}
  {loading&&<p role="status">Reading normalized finding evidence…</p>}
  {page&&<>
   <p className="small muted">{page.tool_claims} tool claims · {page.distinct_static_claims} distinct static records · {page.matching_static_claims} match the filters. These are not confirmed vulnerabilities.</p>
   {page.items.length===0&&<p>No static records match these filters. The scan's coverage, database and tool-error flags still apply.</p>}
   {page.items.map(({record_id,finding:f,receipt_digests})=><article className="finding-record" key={record_id}>
    <div className="card-heading"><h3>{label(f.category)}</h3><span className="badge">Claimed severity: {f.severity}</span></div>
    <p>{f.summary}</p>
    <p className="small">Evidence: {f.evidence_tier} · Triage: {f.status} · Confidence: {f.confidence}</p>
    <p className="mono">{f.path||'Source location unavailable'}{f.line?':'+f.line:''}</p>
    {f.package_url&&<p className="mono">Package: {f.package_url}</p>}
    {f.installed_version&&<p>Installed version claim: {f.installed_version}</p>}
    {f.advisories?.length&&<p>Advisories: {f.advisories.join(', ')}</p>}
    <p className="small muted">{f.coverage_note}</p>
    <div className="table-wrap"><table><thead><tr><th>Original tool</th><th>Version / parser</th><th>Rule / advisory</th><th>Claimed severity</th></tr></thead><tbody>{f.provenance.map((p,i)=><tr key={i}><td>{p.tool_id}</td><td>{p.tool_version} / {p.parser_version}</td><td>{p.rule_id||'Unspecified'}</td><td>{p.severity_claimed||'Unspecified'}</td></tr>)}</tbody></table></div>
    <details><summary>Source and receipt identities</summary><p className="mono">Record: {record_id}</p><p className="mono">Finding: {f.id}</p>{f.provenance.map((p,i)=><div key={i}><p className="mono">{p.tool_id} image: {p.tool_image_digest}</p><p className="mono">Input: {p.input_digest}</p></div>)}{receipt_digests.map(ref=><p className="mono" key={ref}>Receipt: {ref}</p>)}</details>
   </article>)}
   <div className="finding-pagination"><span>Page {number} · {page.items.length} records on this page</span><button className="button light" disabled={loading||number===1} onClick={()=>load()}><RefreshCw size={14}/>Back to first page</button><button className="button light" disabled={loading||!page.next_cursor} onClick={()=>load(page.next_cursor,number+1)}>Next findings<ArrowRight size={14}/></button></div>
   <p className="small mono muted">Bound result: {short(page.result_digest)} · Snapshot: {short(page.snapshot_digest)}</p>
  </>}
 </section>;
}
