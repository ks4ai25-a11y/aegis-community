import {useEffect,useRef,useState} from 'react';
import {FileSearch,RefreshCw,Square} from 'lucide-react';
import {api,key,short} from './client';
import {Findings} from './Findings';
import {Empty} from './ui';
import {createScan,listScans,getScan,cancelScan,getScanResult,listRepositories} from './generated/research-client';
import type {RepositoryV1,ScannerJobV1,ScannerJobStatusV1,ScannerSuiteResultV1} from './generated/contracts';

type Props={action:(work:()=>Promise<unknown>,message?:string)=>Promise<unknown>;busy:boolean;initialJob?:string};
const tools=[['bandit','Bandit','Python patterns'],['gitleaks','Gitleaks','Secret candidates'],['osv_v2','OSV Scanner','Dependency advisories · offline database required'],['semgrep_ce','Semgrep CE','Static patterns'],['syft','Syft','Software inventory'],['trivy','Trivy','Dependency advisories · offline database required']] as const;
const terminalResults=new Set(['completed','completed_partial','completed_stale_db','tool_error']);
const label=(value:string)=>value.replaceAll('_',' ');
function checkStatus(value:ScannerJobStatusV1,id:string){
 if(value.job.job_id!==id)throw new Error('Scan response does not match the selected job');
}
function checkResult(value:ScannerSuiteResultV1,status:ScannerJobStatusV1){
 const d=value.document,j=status.job;
 if(d.job_id!==j.job_id||d.request_digest!==j.request_digest||d.owner_id!==j.owner_id||d.repository_id!==j.input.repository_id||d.map_digest!==j.input.map_digest||d.tool_lock_digest!==j.tool_lock_digest||d.status!==j.state||d.evidence_tier!=='T0'||d.cleanup_required!==true)throw new Error('Result identity or evidence classification does not match this scan');
}


export function Scans({action,busy,initialJob}:Props){
 const [repos,setRepos]=useState<RepositoryV1[]>([]),[repository,setRepository]=useState(''),[selected,setSelected]=useState<string[]>(['bandit']),[seconds,setSeconds]=useState('120'),[ack,setAck]=useState(false),[jobs,setJobs]=useState<ScannerJobV1[]>([]),[jobID,setJobID]=useState(''),[status,setStatus]=useState<ScannerJobStatusV1>(),[result,setResult]=useState<ScannerSuiteResultV1>(),[error,setError]=useState(''),[loading,setLoading]=useState(true),[reading,setReading]=useState(false);
 const mounted=useRef(false),inspection=useRef(0),retry=useRef<{signature:string;key:string}|undefined>(undefined);
 const repo=repos.find(r=>r.repository_id===repository),duration=Number(seconds);
 const validDuration=Number.isInteger(duration)&&duration>=1&&duration<=120;
 const active=status?.job.state==='queued'||status?.job.state==='running';
 async function reload(){
  const [r,j]=await Promise.all([listRepositories(),listScans()]);
  if(!mounted.current)return;
  setRepos(r.items);setJobs(j.items);setRepository(old=>r.items.some(v=>v.repository_id===old)?old:r.items[0]?.repository_id||'');
 }
 useEffect(()=>{mounted.current=true;reload().catch(e=>{if(mounted.current)setError(e.message)}).finally(()=>{if(mounted.current)setLoading(false)});return()=>{mounted.current=false;inspection.current++}},[]);
 async function inspect(id:string){
  const generation=++inspection.current;
  setJobID(id);setStatus(undefined);setResult(undefined);setReading(true);setError('');
  try{
   const next=await getScan(id);checkStatus(next,id);
   if(!mounted.current||generation!==inspection.current)return;
   setStatus(next);
   if(terminalResults.has(next.job.state)){
    const evidence=await getScanResult(id);checkResult(evidence,next);
    if(mounted.current&&generation===inspection.current)setResult(evidence);
   }
  }catch(e){if(mounted.current&&generation===inspection.current)setError((e as Error).message)}
  finally{if(mounted.current&&generation===inspection.current)setReading(false)}
 }
 useEffect(()=>{if(initialJob)inspect(initialJob)},[initialJob]);
 useEffect(()=>{
  if(!jobID||!active)return;
  let live=true,inFlight=false;
  const generation=inspection.current;
  const update=async()=>{
   if(inFlight)return;inFlight=true;
   try{
    const next=await getScan(jobID);checkStatus(next,jobID);
    if(!live||!mounted.current||generation!==inspection.current)return;
    let evidence:ScannerSuiteResultV1|undefined;
    let resultError='';
    if(terminalResults.has(next.job.state)){
     try{evidence=await getScanResult(jobID);checkResult(evidence,next)}catch(e){evidence=undefined;resultError=(e as Error).message}
    }
    if(!live||!mounted.current||generation!==inspection.current)return;
    setResult(evidence);setStatus(next);setError(resultError);
    if(!['queued','running'].includes(next.job.state))await reload();
   }catch(e){if(live&&mounted.current&&generation===inspection.current)setError((e as Error).message)}
   finally{inFlight=false}
  };
  const timer=setInterval(update,2000);
  return()=>{live=false;clearInterval(timer)};
 },[jobID,active]);
 async function submit(){
  if(!repo||!selected.length||!validDuration||!ack)return;
  const body={schema_version:'1.0' as const,app_id:'app_demo' as const,repository_id:repo.repository_id,map_digest:repo.map_digest,mode:'repo_offline' as const,tool_ids:[...selected].sort() as Array<typeof tools[number][0]>,tool_timeout_seconds:duration};
  const signature=JSON.stringify(body);
  if(retry.current?.signature!==signature)retry.current={signature,key:key()};
  setError('');
  let created:ScannerJobV1;
  try{created=await createScan(body,retry.current.key)}catch(e){
   setError('Scan acknowledgement is unconfirmed. Retry the unchanged request to reuse its idempotency key. '+(e as Error).message);
   throw e;
  }
  retry.current=undefined;setAck(false);await reload();await inspect(created.job_id);
 }
 return <>
  {error&&<div className="alert error" role="alert">{error}. Displayed status may be stale; refresh before relying on it.</div>}
  <ScannerNotice/>
  <section className="card scan-request">
   <div className="card-heading"><h2>Queue a read-only scan</h2><span className="pill">Offline static tools</span></div>
   <p className="muted">Scanners inspect an approved source snapshot without executing repository scripts.</p>
   {loading?<p role="status">Loading owned repositories and scans…</p>:repos.length===0?<p>Connect a provisioned repository on the Repositories page first.</p>:<>
    <label htmlFor="scan-repository">Connected repository</label>
    <select id="scan-repository" value={repository} disabled={busy} onChange={e=>{setRepository(e.target.value);setAck(false)}}>{repos.map(r=><option key={r.repository_id} value={r.repository_id}>{r.asset_id} · {short(r.map_digest)}</option>)}</select>
    <p className="small muted">Reconnect source changes on the Repositories page before scanning. The request binds this map: <span className="mono">{repo?.map_digest}</span></p>
    <fieldset className="scanner-tools"><legend>Choose scanners</legend>{tools.map(([id,name,note])=><label className="checkbox" key={id}><input type="checkbox" checked={selected.includes(id)} disabled={busy} onChange={e=>{setSelected(old=>e.target.checked?[...old,id]:old.filter(v=>v!==id));setAck(false)}}/><span><strong>{name}</strong><small>{note}</small></span></label>)}</fieldset>
    <label htmlFor="scan-duration">Time limit per tool (seconds)</label><input id="scan-duration" type="number" min="1" max="120" step="1" value={seconds} disabled={busy} onChange={e=>{setSeconds(e.target.value);setAck(false)}}/>
    {!validDuration&&<p role="alert">Choose a whole number from 1 to 120.</p>}
    <label className="checkbox"><input type="checkbox" checked={ack} disabled={busy} onChange={e=>setAck(e.target.checked)}/>I authorize these read-only tools on the selected repository snapshot.</label>
    <button className="button primary" disabled={busy||loading||!repo||!selected.length||!validDuration||!ack} onClick={()=>action(submit,'Scan request accepted. A queued job does not mean a scanner ran.')}><FileSearch size={16}/>Queue scan</button>{!busy&&!loading&&(!repo?<small className="muted button-reason">Connect a repository first.</small>:!selected.length?<small className="muted button-reason">Choose at least one scanner.</small>:!validDuration?<small className="muted button-reason">Set a time limit of 1–120 seconds.</small>:!ack?<small className="muted button-reason">Tick the authorisation above to queue the scan.</small>:null)}
   </>}
  </section>
  <section className="card">
   <div className="card-heading"><h2>Owned scan jobs</h2><button className="button light" disabled={busy||loading} onClick={()=>action(async()=>{setError('');await reload();if(jobID)await inspect(jobID)})}><RefreshCw size={15}/>Refresh scans</button></div>
   <p className="muted">Latest 100 jobs. Tool claims are static observations, not confirmed vulnerabilities or complete coverage.</p>
   {!jobs.length&&!loading?<Empty title="No scans yet" text="Queue a scan above; its status and results appear here." icon={<FileSearch size={22}/>}/>:<div className="table-wrap"><table><thead><tr><th>Requested</th><th>Tools</th><th>State</th><th>Inspect</th></tr></thead><tbody>{jobs.map(j=><tr key={j.job_id}><td>{new Date(j.created_at).toLocaleString()}</td><td>{j.input.tool_ids.join(', ')}</td><td><span className="badge">{label(j.state)}</span></td><td><button className="button light" disabled={busy} onClick={()=>inspect(j.job_id)}>View scan <span className="mono">{short(j.job_id)}</span></button></td></tr>)}</tbody></table></div>}
  </section>
  {reading&&<p role="status">Reading scan evidence…</p>}
  {status&&<section className="card scan-detail">
   <div className="card-heading"><h2>Selected scan</h2><span className="badge">{label(status.job.state)}</span></div>
   <p className="mono">{status.job.job_id}</p>
   <div className="system-row"><span>Execution admission</span><strong>{label(status.execution_admission)}</strong></div>
   <div className="system-row"><span>Cancellation requested</span><span>{status.job.cancel_requested?'Yes':'No'}</span></div>
   <div className="system-row"><span>Per-tool limit</span><span>{status.job.input.tool_timeout_seconds} seconds</span></div>
   <div className="system-row"><span>Request expires</span><span>{new Date(status.job.expires_at).toLocaleString()}</span></div>
   <p className="small mono muted">Source map: {status.job.input.map_digest}</p>
   <p className="small mono muted">Tool lock: {status.job.tool_lock_digest}</p>
   {status.job.error_code&&<p role="status">Recorded diagnostic: {status.job.error_code}</p>}
   <div className="note"><Square size={17}/><p>{status.execution_admission==='cleanup_required'?'Admission is held for independent cleanup verification. A terminal result does not prove that containers or workspaces are gone.':status.execution_admission==='active'?'The worker holds execution admission. Cancellation asks it to stop; resource cleanup must be verified separately.':status.execution_admission==='not_claimed'?'This job has not acquired execution admission. No scanner execution or result is implied.':'Resource cleanup is unconfirmed. Cancellation is not proof of resource absence.'}</p></div>
   {active&&!status.job.cancel_requested&&<button className="button light" disabled={busy} onClick={()=>action(async()=>{await cancelScan(status.job.job_id,{});await reload();await inspect(status.job.job_id)},'Cancellation requested. Cleanup is not confirmed.')}><Square size={15}/>Cancel selected scan</button>}
   {!result&&!reading&&<p>No immutable scanner result is displayed. {terminalResults.has(status.job.state)?'Refresh to retry the result read.':'Queued, cancelled, failed and timed-out jobs do not become zero-findings results.'}</p>}
  </section>}
  {result&&<><ScanResult result={result}/><Findings key={result.result_digest} result={result}/></>}
 </>;
}

export function ScanResult({result}:{result:ScannerSuiteResultV1}){
 const d=result.document;
 return <section className="card scan-result">
  <div className="card-heading"><h2>Static scan evidence</h2><span className="pill">{d.evidence_tier} · Tool claims</span></div>
  <div className="system-row"><span>Overall tool status</span><strong>{label(d.status)}</strong></div>
  <div className="system-row"><span>Tool finding claims</span><span>{d.finding_claims}</span></div>
  <div className="scan-flags"><span>Partial coverage: {d.has_partial?'Yes':'No'}</span><span>Stale database: {d.has_stale_database?'Yes':'No'}</span><span>Tool error: {d.has_tool_error?'Yes':'No'}</span></div>
  <p className="muted">Counts sum tool claims and may include overlap. They are not deduplicated vulnerabilities, exploit proof, or a clean-application verdict.</p>
  <div className="table-wrap"><table><thead><tr><th>Tool</th><th>Status</th><th>Claims</th><th>Inventory</th><th>Receipt</th></tr></thead><tbody>{d.tools.map(t=><tr key={t.tool_id}><td>{t.tool_id}</td><td>{label(t.status)}</td><td>{t.finding_claims}</td><td>{t.has_sbom?'SBOM present':'None'}</td><td className="mono">{short(t.receipt_digest)}</td></tr>)}</tbody></table></div>
  <p className="small mono muted">Result identity: {result.result_digest}</p><p className="small mono muted">Snapshot identity: {d.snapshot_digest}</p>
  <div className="note"><Square size={17}/><p>Cleanup verification is required. This result cannot release execution admission.</p></div>
 </section>;
}

// Queued scans only run when an operator has enrolled a scanner worker. The
// bundled demo has none, so say so before anyone waits on a queued job.
export function ScannerNotice({compact=false}:{compact?:boolean}){
 const[state,setState]=useState<{service_configured:boolean;enrolled_workers:number}>();
 useEffect(()=>{api('/system/status').then(v=>setState(v.scanner)).catch(()=>{})},[]);
 if(!state||state.enrolled_workers>0)return null;
 const text=state.service_configured?'No scanner worker is enrolled, so queued scans will wait until an operator enrols one.':'The scanner service is not configured on this installation, so scans cannot be queued.';
 return <div role="status" className="alert warn">{text}{!compact&&<> <a href="https://github.com/ks4ai25-a11y/aegis-community/blob/main/docs/operators/packaged-scanner-worker.md" target="_blank" rel="noreferrer noopener">How to enrol a scanner worker</a>.</>}</div>;
}
