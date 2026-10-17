import {useEffect,useState} from 'react';
import {FileCheck2,LockKeyhole,RotateCcw,Terminal} from 'lucide-react';
import {key,short,human} from './client';
import{createScopeGrant,listVerifications,getVerification,getVerificationReport,approveScopeGrant,revokeScopeGrant,createVerification,cancelVerification}from'./generated/research-client';
import {Report} from './Report';
import {Empty} from './ui';

import type {ScopeGrantRecordV1 as GrantRecord,ResearchJobV1 as Job,VerificationReportV1} from './generated/contracts';
type Props={action:(work:()=>Promise<unknown>,message?:string)=>Promise<unknown>;busy:boolean;status?:{gateway_healthy:boolean;active_revision:string}};

export function Verification({action,busy,status}:Props) {
 const[scope,setScope]=useState<GrantRecord>(),[ack,setAck]=useState(false),[job,setJob]=useState<Job>(),[jobs,setJobs]=useState<Job[]>([]),[report,setReport]=useState<VerificationReportV1>(),[error,setError]=useState(''),[now,setNow]=useState(Date.now());
 const running=job?.state==='queued'||job?.state==='running';
 async function reloadJobs(){const v=await listVerifications();setJobs(v.items)}
 useEffect(()=>{reloadJobs().catch(e=>setError(e.message));const t=setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(t)},[]);
 useEffect(()=>{
  if(!job||!running)return;let alive=true;
  const update=async()=>{try{const next=await getVerification(job.job_id);if(!alive)return;setJob(next);if(!['queued','running'].includes(next.state)){await reloadJobs();if(next.report_digest){const r=await getVerificationReport(next.report_digest);setReport(r)}}}catch(e){if(alive)setError((e as Error).message)}};
  const t=setInterval(update,750);return()=>{alive=false;clearInterval(t)};
 },[job?.job_id,running]);
 const scopeUsable=scope?.state==='active'&&scope.requests_remaining>=4&&new Date(scope.grant.expires_at).getTime()>now;
 async function inspect(j:Job){setJob(j);setReport(undefined);if(j.report_digest)setReport(await getVerificationReport(j.report_digest))}
 return <>
  {error&&<div className="alert error" role="alert">{error}</div>}
  <section className="card">
   <div className="card-heading"><h2>Approve a bounded test scope</h2><span className="pill">Aegis-owned fixture</span></div>
   <p className="muted">Review the exact target and limits before testing. Each grant permits four requests in total, then it is exhausted. Production targets are unavailable.</p>
   <button disabled={busy||running} className="button light" onClick={()=>action(async()=>{const g=await createScopeGrant({app_id:'app_demo',mode:'test_lab',fixture_id:'crs-synthetic-sqli-pattern-v1',lifetime_minutes:10});setScope(g);setAck(false)})}><LockKeyhole size={15}/>Prepare scope for review</button>
   {scope&&<>
    <div className="system-row"><span>Target</span><span>{scope.grant.network_addresses.join(', ')}</span></div>
    <div className="system-row"><span>Routes</span><span>{scope.grant.allowed_routes.join(', ')}</span></div>
    <div className="system-row"><span>Limits</span><span>{scope.grant.max_requests} requests total · {scope.grant.max_duration_seconds}s · one worker</span></div>
    <div className="system-row"><span>Expires</span><span>{new Date(scope.grant.expires_at).toLocaleString()}</span></div>
    <div className="system-row"><span>State / remaining requests</span><span>{human(scope.state)} / {scope.requests_remaining}</span></div>
    <p className="mono muted">Exact scope: {scope.approved_digest}</p>
    {scope.state==='draft'&&<><label className="checkbox"><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>I approve these synthetic targets, routes, expiry and limits.</label><button disabled={busy||!ack} className="button primary" onClick={()=>action(async()=>setScope(await approveScopeGrant(scope.grant.scope_grant_id,{approved_digest:scope.approved_digest,acknowledge_test_scope:true})))}>Approve exact scope</button></>}
    {scope.state==='active'&&<button disabled={busy} className="button light" onClick={()=>action(async()=>{await revokeScopeGrant(scope.grant.scope_grant_id,{});setScope({...scope,state:'revoked'})},'Scope revoked. Queued and running work is being cancelled.')}><RotateCcw size={15}/>Revoke scope</button>}
   </>}
  </section>
  <section className="card">
   <div className="card-heading"><h2>Proof of Protection</h2><span className="pill">Isolated demo only</span></div>
   <p className="muted">The worker sends controls to separate baseline and candidate gateways. Durable status survives controller restarts. A timeout, cancellation or missing evidence cannot become a passing proof.</p>
   <div className="fixture"><span className="fixture-icon"><Terminal size={25}/></span><div><h3>CRS synthetic SQLi pattern</h3><p>Fixed corpus · exact policy revision {short(status?.active_revision)}</p></div></div>
   <button disabled={busy||running||!scopeUsable||!status?.gateway_healthy} className="button primary" onClick={()=>action(async()=>{if(!scope||!status)return;const j=await createVerification({schema_version:'1.0',app_id:'app_demo',scope_grant_id:scope.grant.scope_grant_id,scope_digest:scope.approved_digest,fixture_id:'crs-synthetic-sqli-pattern-v1',policy_digest:status.active_revision},key());setJob(j);setReport(undefined);setScope({...scope,requests_remaining:0});await reloadJobs()})}><FileCheck2 size={15}/>{running?'Verification in progress':'Queue scoped verification'}</button>{!busy&&!running&&(!scopeUsable?<small className="muted button-reason">Prepare and approve a test scope above first.</small>:!status?.gateway_healthy?<small className="muted button-reason">Waiting for the gateway to report healthy.</small>:null)}
   {job&&<div className="note" role="status"><FileCheck2 size={17}/><div><p>Job {short(job.job_id)}: {human(job.state)} · attempts {job.attempts}{job.error_code?' · '+job.error_code:''}</p>{running&&<button disabled={busy} className="button light" onClick={()=>action(async()=>setJob(await cancelVerification(job.job_id,{})),'Cancellation requested. The worker must stop before recording a result.')}>Cancel job</button>}{!running&&!job.report_digest&&<p>No verified report was recorded for this job.</p>}</div></div>}
   {report&&<Report report={report}/>}
  </section>
  <section className="card"><div className="card-heading"><h2>Verification history</h2><button className="button light" onClick={()=>action(reloadJobs)}>Refresh</button></div><div className="table-wrap"><table><thead><tr><th>Job</th><th>State</th><th>Created</th><th>Evidence</th></tr></thead><tbody>{jobs.map(j=><tr key={j.job_id}><td className="mono">{short(j.job_id)}</td><td>{human(j.state)}</td><td>{new Date(j.created_at).toLocaleString()}</td><td><button className="button light" onClick={()=>action(()=>inspect(j))}>{j.report_digest?'Inspect report':'Inspect status'}</button></td></tr>)}</tbody></table></div>{jobs.length===0&&<Empty title="No verifications yet" text="Approve a test scope above, then queue a verification; its report appears here." icon={<FileCheck2 size={22}/>}/>}</section>
 </>
}
