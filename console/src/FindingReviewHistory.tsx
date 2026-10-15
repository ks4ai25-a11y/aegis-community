import {useEffect,useRef,useState} from 'react';
import {getFindingTriageHistory} from './generated/research-client';
import type {FindingTriageHistoryV1,FindingTriageRecordV1} from './generated/contracts';
import {validateFindingReview} from './findingReview';

async function digest(value:unknown){
 const bytes=new TextEncoder().encode(JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')));
 const hash=await crypto.subtle.digest('SHA-256',bytes);
 return 'sha256:'+Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('');
}
export async function validateReviewHistory(next:FindingTriageHistoryV1,owner:string,job:string,result:string,record:string,known?:FindingTriageRecordV1){
 const d=next.document;
 if(Object.keys(next).length!==2||!d||d.schema_version!=='1.0'||d.assessment_scope!=='owner_review_only'||d.owner_id!==owner||d.job_id!==job||d.record_id!==record||d.result_digest!==result||d.complete!==true||!Number.isInteger(d.revision_count)||d.revision_count<0||d.revision_count>50||!Array.isArray(d.items)||d.items.length!==d.revision_count)throw new Error('Review history does not match the complete owned finding chain');
 const baseline={schema_version:'1.0',owner_id:owner,job_id:job,record_id:record,result_digest:result,revision:0,state:'suspected',rationale:'',previous_digest:'',updated_at:''};
 if(await digest(baseline)!==d.baseline_digest)throw new Error('Review history baseline could not be confirmed');
 let previous='';
 for(let index=0;index<d.items.length;index++){
  if(Object.keys(d.items[index]).length!==2)throw new Error('Unexpected review record fields');
  const item=await validateFindingReview(d.items[index],owner,job,result,record);
  if(item.document.revision!==index+1||item.document.previous_digest!==previous)throw new Error('Review history has a missing, reordered or broken decision');
  previous=item.triage_digest;
 }
 if(d.head_digest!==(previous||d.baseline_digest)||known&&(d.revision_count<known.document.revision||d.revision_count===known.document.revision&&d.head_digest!==known.triage_digest))throw new Error('Review history is older than or conflicts with the displayed assessment');
 const ordered={schema_version:d.schema_version,assessment_scope:d.assessment_scope,owner_id:d.owner_id,job_id:d.job_id,record_id:d.record_id,result_digest:d.result_digest,baseline_digest:d.baseline_digest,head_digest:d.head_digest,revision_count:d.revision_count,complete:d.complete,items:d.items.map(item=>({triage_digest:item.triage_digest,document:{schema_version:item.document.schema_version,owner_id:item.document.owner_id,job_id:item.document.job_id,record_id:item.document.record_id,result_digest:item.document.result_digest,revision:item.document.revision,state:item.document.state,rationale:item.document.rationale,previous_digest:item.document.previous_digest,updated_at:item.document.updated_at}}))};
 if(Object.keys(d).length!==Object.keys(ordered).length||await digest(ordered)!==next.history_digest)throw new Error('Review history digest could not be confirmed');
 return next;
}
export function FindingReviewHistory({owner,job,result,record,known}:{owner:string,job:string,result:string,record:string,known?:FindingTriageRecordV1}){
 const [history,setHistory]=useState<FindingTriageHistoryV1>(),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const alive=useRef(false),generation=useRef(0);
 useEffect(()=>{alive.current=true;setHistory(undefined);setError('');setBusy(false);generation.current++;return()=>{alive.current=false;generation.current++}},[owner,job,result,record,known?.triage_digest]);
 async function load(){
  const epoch=++generation.current;setBusy(true);setHistory(undefined);setError('');
  try{
   const next=await validateReviewHistory(await getFindingTriageHistory({record_id:record,result_digest:result},job),owner,job,result,record,known);
   if(alive.current&&epoch===generation.current)setHistory(next);
  }catch(e){if(alive.current&&epoch===generation.current)setError((e as Error).message)}
  finally{if(alive.current&&epoch===generation.current)setBusy(false)}
 }
 function download(){
  if(!history)return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(history,null,2)+'\n'],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download=`aegis-review-history-${record.slice(7,19)}-r${history.document.revision_count}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }
 return <section className="review-history" aria-label="Owner review history" aria-busy={busy}>
  <button className="button light" disabled={busy} onClick={load}>{history?'Reload review history':'View review history'}</button>
  {busy&&<p role="status">Checking the complete review chain…</p>}
  {error&&<p role="alert" className="alert error">Review history unavailable: {error}. No complete history is inferred.</p>}
  {history&&<>
   <h4>Recorded review history · {history.document.revision_count} decisions</h4>
   <p className="small muted">Owner assessments for this exact scan and finding. Original scanner evidence remains T0. Local hashes detect record changes under host trust; they are not publisher signatures.</p>
   {!history.document.revision_count&&<p>No owner decision has been recorded for this finding.</p>}
   <ol>{history.document.items.map(item=><li key={item.triage_digest}>
    <strong>Revision {item.document.revision} · {item.document.state.replaceAll('_',' ')}</strong>
    <p className="small"><time dateTime={item.document.updated_at}>{new Date(item.document.updated_at).toLocaleString()}</time></p>
    <p className="review-rationale">{item.document.rationale}</p>
    <p className="mono small">Decision digest: {item.triage_digest}</p>
   </li>)}</ol>
   <p className="mono small">History digest: {history.history_digest}</p>
   <p className="small muted">JSON export includes local review rationales. Save it privately.</p>
   <button className="button light" onClick={download}>Export review history JSON</button>
  </>}
 </section>;
}
