import {useEffect,useRef,useState} from 'react';
import {getFindingTriage,setFindingTriage} from './generated/research-client';
import type {FindingTriageInputV1,FindingTriageRecordV1} from './generated/contracts';
import {key} from './client';

type State=FindingTriageInputV1['state'];
const states:State[]=['suspected','unverified','false_positive','accepted_risk'];
export async function validateFindingReview(next:FindingTriageRecordV1,owner:string,job:string,result:string,record:string){
  const d=next.document;
  if(!d||d.schema_version!=='1.0'||d.owner_id!==owner||d.job_id!==job||d.result_digest!==result||d.record_id!==record||!Number.isInteger(d.revision)||d.revision<0||d.revision>50||!states.includes(d.state)||typeof d.rationale!=='string'||new TextEncoder().encode(d.rationale).length>512||/[\u0000-\u001f\u007f-\u009f]/.test(d.rationale)||typeof d.updated_at!=='string'||!/^sha256:[0-9a-f]{64}$/.test(next.triage_digest)||!(d.previous_digest===''||/^sha256:[0-9a-f]{64}$/.test(d.previous_digest))||(d.revision===0?(d.state!=='suspected'||d.rationale!==''||d.updated_at!==''||d.previous_digest!==''):d.rationale.trim().length<5||!Number.isFinite(Date.parse(d.updated_at))||d.revision===1&&d.previous_digest!==''||d.revision>1&&d.previous_digest===''))throw new Error('Triage response does not match the selected finding');
  const ordered={schema_version:d.schema_version,owner_id:d.owner_id,job_id:d.job_id,record_id:d.record_id,result_digest:d.result_digest,revision:d.revision,state:d.state,rationale:d.rationale,previous_digest:d.previous_digest,updated_at:d.updated_at};
  if(Object.keys(d).length!==Object.keys(ordered).length)throw new Error('Unexpected triage response fields');
  const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(ordered).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))));
  if('sha256:'+Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('')!==next.triage_digest)throw new Error('Triage record digest could not be confirmed');
  return next;
 }

export function FindingTriage({owner,job,result,record,review,onRecorded}:{owner:string,job:string,result:string,record:string,review?:FindingTriageRecordV1,onRecorded:(next:FindingTriageRecordV1)=>void}){
 const [opened,setOpened]=useState(false),[current,setCurrent]=useState<FindingTriageRecordV1>(),[state,setState]=useState<State>('unverified'),[rationale,setRationale]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const known=useRef(review);if(review&&(!known.current||review.document.revision>=known.current.document.revision))known.current=review;
 const alive=useRef(false),generation=useRef(0),pending=useRef<{json:string,key:string}|undefined>(undefined);
 useEffect(()=>{alive.current=true;return()=>{alive.current=false;generation.current++}},[]);
 async function load(){
  const epoch=++generation.current;setOpened(true);setBusy(true);setError('');setCurrent(undefined);
  try{const next=await validateFindingReview(await getFindingTriage({record_id:record},job),owner,job,result,record);if(!alive.current||epoch!==generation.current)return;if(known.current&&next.document.revision<known.current.document.revision)throw new Error('Triage read is older than the displayed owner assessment');known.current=next;setCurrent(next);setState(next.document.revision?next.document.state:'unverified');setRationale(next.document.rationale);pending.current=undefined;onRecorded(next)}
  catch(e){if(alive.current&&epoch===generation.current)setError((e as Error).message)}
  finally{if(alive.current&&epoch===generation.current)setBusy(false)}
 }
 async function save(){
  if(!current)return;
  const epoch=++generation.current;setBusy(true);setError('');
  const body:FindingTriageInputV1={schema_version:'1.0',record_id:record,result_digest:result,expected_revision:current.document.revision,state,rationale:rationale.trim()};
  const json=JSON.stringify(body);if(pending.current?.json!==json)pending.current={json,key:key()};const requestKey=pending.current.key;
  try{const next=await validateFindingReview(await setFindingTriage(job,body,requestKey),owner,job,result,record);if(!alive.current||epoch!==generation.current)return;
   if(next.document.revision!==body.expected_revision+1||next.document.state!==body.state||next.document.rationale!==body.rationale||next.document.previous_digest!==(current.document.revision?current.triage_digest:''))throw new Error('Recorded review does not match the submitted decision');
   if(known.current&&next.document.revision<known.current.document.revision){setCurrent(undefined);setError('This retry returned an earlier recorded decision. Reload the current review to see the latest revision.');pending.current=undefined;return}known.current=next;
   setCurrent(next);setState(next.document.state);setRationale(next.document.rationale);pending.current=undefined;onRecorded(next);
  }catch(e){if(alive.current&&epoch===generation.current)setError((e as Error).message+'. Retry the unchanged decision to recover its recorded response, or reload the current review before editing.')}
  finally{if(alive.current&&epoch===generation.current)setBusy(false)}
 }
 return <div className="finding-triage" aria-busy={busy}>
  <p className="small">{review?(review.document.revision?`Owner assessment: ${review.document.state.replaceAll('_',' ')} · Revision ${review.document.revision}`:'No owner decision recorded'):'Owner review status not loaded'}</p>
  {!opened?<button className="button light" onClick={load}>Review triage</button>:<>
   <h4>Owner review</h4>
   <p className="small muted">Your assessment applies to this finding in this scan. It preserves the original tool claim and T0 evidence. Keep credentials and sensitive source text out of the local rationale.</p>
   {busy&&<p role="status">Reading or recording owner review…</p>}
   {error&&<p className="alert error" role="alert">{error}</p>}
   {current&&<>
    <p role="status">Recorded assessment: {current.document.state.replaceAll('_',' ')} · Revision {current.document.revision}{current.document.revision===0?' · No owner decision recorded':''}</p>
    <label>Review disposition<select value={state} disabled={busy} onChange={e=>setState(e.target.value as State)}><option value="unverified">Unverified — more context needed</option><option value="false_positive">False positive — owner assessment</option><option value="accepted_risk">Accepted risk — owner decision</option><option value="suspected">Reopen as suspected</option></select></label>
    <label>Local review rationale<textarea placeholder="A brief single-line review reason" value={rationale} disabled={busy} maxLength={512} rows={3} onChange={e=>setRationale(e.target.value)}/></label>
    <button className="button" disabled={busy||rationale.trim().length<5||new TextEncoder().encode(rationale.trim()).length>512||/[\u0000-\u001f\u007f-\u009f]/.test(rationale)||current.document.revision>=50} onClick={save}>Record review</button>
    {current.document.revision>=50&&<p>The review history limit has been reached; existing decisions remain available.</p>}
   </>}
   <button className="button light" disabled={busy} onClick={load}>Reload current review</button>
  </>}
 </div>;
}
