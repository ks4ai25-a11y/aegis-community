import type {FindingTriageInputV1,FindingTriageRecordV1} from './generated/contracts';
export type State=FindingTriageInputV1['state'];
const states:State[]=['suspected','unverified','false_positive','accepted_risk'];
export async function validateFindingReview(next:FindingTriageRecordV1,owner:string,job:string,result:string,record:string){
  const d=next.document;
  if(!d||d.schema_version!=='1.0'||d.owner_id!==owner||d.job_id!==job||d.result_digest!==result||d.record_id!==record||!Number.isInteger(d.revision)||d.revision<0||d.revision>50||!states.includes(d.state)||typeof d.rationale!=='string'||new TextEncoder().encode(d.rationale).length>512||/[\u0000-\u001f\u007f-\u009f]/.test(d.rationale)||typeof d.updated_at!=='string'||!/^sha256:[0-9a-f]{64}$/.test(next.triage_digest)||!(d.previous_digest===''||/^sha256:[0-9a-f]{64}$/.test(d.previous_digest))||(d.revision===0?(d.state!=='suspected'||d.rationale!==''||d.updated_at!==''||d.previous_digest!==''):new TextEncoder().encode(d.rationale.trim()).length<5||!Number.isFinite(Date.parse(d.updated_at))||d.revision===1&&d.previous_digest!==''||d.revision>1&&d.previous_digest===''))throw new Error('Triage response does not match the selected finding');
  const ordered={schema_version:d.schema_version,owner_id:d.owner_id,job_id:d.job_id,record_id:d.record_id,result_digest:d.result_digest,revision:d.revision,state:d.state,rationale:d.rationale,previous_digest:d.previous_digest,updated_at:d.updated_at};
  if(Object.keys(d).length!==Object.keys(ordered).length)throw new Error('Unexpected triage response fields');
  const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(ordered).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))));
  if('sha256:'+Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('')!==next.triage_digest)throw new Error('Triage record digest could not be confirmed');
  return next;
 }

