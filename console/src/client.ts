// SPDX-License-Identifier: BUSL-1.1
let csrf='';export function setCSRF(v:string){csrf=v}
export async function api<T=any>(path:string,body?:unknown,headers:Record<string,string>={}):Promise<T>{const r=await fetch('/api/v1'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...headers},body:body===undefined?undefined:JSON.stringify(body)});let data:any;try{data=await r.json()}catch{data={}}if(r.status===401&&!path.startsWith('/auth/'))window.dispatchEvent(new Event('aegis-session-expired'));if(!r.ok)throw new Error(data.error?.message||`Request failed (HTTP ${r.status})`);return data}
export function key(){return crypto.randomUUID()}
export function short(v?:string){return v?v.replace('sha256:','').slice(0,12):'Unavailable'}

// Readable labels for internal status codes; unknown values are shown as words.
const labels:Record<string,string>={repo_offline:'Offline, read-only',success:'Passed',failure:'Failed',queued:'Queued',running:'Running',completed:'Completed',cancelled:'Cancelled',revoked:'Revoked',active:'Active',ACTIVE:'Active',SUPERSEDED:'Superseded',PENDING_APPROVAL:'Pending approval',FAILED:'Failed',LEVEL_1_CONTROL_TEST:'Level 1 · control test in fixture',completed_stale_db:'Completed (advisory database stale)',completed_partial:'Completed (partial)',tool_error:'Tool error',timeout:'Timed out',draft:'Draft',expired:'Expired',exhausted:'Exhausted'};
export function human(v?:string){if(!v)return '—';if(labels[v])return labels[v];const t=v.replaceAll('_',' ').toLowerCase();return t.charAt(0).toUpperCase()+t.slice(1)}
