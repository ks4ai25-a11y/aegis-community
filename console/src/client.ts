let csrf='';export function setCSRF(v:string){csrf=v}
export async function api<T=any>(path:string,body?:unknown,headers:Record<string,string>={}):Promise<T>{const r=await fetch('/api/v1'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...headers},body:body===undefined?undefined:JSON.stringify(body)});let data:any;try{data=await r.json()}catch{data={}}if(r.status===401&&!path.startsWith('/auth/'))window.dispatchEvent(new Event('aegis-session-expired'));if(!r.ok)throw new Error(data.error?.message||`Request failed (HTTP ${r.status})`);return data}
export function key(){return crypto.randomUUID()}
export function short(v?:string){return v?v.replace('sha256:','').slice(0,12):'Unavailable'}
