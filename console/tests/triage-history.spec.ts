// SPDX-License-Identifier: BUSL-1.1
import {test,expect,type Page,type Route} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const actual=JSON.parse(readFileSync(new URL('../../docs/evidence/finding-history-acceptance.json',import.meta.url),'utf8'));
const history=actual.actual_http_history,empty=actual.actual_http_empty_history,result=actual.actual_parser_result,d=result.document,base=actual.actual_parser_page;
const entry=base.items.find((item:any)=>item.record_id===history.document.record_id);
const sample=JSON.parse(readFileSync(new URL('../../contracts/samples/ScannerJobV1.json',import.meta.url),'utf8'));
const job={...sample,owner_id:d.owner_id,job_id:d.job_id,request_digest:d.request_digest,tool_lock_digest:d.tool_lock_digest,state:d.status,input:{...sample.input,app_id:d.app_id,repository_id:d.repository_id,map_digest:d.map_digest,tool_ids:d.tools.map((t:any)=>t.tool_id)}};
const clone=(value:any)=>JSON.parse(JSON.stringify(value));
function hash(value:any){return 'sha256:'+createHash('sha256').update(JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))).digest('hex')}
async function open(page:Page,handler:(route:Route)=>Promise<void>,known=history.document.items.at(-1)){
 await page.route('**/api/v1/**',async route=>{
  const u=new URL(route.request().url()),path=u.pathname;
  if(path.endsWith('/finding-triage-history')){expect(u.searchParams.get('record_id')).toBe(entry.record_id);expect(u.searchParams.get('result_digest')).toBe(result.result_digest);await handler(route);return}
  const body=path==='/api/v1/auth/session'?{csrf_token:'synthetic-history-csrf'}:path==='/api/v1/system/status'?{mode:'observe',gateway_healthy:true,version:'Synthetic history fixture',database_bytes:1024}:path==='/api/v1/repos'?{items:[]}:path==='/api/v1/sites/site_demo/events'?{items:[]}:path==='/api/v1/scans'?{items:[job]}:path.endsWith('/result')?result:path==='/api/v1/findings'?{...base,matching_static_claims:u.searchParams.get('severity')==='low'?0:1,items:u.searchParams.get('severity')==='low'?[]:[{...entry,owner_review:known}],next_cursor:''}:{job,execution_admission:'cleanup_required'};
  await route.fulfill({json:body});
 });
 await page.goto('/');await page.getByRole('button',{name:'Scans',exact:true}).click();await page.getByRole('button',{name:/View scan/}).click();await page.getByRole('button',{name:'View review history',exact:true}).click();
}
test('renders actual complete Go history and exports exact verified JSON',async({page},info)=>{
 await open(page,async route=>{await route.fulfill({json:history})});
 const view=page.getByRole('region',{name:'Owner review history'});
 await expect(view).toContainText('Recorded review history · 2 decisions');await expect(view.locator('li')).toHaveCount(2);
 await expect(view).toContainText(history.document.items[0].document.rationale);await expect(view).toContainText('accepted risk');
 await expect(page.locator('.finding-record')).toContainText('Evidence: T0 · Tool claim: suspected');
 const downloaded=page.waitForEvent('download');await view.getByRole('button',{name:'Export review history JSON'}).click();const download=await downloaded;
 expect(download.suggestedFilename()).toMatch(/^aegis-review-history-[0-9a-f]{12}-r2\.json$/);
 const path=await download.path();expect(JSON.parse(readFileSync(path!,'utf8'))).toEqual(history);
 await view.screenshot({path:info.outputPath('review-history-desktop.png')});
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);await view.screenshot({path:info.outputPath('review-history-mobile.png')});
});
test('empty history explicitly shows no decision without inventing an initial entry',async({page})=>{
 const baseline={triage_digest:empty.document.head_digest,document:{schema_version:'1.0',owner_id:d.owner_id,job_id:d.job_id,record_id:entry.record_id,result_digest:result.result_digest,revision:0,state:'suspected',rationale:'',previous_digest:'',updated_at:''}};
 await open(page,async route=>{await route.fulfill({json:empty})},baseline);await expect(page.locator('.review-history')).toContainText('No owner decision has been recorded');await expect(page.locator('.review-history li')).toHaveCount(0);
});
for(const fault of ['owner','result','missing','reordered','link','record-digest','envelope-digest','incomplete','extra','oversized'])test('refuses unconfirmed history: '+fault,async({page})=>{
 const value=clone(history),doc=value.document;
 if(fault==='owner')doc.owner_id='another-owner';
 if(fault==='result')doc.result_digest='sha256:'+'f'.repeat(64);
 if(fault==='missing')doc.items.shift();
 if(fault==='reordered')doc.items.reverse();
 if(fault==='link'){doc.items[1].document.previous_digest='sha256:'+'0'.repeat(64);doc.items[1].triage_digest=hash(doc.items[1].document);doc.head_digest=doc.items[1].triage_digest;value.history_digest=hash(doc)}
 if(fault==='record-digest')doc.items[0].triage_digest='sha256:'+'0'.repeat(64);
 if(fault==='envelope-digest')value.history_digest='sha256:'+'0'.repeat(64);
 if(fault==='incomplete')doc.complete=false;
 if(fault==='extra')doc.unexpected=true;
 if(fault==='oversized'){doc.revision_count=51;doc.items=Array(51).fill(doc.items[0])}
 await open(page,async route=>{await route.fulfill({json:value})});await expect(page.getByRole('alert')).toContainText('Review history unavailable');await expect(page.getByRole('button',{name:'Export review history JSON'})).toHaveCount(0);await expect(page.locator('.review-history li')).toHaveCount(0);
});
test('refuses a valid older chain when a later review is already displayed',async({page})=>{
 const older=clone(history);older.document.items.pop();older.document.revision_count=1;older.document.head_digest=older.document.items[0].triage_digest;older.history_digest=hash(older.document);
 await open(page,async route=>{await route.fulfill({json:older})});await expect(page.getByRole('alert')).toContainText('older than or conflicts');await expect(page.getByRole('button',{name:'Export review history JSON'})).toHaveCount(0);
});
test('late history cannot return after the finding is filtered out',async({page})=>{
 let release:()=>void=()=>{},started=false;const pending=new Promise<void>(r=>{release=r});
 await open(page,async route=>{started=true;await pending;await route.fulfill({json:history})});await expect.poll(()=>started).toBeTruthy();
 await page.getByLabel('Claimed severity').selectOption('low');await expect(page.locator('.finding-record')).toHaveCount(0);
 const response=page.waitForResponse(r=>r.url().includes('/finding-triage-history'));release();await(await response).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 await expect(page.locator('.review-history')).toHaveCount(0);
});

test('valid UTF-8 byte-bounded rationale is preserved even below five characters',async({page})=>{
 const value=clone(history);value.document.items[1].document.rationale='暂缓处置';value.document.items[1].triage_digest=hash(value.document.items[1].document);value.document.head_digest=value.document.items[1].triage_digest;value.history_digest=hash(value.document);
 await open(page,async route=>{await route.fulfill({json:value})},value.document.items[1]);await expect(page.locator('.review-history')).toContainText('暂缓处置');await expect(page.getByRole('button',{name:'Export review history JSON'})).toBeEnabled();
});
