// SPDX-License-Identifier: BUSL-1.1
import {test,expect,type Page,type Route} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const recorded=JSON.parse(readFileSync(new URL('../../docs/evidence/finding-triage-acceptance.json',import.meta.url),'utf8'));
const result=recorded.actual_parser_result,d=result.document,base=recorded.actual_parser_page,entry=base.items[0];
const sample=JSON.parse(readFileSync(new URL('../../contracts/samples/ScannerJobV1.json',import.meta.url),'utf8'));
const job={...sample,owner_id:d.owner_id,job_id:d.job_id,request_digest:d.request_digest,tool_lock_digest:d.tool_lock_digest,state:d.status,input:{...sample.input,app_id:d.app_id,repository_id:d.repository_id,map_digest:d.map_digest,tool_ids:d.tools.map((t:any)=>t.tool_id)}};
function record(revision=0,state='suspected',rationale=''){
 const document={schema_version:'1.0',owner_id:d.owner_id,job_id:d.job_id,record_id:entry.record_id,result_digest:result.result_digest,revision,state,rationale,previous_digest:'',updated_at:revision?'2026-10-14T10:00:00Z':''};
 const json=JSON.stringify(document).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
 return {triage_digest:'sha256:'+createHash('sha256').update(json).digest('hex'),document};
}
async function open(page:Page,triage:(r:Route)=>Promise<void>,known?:any){
 await page.route('**/api/v1/**',async route=>{
  const u=new URL(route.request().url()),path=u.pathname;
  if(path.endsWith('/finding-triage')){await triage(route);return}
  const body=path==='/api/v1/auth/session'?{csrf_token:'synthetic-ui-csrf'}:path==='/api/v1/system/status'?{mode:'observe',gateway_healthy:true,version:'Synthetic triage fixture',database_bytes:1024}:path==='/api/v1/repos'?{items:[]}:path==='/api/v1/sites/site_demo/events'?{items:[]}:path==='/api/v1/scans'?{items:[job]}:path.endsWith('/result')?result:path==='/api/v1/findings'?{...base,matching_static_claims:u.searchParams.get('severity')==='low'?0:1,items:u.searchParams.get('severity')==='low'?[]:[{...entry,owner_review:known||record()}],next_cursor:''}:{job,execution_admission:'cleanup_required'};
  await route.fulfill({json:body});
 });
 await page.goto('/');await page.getByRole('button',{name:'Scans',exact:true}).click();await page.getByRole('button',{name:/View scan/}).click();await page.getByRole('button',{name:'Review triage'}).click();
}
test('owner review remains separate from T0 evidence and safely renders rationale',async({page})=>{
 let current=record(),posted:any;
 await open(page,async route=>{
  if(route.request().method()==='POST'){posted=route.request().postDataJSON();expect(route.request().headers()['x-csrf-token']).toBe('synthetic-ui-csrf');expect(route.request().headers()['idempotency-key']).toBeTruthy();current=record(1,posted.state,posted.rationale)}
  await route.fulfill({json:current});
 });
 await expect(page.locator('.finding-triage')).toContainText('No owner decision recorded');
 await page.getByLabel('Review disposition').selectOption('false_positive');
 const rationale='<img src=x onerror="window.injected=true"> & synthetic fixture';
 await page.getByLabel('Local review rationale').fill(rationale);await page.getByRole('button',{name:'Record review'}).click();
 await expect(page.locator('.finding-triage')).toContainText('Recorded assessment: false positive · Revision 1');
 expect(posted).toMatchObject({schema_version:'1.0',record_id:entry.record_id,result_digest:result.result_digest,expected_revision:0,state:'false_positive',rationale});
 await expect(page.locator('.finding-record')).toContainText('Evidence: T0 · Tool claim: suspected · Confidence: low');
 await expect(page.locator('.finding-triage img')).toHaveCount(0);
 await page.getByRole('button',{name:'Reload current review'}).click();await expect(page.getByLabel('Local review rationale')).toHaveValue(rationale);
 await page.locator('.finding-record').screenshot({path:test.info().outputPath('finding-triage-desktop.png')});
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
 await page.locator('.finding-record').screenshot({path:test.info().outputPath('finding-triage-mobile.png')});
});
test('lost mutation response retries with the same key and revision',async({page})=>{
 const posts:{body:string,key:string}[]=[];
 await open(page,async route=>{
  if(route.request().method()==='GET'){await route.fulfill({json:record()});return}
  posts.push({body:route.request().postData()!,key:route.request().headers()['idempotency-key']});
  if(posts.length===1){await route.abort('failed');return}
  const body=route.request().postDataJSON();await route.fulfill({json:record(1,body.state,body.rationale)});
 });
 await page.getByLabel('Local review rationale').fill('Needs application authorization context');await page.getByRole('button',{name:'Record review'}).click();
 await expect(page.getByRole('alert')).toContainText('Retry the unchanged decision');await page.getByRole('button',{name:'Record review'}).click();
 await expect(page.locator('.finding-triage')).toContainText('Revision 1');expect(posts).toHaveLength(2);expect(posts[1]).toEqual(posts[0]);
});
for(const mismatch of ['owner','result','digest'])test('refuses mismatched triage '+mismatch,async({page})=>{
 await open(page,async route=>{const next=record();if(mismatch==='owner')next.document.owner_id='other-owner';else if(mismatch==='result')next.document.result_digest='sha256:'+'f'.repeat(64);else next.triage_digest='sha256:'+'f'.repeat(64);await route.fulfill({json:next})});
 await expect(page.getByRole('alert')).toContainText(mismatch==='digest'?'digest could not be confirmed':'does not match');await expect(page.getByRole('button',{name:'Record review'})).toHaveCount(0);
});
test('a late review read cannot reappear after its finding is filtered out',async({page})=>{
 let release:()=>void=()=>{},started=false;const pending=new Promise<void>(r=>{release=r});
 await open(page,async route=>{started=true;await pending;await route.fulfill({json:record()})});
 await expect.poll(()=>started).toBeTruthy();await page.getByLabel('Claimed severity').selectOption('low');await expect(page.locator('.finding-record')).toHaveCount(0);
 const response=page.waitForResponse(r=>r.url().includes('/finding-triage'));release();await(await response).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 await expect(page.locator('.finding-triage')).toHaveCount(0);
});

test('actual Go owner response validates HTML escaping and the immutable record digest',async({page})=>{
 await open(page,async route=>{await route.fulfill({json:recorded.recorded_triage})});
 await expect(page.locator('.finding-triage')).toContainText('Recorded assessment: false positive · Revision 1');
 await expect(page.getByLabel('Local review rationale')).toHaveValue(recorded.recorded_triage.document.rationale);
 await expect(page.locator('.finding-record')).toContainText('Evidence: T0 · Tool claim: suspected');
});

test('an older review read cannot replace the summary already shown',async({page})=>{
 await open(page,async route=>{await route.fulfill({json:record()})},recorded.recorded_triage);
 await expect(page.getByRole('alert')).toContainText('older than the displayed owner assessment');
 await expect(page.locator('.finding-triage')).toContainText('Owner assessment: false positive · Revision 1');
 await expect(page.getByRole('button',{name:'Record review'})).toHaveCount(0);
});
