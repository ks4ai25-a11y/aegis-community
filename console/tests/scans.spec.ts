// SPDX-License-Identifier: BUSL-1.1
import {test,expect,type Page,type Route} from '@playwright/test';
import {readFileSync} from 'node:fs';
const sample=JSON.parse(readFileSync(new URL('../../contracts/samples/ScannerJobV1.json',import.meta.url),'utf8'));
const repo=JSON.parse(readFileSync(new URL('../../contracts/samples/RepositoryV1.json',import.meta.url),'utf8'));
const evidence=JSON.parse(readFileSync(new URL('../../docs/evidence/scanner-owner-api-acceptance.json',import.meta.url),'utf8')).actual_http_results[3];
const clone=<T>(value:T):T=>structuredClone(value);
function job(id:string,state='queued'){
 const value=clone(sample);value.job_id=id;value.state=state;value.cancel_requested=false;value.input.repository_id=repo.repository_id;value.input.map_digest=repo.map_digest;return value;
}
async function shell(page:Page,scans:(route:Route)=>Promise<void>){
 await page.route('**/api/v1/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  const body=path==='/api/v1/auth/session'?{csrf_token:'synthetic-ui-csrf'}:path==='/api/v1/system/status'?{version:'UI contract fixture',mode:'observe',gateway_healthy:true,requests_retained:0,open_incidents:0,events_dropped_total:0,database_bytes:1024}:path==='/api/v1/repos'?{items:[repo]}:path==='/api/v1/sites/site_demo/events'?{items:[]}:undefined;
  if(body!==undefined){await route.fulfill({json:body});return}
  if(path==='/api/v1/findings'){
   const d=evidence.document;
   await route.fulfill({json:{schema_version:'1.0',owner_id:d.owner_id,job_id:d.job_id,request_digest:d.request_digest,result_digest:evidence.result_digest,snapshot_digest:d.snapshot_digest,status:d.status,has_partial:d.has_partial,has_stale_database:d.has_stale_database,has_tool_error:d.has_tool_error,tool_claims:d.finding_claims,distinct_static_claims:0,matching_static_claims:0,items:[],next_cursor:''}});return;
  }
  if(path.startsWith('/api/v1/scans')){await scans(route);return}
  await route.fulfill({status:404,json:{error:{message:'Not available in UI fixture'}}});
 });
 await page.goto('/');await page.getByRole('button',{name:'Scans',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Queue a read-only scan'})).toBeVisible();
}

test('consent, budgets, exact retry and cancellation preserve uncertainty',async({page})=>{
 const id='01a135d9-bf12-7d90-91af-98af16579a92';let current=job(id),attempts=0;const keys:string[]=[],requests:unknown[]=[];let listed=false;
 await shell(page,async route=>{
  const request=route.request(),path=new URL(request.url()).pathname;
  if(path==='/api/v1/scans'&&request.method()==='POST'){
   attempts++;keys.push(request.headers()['idempotency-key']);requests.push(request.postDataJSON());listed=true;
   if(attempts===1){await route.abort('failed');return}
   await route.fulfill({status:202,json:current});return;
  }
  if(path==='/api/v1/scans'){await route.fulfill({json:{items:listed?[current]:[]}});return}
  if(path.endsWith('/cancel')){expect(request.postDataJSON()).toEqual({});current={...current,state:'cancelled',cancel_requested:true};await route.fulfill({json:{job:current,execution_admission:'unconfirmed'}});return}
  if(path.endsWith('/result'))throw new Error('Queued or cancelled job requested a fabricated result');
  await route.fulfill({json:{job:current,execution_admission:current.state==='queued'?'not_claimed':'unconfirmed'}});
 });
 const queue=page.getByRole('button',{name:'Queue scan',exact:true});await expect(queue).toBeDisabled();
 await page.getByRole('checkbox',{name:/OSV Scanner/}).check();
 await page.getByLabel('Time limit per tool (seconds)').fill('121');await expect(page.getByText('Choose a whole number from 1 to 120.')).toBeVisible();
 await page.getByLabel('Time limit per tool (seconds)').fill('60');
 await page.getByRole('checkbox',{name:/I authorize these read-only tools/}).check();await queue.click();
 await expect(page.getByText(/Scan acknowledgement is unconfirmed/)).toBeVisible();
 await expect(queue).toBeEnabled();await queue.click();
 await expect(page.getByText('No scanner has picked up this job yet.')).toBeVisible();
 expect(keys).toHaveLength(2);expect(keys[0]).toBe(keys[1]);expect(requests[0]).toEqual(requests[1]);
 expect(requests[1]).toMatchObject({tool_ids:['bandit','osv_v2'],tool_timeout_seconds:60,map_digest:repo.map_digest,mode:'repo_offline'});
 await page.getByRole('button',{name:'Cancel selected scan'}).click();
 await expect(page.getByText('Cleanup is unconfirmed.')).toBeVisible();
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toHaveCount(0);
});

test('polling displays terminal tool-error evidence without losing cleanup hold',async({page})=>{
 const result=clone(evidence),id=result.document.job_id;
 const current={...clone(sample),job_id:id,owner_id:result.document.owner_id,request_digest:result.document.request_digest,tool_lock_digest:result.document.tool_lock_digest,input:{...sample.input,repository_id:result.document.repository_id,map_digest:result.document.map_digest,tool_ids:result.document.tools.map((t:{tool_id:string})=>t.tool_id)},state:'queued'};
 let reads=0;
 await shell(page,async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/api/v1/scans'){await route.fulfill({json:{items:[current]}});return}
  if(path.endsWith('/result')){await route.fulfill({json:result});return}
  reads++;current.state=reads>1?result.document.status:'queued';await route.fulfill({json:{job:current,execution_admission:reads>1?'cleanup_required':'not_claimed'}});
 });
 await page.getByRole('button',{name:/View scan/}).click();
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toBeVisible();
 await expect(page.getByText('Tool error: Yes',{exact:true})).toBeVisible();
 await expect(page.getByText('The scanner slot stays held until an independent cleanup check runs.',{exact:false})).toBeVisible();
 await expect(page.getByText('Tool-reported claims')).toBeVisible();
 await expect(page.locator('section').filter({has:page.getByRole('heading',{name:'Owned scan jobs'})}).getByText('tool error',{exact:true})).toBeVisible();
 await page.screenshot({path:test.info().outputPath('triage-phase-scanner-console-desktop.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toBeVisible();
 const overflow=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,elements:[...document.querySelectorAll('*')].filter(e=>e.getBoundingClientRect().right>innerWidth+1).slice(0,12).map(e=>({tag:e.tagName,cls:e.className,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width}))}));await page.screenshot({path:test.info().outputPath('triage-phase-scanner-console-mobile.png'),fullPage:true});expect(overflow.scroll,JSON.stringify(overflow)).toBeLessThanOrEqual(overflow.width);
 await page.screenshot({path:test.info().outputPath('triage-phase-scanner-console-mobile.png'),fullPage:true});
});

test('late response from a previously selected job cannot replace newer evidence',async({page})=>{
 const first=job('01a135d9-bf12-7d90-91af-98af16579a92'),second=job('01a135d9-e9e3-795e-8ab4-e21d7253b4ba');let release:()=>void=()=>{};
 const pending=new Promise<void>(r=>{release=r});let requested=false;
 await shell(page,async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/api/v1/scans'){await route.fulfill({json:{items:[first,second]}});return}
  if(path.endsWith(first.job_id)){requested=true;await pending;await route.fulfill({json:{job:first,execution_admission:'not_claimed'}});return}
  await route.fulfill({json:{job:second,execution_admission:'not_claimed'}});
 });
 await page.getByRole('button',{name:/View scan/}).nth(0).click();await expect.poll(()=>requested).toBeTruthy();
 await page.getByRole('button',{name:/View scan/}).nth(1).click();
 await expect(page.locator('.scan-detail')).toContainText(second.job_id);const completed=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(first.job_id));release();await (await completed).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 await expect(page.locator('.scan-detail')).not.toContainText(first.job_id);
 await expect(page.locator('.scan-detail')).toContainText(second.job_id);
});

test('a result for another job is refused rather than rendered',async({page})=>{
 const result=clone(evidence),current=job(result.document.job_id,result.document.status);
 await shell(page,async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/api/v1/scans'){await route.fulfill({json:{items:[current]}});return}
  if(path.endsWith('/result')){result.document.job_id='01a135d9-bf12-7d90-91af-98af16579a92';await route.fulfill({json:result});return}
  await route.fulfill({json:{job:current,execution_admission:'cleanup_required'}});
 });
 await page.getByRole('button',{name:/View scan/}).click();
 await expect(page.getByRole('alert')).toContainText('Result identity or evidence classification does not match this scan');
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toHaveCount(0);
});

test('a mismatched terminal result received by polling is never displayed',async({page})=>{
 const result=clone(evidence),id=result.document.job_id;
 const current={...clone(sample),job_id:id,owner_id:result.document.owner_id,request_digest:result.document.request_digest,tool_lock_digest:result.document.tool_lock_digest,input:{...sample.input,repository_id:result.document.repository_id,map_digest:result.document.map_digest},state:'queued'};
 let reads=0;
 await shell(page,async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/api/v1/scans'){await route.fulfill({json:{items:[current]}});return}
  if(path.endsWith('/result')){result.document.request_digest='sha256:'+'f'.repeat(64);await route.fulfill({json:result});return}
  reads++;current.state=reads>1?result.document.status:'queued';await route.fulfill({json:{job:current,execution_admission:reads>1?'cleanup_required':'not_claimed'}});
 });
 await page.getByRole('button',{name:/View scan/}).click();
 await expect(page.getByRole('alert')).toContainText('Result identity or evidence classification does not match this scan');
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toHaveCount(0);
 await expect(page.locator('.scan-detail')).toContainText('Held for cleanup check');
});

test('a release made after the scan finished shows without a manual refresh',async({page})=>{
 const result=clone(evidence),id=result.document.job_id;
 const current={...clone(sample),job_id:id,owner_id:result.document.owner_id,request_digest:result.document.request_digest,tool_lock_digest:result.document.tool_lock_digest,input:{...sample.input,repository_id:result.document.repository_id,map_digest:result.document.map_digest},state:result.document.status};
 let admission='cleanup_required';
 await shell(page,async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/api/v1/scans'){await route.fulfill({json:{items:[current]}});return}
  if(path.endsWith('/result')){await route.fulfill({json:result});return}
  await route.fulfill({json:{job:current,execution_admission:admission}});
 });
 await page.getByRole('button',{name:/View scan/}).click();
 await expect(page.locator('.scan-detail')).toContainText('Held for cleanup check');
 await expect(page.locator('.scan-result')).toContainText('A result can never release the scanner slot on its own.');
 admission='cleanup_confirmed';
 await expect(page.locator('.scan-detail')).toContainText('Released',{timeout:25000});
 await expect(page.locator('.scan-result')).toContainText('It has since been confirmed and the scanner slot released.');
 await expect(page.locator('.scan-detail')).not.toContainText('Held for cleanup check');
});
