import {test,expect,type Page,type Route} from '@playwright/test';
import {readFileSync} from 'node:fs';
const actual=JSON.parse(readFileSync(new URL('../../docs/evidence/finding-catalogue-acceptance.json',import.meta.url),'utf8')).actual_http;
const base=actual.default,d=base.result.document;
const sample=JSON.parse(readFileSync(new URL('../../contracts/samples/ScannerJobV1.json',import.meta.url),'utf8'));
const repo={schema_version:'1.0',repository_id:d.repository_id,owner_id:d.owner_id,app_id:d.app_id,asset_id:'fixture',map_digest:d.map_digest};
const job={...sample,job_id:d.job_id,owner_id:d.owner_id,request_digest:d.request_digest,state:d.status,tool_lock_digest:d.tool_lock_digest,input:{...sample.input,app_id:d.app_id,repository_id:d.repository_id,map_digest:d.map_digest,tool_ids:d.tools.map((t:any)=>t.tool_id)}};
const copy=(v:any)=>JSON.parse(JSON.stringify(v));
test.use({timezoneId:'UTC'});
async function open(page:Page,catalogue:(r:Route,u:URL)=>Promise<void>){
 await page.route('**/api/v1/**',async route=>{
  const u=new URL(route.request().url()),path=u.pathname;
  if(path==='/api/v1/findings/catalogue'){await catalogue(route,u);return}
  const body=path==='/api/v1/auth/session'?{owner_id:d.owner_id,csrf_token:'synthetic-catalogue-csrf'}:path==='/api/v1/system/status'?{mode:'observe',gateway_healthy:true,version:'Catalogue fixture',database_bytes:1024}:path==='/api/v1/sites/site_demo/events'?{items:[]}:path==='/api/v1/repos'?{items:[repo]}:path==='/api/v1/scans'?{items:[job]}:path.endsWith('/result')?base.result:path==='/api/v1/findings'?base.findings:{job,execution_admission:'cleanup_required'};
  await route.fulfill({json:body});
 });
 await page.goto('/');await page.getByRole('button',{name:'Findings',exact:true}).click();
}
test('actual owner catalogue preserves provenance, reviews and layout',async({page},info)=>{
 await open(page,async r=>{await r.fulfill({json:base})});await expect(page.locator('.finding-record')).toHaveCount(4);
 await expect(page.locator('.catalogue-results')).toContainText('5 tool claims · 4 distinct static records');await expect(page.locator('.catalogue-results')).toContainText('Stale database: yes');
 await expect(page.locator('.finding-record').first()).toContainText('Evidence: T0 · Tool claim: suspected');await expect(page.getByRole('button',{name:'Next retained observations'})).toBeDisabled();
 await page.locator('.catalogue-results').screenshot({path:info.outputPath('catalogue-desktop.png')});await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);await page.screenshot({path:info.outputPath('catalogue-mobile.png'),fullPage:true});await page.locator('.card').first().screenshot({path:info.outputPath('catalogue-mobile-filters.png')});await page.locator('.finding-record').first().screenshot({path:info.outputPath('catalogue-mobile-finding.png')});
});
test('pages exact actual findings and can return to the first page',async({page})=>{
 await open(page,async(r,u)=>{await r.fulfill({json:u.searchParams.get('limit')==='2'?(u.searchParams.get('cursor')?actual.last:actual.first):base})});
 await expect(page.locator('.finding-record')).toHaveCount(4);await page.getByLabel('Records per catalogue page').selectOption('2');await expect(page.locator('.finding-record')).toHaveCount(2);
 const first=await page.locator('.finding-record').first().textContent();await page.getByRole('button',{name:'Next retained observations'}).click();await expect(page.locator('.finding-record')).toHaveCount(2);expect(await page.locator('.finding-record').first().textContent()).not.toBe(first);await expect(page.getByRole('button',{name:'Next retained observations'})).toBeDisabled();
 await page.getByRole('button',{name:'Refresh catalogue from first page'}).click();await expect(page.locator('.finding-record').first()).toHaveText(first!);
});
test('filtering an empty scan page retains coverage and never implies an empty corpus',async({page})=>{
 await open(page,async(r,u)=>{await r.fulfill({json:u.searchParams.get('severity')==='critical'?actual.filtered:base})});await expect(page.locator('.finding-record')).toHaveCount(4);await page.getByLabel('Catalogue severity').selectOption('critical');await expect(page.locator('.finding-record')).toHaveCount(0);await expect(page.locator('.catalogue-results')).toContainText('Other retained scans may contain matching observations');await expect(page.locator('.catalogue-results')).toContainText('Stale database: yes');
});
test('empty result roster keeps unavailable jobs separate from clean evidence',async({page})=>{
 const value={...actual.empty,owner_id:d.owner_id,jobs_without_result:7};await open(page,async r=>{await r.fulfill({json:value})});await expect(page.locator('.catalogue-results')).toContainText('7 jobs without an immutable result');await expect(page.locator('.catalogue-results')).toContainText('does not establish zero findings');await expect(page.locator('.finding-record')).toHaveCount(0);
});
test('repository and local time filters become exact API query fields',async({page})=>{
 const requests:URL[]=[];await open(page,async(r,u)=>{requests.push(u);await r.fulfill({json:base})});await expect(page.locator('.finding-record')).toHaveCount(4);
 await page.getByLabel('Catalogue repository').selectOption(d.repository_id);await expect.poll(()=>requests.at(-1)?.searchParams.get('repository_id')).toBe(d.repository_id);
 await page.getByLabel('Results from (local time)').fill('2026-01-01T10:00');await expect.poll(()=>requests.at(-1)?.searchParams.get('since')).toBe('2026-01-01T10:00:00.000Z');
 await page.getByLabel('Results before (local time)').fill('2027-01-01T11:00');await expect.poll(()=>requests.at(-1)?.searchParams.get('until')).toBe('2027-01-01T11:00:00.000Z');
});
test('opens the exact selected scan result from catalogue provenance',async({page})=>{
 await open(page,async r=>{await r.fulfill({json:base})});await page.getByRole('button',{name:'Open this scan result'}).click();await expect(page.getByRole('heading',{name:'Static finding details'})).toBeVisible();await expect(page.locator('.scan-detail')).toContainText(d.job_id);
});
for(const fault of ['owner','scope','index','result-owner','result-digest','tier','snapshot','receipt','review','missing-result','missing-continuation','excess-items'])test('refuses mismatched catalogue evidence: '+fault,async({page})=>{
 const value=copy(base);
 if(fault==='owner')value.owner_id='another-owner';
 if(fault==='scope')value.scope='confirmed_vulnerabilities';
 if(fault==='index')value.result_index=99;
 if(fault==='result-owner')value.result.document.owner_id='another-owner';
 if(fault==='result-digest')value.result.result_digest='sha256:'+'f'.repeat(64);
 if(fault==='tier')value.findings.items[0].finding.evidence_tier='T3';
 if(fault==='snapshot')value.findings.snapshot_digest='sha256:'+'f'.repeat(64);
 if(fault==='receipt')value.findings.items[0].receipt_digests=['sha256:'+'f'.repeat(64)];
 if(fault==='review')value.findings.items[0].owner_review.document.owner_id='another-owner';
 if(fault==='missing-result')delete value.result;
 if(fault==='missing-continuation')value.findings.next_cursor='missing-outer-continuation';
 if(fault==='excess-items'){value.findings.items=Array(21).fill(value.findings.items[0]);value.findings.matching_static_claims=21;value.findings.distinct_static_claims=21}
 await open(page,async r=>{await r.fulfill({json:value})});await expect(page.getByRole('alert')).toContainText('Catalogue evidence unavailable');await expect(page.locator('.finding-record')).toHaveCount(0);
});
test('changed result set cannot be silently continued and refresh recovers',async({page})=>{
 await open(page,async(r,u)=>{if(u.searchParams.get('cursor'))await r.fulfill({status:409,json:{error:{code:'CATALOGUE_CHANGED',message:'Retained results changed; restart from the first catalogue page'}}});else await r.fulfill({json:u.searchParams.get('limit')==='2'?actual.first:base})});
 await page.getByLabel('Records per catalogue page').selectOption('2');await expect(page.locator('.finding-record')).toHaveCount(2);await page.getByRole('button',{name:'Next retained observations'}).click();await expect(page.getByRole('alert')).toContainText('Retained results changed');await expect(page.locator('.finding-record')).toHaveCount(0);
 await page.getByRole('button',{name:'Refresh catalogue from first page'}).click();await expect(page.locator('.finding-record')).toHaveCount(2);
});
test('late filtered catalogue cannot overwrite newer evidence',async({page})=>{
 let release:()=>void=()=>{},pendingStarted=false;const pending=new Promise<void>(r=>{release=r});
 await open(page,async(r,u)=>{if(u.searchParams.get('severity')==='critical'){pendingStarted=true;await pending;await r.fulfill({json:actual.filtered})}else await r.fulfill({json:base})});
 await expect(page.locator('.finding-record')).toHaveCount(4);await page.getByLabel('Catalogue severity').selectOption('critical');await expect.poll(()=>pendingStarted).toBeTruthy();await page.getByLabel('Catalogue severity').selectOption('');await expect(page.locator('.finding-record')).toHaveCount(4);
 const response=page.waitForResponse(r=>r.url().includes('severity=critical'));release();await(await response).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await expect(page.locator('.finding-record')).toHaveCount(4);
});
