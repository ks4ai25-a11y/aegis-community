import {test,expect,type Page,type Route} from '@playwright/test';
import {readFileSync} from 'node:fs';
const recorded=JSON.parse(readFileSync(new URL('../../docs/evidence/finding-projection-acceptance.json',import.meta.url),'utf8'));
const result=recorded.actual_parser_result,d=result.document;
const entries=recorded.actual_parser_pages.flatMap((p:{items:unknown[]})=>p.items);
const base=recorded.actual_parser_pages[0];
const sample=JSON.parse(readFileSync(new URL('../../contracts/samples/ScannerJobV1.json',import.meta.url),'utf8'));
const current={...sample,owner_id:d.owner_id,job_id:d.job_id,request_digest:d.request_digest,tool_lock_digest:d.tool_lock_digest,state:d.status,input:{...sample.input,app_id:d.app_id,repository_id:d.repository_id,map_digest:d.map_digest,tool_ids:d.tools.map((t:{tool_id:string})=>t.tool_id)}};
function fixture(query:URLSearchParams){
 const filtered=entries.filter((e:any)=>(!query.get('category')||e.finding.category===query.get('category'))&&(!query.get('severity')||e.finding.severity===query.get('severity')));
 const offset=query.get('cursor')?2:0;
 return {...base,matching_static_claims:filtered.length,items:filtered.slice(offset,offset+2),next_cursor:offset+2<filtered.length?'fixture-next-page':''};
}
async function open(page:Page,findings:(route:Route)=>Promise<void>){
 await page.route('**/api/v1/**',async route=>{
  const request=new URL(route.request().url()),path=request.pathname;
  if(path==='/api/v1/findings'){await findings(route);return}
  const body=path==='/api/v1/auth/session'?{csrf_token:'synthetic-ui-csrf'}:path==='/api/v1/system/status'?{mode:'observe',gateway_healthy:true,version:'Synthetic finding fixture',database_bytes:1024}:path==='/api/v1/repos'?{items:[]}:path==='/api/v1/sites/site_demo/events'?{items:[]}:path==='/api/v1/scans'?{items:[current]}:path.endsWith('/result')?result:{job:current,execution_admission:'cleanup_required'};
  await route.fulfill({json:body});
 });
 await page.goto('/');await page.getByRole('button',{name:'Scans',exact:true}).click();await page.getByRole('button',{name:/View scan/}).click();
 await expect(page.getByRole('heading',{name:'Static finding details'})).toBeVisible();
}
test('deduplicated dependency retains conflicting severity, exact versions and both receipts',async({page})=>{
 await open(page,async route=>{await route.fulfill({json:fixture(new URL(route.request().url()).searchParams)})});
 const merged=page.locator('.finding-record').filter({hasText:'known vulnerable dependency'});
 await expect(merged).toHaveCount(1);await expect(merged).toContainText('osv_v2');await expect(merged).toContainText('trivy');await expect(merged).toContainText('informational');await expect(merged).toContainText('high');
 await expect(merged).toContainText('Tool claim: suspected');await expect(merged).toContainText('Confidence: low');
 await merged.getByText('Source and receipt identities').click();
 await expect(merged).toContainText('2.7.0');await expect(merged).toContainText('0.75.0');
 const dep=entries.find((e:any)=>e.finding.category==='known_vulnerable_dependency');
 for(const ref of dep.receipt_digests)await expect(merged).toContainText(ref);
 await expect(page.locator('.finding-details')).toContainText('5 tool claims · 4 distinct static records');
 await page.locator('.finding-details').screenshot({path:'../docs/evidence/triage-phase-finding-details-desktop.png'});
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
 await page.locator('.finding-details').screenshot({path:'../docs/evidence/triage-phase-finding-details-mobile.png'});
 await page.getByRole('button',{name:'Next findings'}).click();await expect(page.locator('.finding-pagination')).toContainText('Page 2');
 await expect(page.getByRole('button',{name:'Next findings'})).toBeDisabled();
 await page.getByRole('button',{name:'Back to first page'}).click();await expect(page.locator('.finding-pagination')).toContainText('Page 1');
 await page.getByLabel('Finding category').selectOption('known_vulnerable_dependency');await expect(page.locator('.finding-record')).toHaveCount(1);
});
test('late filter response cannot erase newer findings',async({page})=>{
 let release:()=>void=()=>{},started=false;const pending=new Promise<void>(r=>{release=r});
 await open(page,async route=>{const q=new URL(route.request().url()).searchParams;if(q.get('severity')==='low'){started=true;await pending}await route.fulfill({json:fixture(q)})});
 await page.getByLabel('Claimed severity').selectOption('low');await expect.poll(()=>started).toBeTruthy();
 await page.getByLabel('Claimed severity').selectOption('high');await expect(page.locator('.finding-record')).toHaveCount(2);
 const completed=page.waitForResponse(r=>new URL(r.url()).searchParams.get('severity')==='low');release();await(await completed).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 await expect(page.locator('.finding-record')).toHaveCount(2);await expect(page.locator('.finding-details')).not.toContainText('No static records match');
});
test('mismatched page and hostile presentation cannot become trusted findings',async({page})=>{
 let wrong=false;
 await open(page,async route=>{
  const next=structuredClone(fixture(new URL(route.request().url()).searchParams));
  if(wrong)next.result_digest='sha256:'+'e'.repeat(64);else next.items[0].finding.summary='<img src=x onerror="window.injected=true">';
  await route.fulfill({json:next});
 });
 await expect(page.locator('.finding-details')).toContainText('<img src=x');await expect(page.locator('.finding-details img')).toHaveCount(0);
 wrong=true;await page.getByLabel('Claimed severity').selectOption('high');
 await expect(page.getByRole('alert')).toContainText('Finding page does not match the selected immutable result');
 await expect(page.locator('.finding-record')).toHaveCount(0);
 wrong=false;await page.getByRole('button',{name:'Retry from first page'}).click();await expect(page.locator('.finding-record')).toHaveCount(2);
});
