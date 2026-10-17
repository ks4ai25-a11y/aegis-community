import {test,type Page} from '@playwright/test';
import {readFileSync} from 'node:fs';

const out=process.env.AEGIS_PREVIEW_SHOTS||'/tmp/aegis-preview';
const scheme=(process.env.AEGIS_PREVIEW_SCHEME||'dark') as 'dark'|'light';
const actual=JSON.parse(readFileSync(new URL('../../docs/evidence/finding-catalogue-acceptance.json',import.meta.url),'utf8')).actual_http.default;
const d=actual.result.document;
const digest=(c:string)=>'sha256:'+c.repeat(64);
const now=Date.parse('2026-10-17T09:30:00Z');
const at=(s:number)=>new Date(now-s*1000).toISOString();
const routes=['/api/accounts/{id}','/catalog','/login','/api/orders/{id}','/products','/admin','/api/users/{id}','/healthz'];
const events=Array.from({length:40},(_,i)=>{const blocked=i%7===3,waf=i%5===2;return {event:{event_id:'01a1'+String(i).padStart(4,'0'),observed_at:at(i*37),method:['GET','POST','GET','PUT'][i%4],route_template:routes[i%routes.length],request_id:'req'+i,source:waf?'coraza':'caddy-access',decision:blocked?'blocked_waf':waf?'observed':'allowed',rule_ids:waf||blocked?['942100']:[],http_status:blocked?403:200,gateway_revision:digest('a')}}});
const incidents=[
 {incident_id:'inc-001',summary:'SQL injection pattern on /api/{segment}',detector_id:'CRS-942',opened_at:at(600),synthetic:false,state:'open',severity:'high'},
 {incident_id:'inc-002',summary:'Login failure burst from one client',detector_id:'DET-02',opened_at:at(3600),synthetic:false,state:'open',severity:'medium'},
 {incident_id:'inc-003',summary:'Origin of site_shop is reachable without the gateway',detector_id:'DET-08',opened_at:at(7200),synthetic:false,state:'open',severity:'medium'},
 {incident_id:'inc-004',summary:'Synthetic demo SQL injection pattern',detector_id:'CRS-942',opened_at:at(86400),synthetic:true,state:'open',severity:'low'}];
const policy={schema_version:'1.1',parent_revision:'',requested_mode:'observe',crs:{blocking_paranoia:1,executing_paranoia:1,inbound_anomaly_threshold:5},exclusions:[],metadata:{rationale:'Initial Observe policy',requested_by:'system'}};
const sites=[{site_id:'site_demo',display_name:'Bundled demo',hostname:'demo.example.test',hostnames:['demo.example.test'],origin_url:'http://demo-origin:8080',mode:'observe',synthetic:true},{site_id:'site_shop',display_name:'Shop',hostname:'shop.example.com',hostnames:['shop.example.com','www.shop.example.com'],origin_url:'http://shop-app:3000',mode:'protect',synthetic:false}];
const repo={schema_version:'1.0',repository_id:d.repository_id,owner_id:d.owner_id,app_id:'app_demo',asset_id:'shop-src',mode:'repo_offline',map_digest:d.map_digest,created_at:at(5000)};
const map={schema_version:'1.0',application_id:'app_demo',source_ref:'mounted-asset:shop-src',commit_sha:'9f1c2e7d4b6a8f0e1d2c3b4a5f6e7d8c9b0a1f2e',observed_at:at(5000),extractors:[{id:'next-file-conventions',version:'1.1'},{id:'express-literal-routes',version:'1.0'}],sensitive_ops:[],models:[],auth_boundaries:[],frameworks:['express'],files:Array.from({length:42},(_,i)=>({path:'src/f'+i+'.js',digest:digest('b'),size:100})),
 routes:[{method:'GET',pattern:'/api/accounts/{parameter}',origin:'declared_route',auth_signal:'not assessed',confidence:'medium',source_path:'src/routes/accounts.js'},{method:'POST',pattern:'/api/login',origin:'declared_route',auth_signal:'not assessed',confidence:'medium',source_path:'src/routes/auth.js'},{method:'GET',pattern:'/api/orders/{parameter}',origin:'declared_route',auth_signal:'auth_middleware_named',confidence:'medium',source_path:'src/routes/orders.js'}],unknowns:['Declared route files do not prove runtime reachability or authorization enforcement.'],content_digest:d.map_digest};

async function mock(page:Page){
 page.on('pageerror',e=>console.log('pageerror',e.message));
 await page.route('**/api/v1/**',async route=>{
  const u=new URL(route.request().url()),p=u.pathname.replace('/api/v1',''),m=route.request().method();
  const j=(json:any,status=200)=>route.fulfill({status,json});
  if(p==='/auth/session')return j({owner_id:d.owner_id,csrf_token:'preview'});
  if(p==='/system/status')return j({mode:'observe',gateway_healthy:true,gateway_revision:digest('a'),requests_retained:18342,open_incidents:3,events_dropped_total:0,database_bytes:42*1048576,version:'0.1.0-alpha.1',canary:{outcome:'PASS',checked_at:at(40)}});
  if(p==='/sites')return j({items:sites});
  if(p.endsWith('/events'))return j({items:events});
  if(p.endsWith('/incidents'))return j({items:incidents});
  if(p.startsWith('/incidents/')&&!p.endsWith('assessment')&&!p.endsWith('proposals'))return j({...incidents[0],confidence:'medium',detector:{detector_id:'CRS-942',detector_version:'1.0'},unknowns:['A rule match does not establish that exploitation succeeded.','Request bodies are not retained.'],evidence:events.slice(0,4).map(e=>e.event)});
  if(p.endsWith('/proposals'))return j({proposals:[],not_proposed:[],limitations:['Proposals are drafts until you validate and approve them.']});
  if(p.endsWith('/assessment'))return j({error:{message:'Not assessed yet'}},404);
  if(p.endsWith('/policy'))return j({digest:digest('a'),policy});
  if(p.endsWith('/policies/history'))return j({items:[{digest:digest('a'),policy,state:'ACTIVE',created_at:at(9000)},{digest:digest('c'),policy:{...policy,requested_mode:'protect'},state:'SUPERSEDED',created_at:at(20000)}]});
  if(p.endsWith('/endpoints'))return j({items:routes.map((r,i)=>({method:'GET',route_template:r,requests_retained:1200-i*130}))});
  if(p.endsWith('/exposure'))return j({entries:[],counts:{both:0,declared_only:0,observed_only:0,unclassified:0},limitations:[]});
  if(p==='/audit')return j({items:Array.from({length:6},(_,i)=>({seq:120-i,hash:digest(String(i)),previous_hash:digest(String(i+1))}))});
  if(p==='/ai/status')return j({provider:'ollama',model:'llama3.2:3b',deterministic_available:true});
  if(p==='/connectors')return j({items:[]});
  if(p==='/repos/assets')return j({asset_ids:['shop-src','billing-api']});
  if(p==='/repos')return j({items:[repo]});
  if(p.endsWith('/map'))return j(map);
  if(p.endsWith('/rescan'))return j({enabled:true,tool_ids:['bandit'],last_outcome:'unchanged'});
  if(p==='/findings/catalogue')return j(actual);
  if(p==='/scans')return j({items:[]});
  if(p.startsWith('/research')||p.startsWith('/verify'))return j({items:[]});
  return j({items:[]});
 });
}
const pages=['Overview','Sites','Live activity','Incidents','Endpoints','Policies','Verify','Repositories','Scans','Findings','AI Apps','Settings'];
for(const width of [1440,390]){
 test('pages at '+width,async({page})=>{
  test.setTimeout(240000);
  await page.emulateMedia({colorScheme:scheme,reducedMotion:'reduce'});
  await page.setViewportSize({width,height:width>800?960:844});
  await mock(page);await page.goto('/');await page.waitForTimeout(400);
  for(const name of pages){
   const nav=page.getByRole('navigation',{name:'Main navigation'}).getByRole('button',{name:new RegExp('^'+name)});
   if(width<800)await page.getByRole('button',{name:'Open navigation'}).click();
   await nav.click();await page.waitForTimeout(350);
   if(name==='Incidents')await page.getByText('SQL injection pattern on /api/{segment}').first().click().catch(()=>{});
   if(name==='Repositories')await page.getByRole('button',{name:'View map'}).click().catch(()=>{});
   await page.waitForTimeout(250);
   await page.screenshot({path:`${out}/${scheme}-${width}-${name.replace(' ','-').toLowerCase()}.png`,fullPage:true});
  }
 });
}
test('sign-in',async({page})=>{
 await page.emulateMedia({colorScheme:scheme});
 await page.route('**/api/v1/**',r=>r.fulfill({status:401,json:{error:{message:'Sign in'}}}));
 await page.goto('/');await page.waitForTimeout(400);
 await page.screenshot({path:`${out}/${scheme}-1440-signin.png`});
});
