// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';

for(const value of [{job:{state:'completed'}},{items:null},{items:[null]},{items:[{site_id:12,display_name:{}}]}]) {
 test('malformed site catalogue preserves the workspace: '+JSON.stringify(value),async({page})=>{
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const path=new URL(route.request().url()).pathname;
   const body=path==='/api/v1/auth/session'?{owner_id:'fixture-owner',csrf_token:'synthetic-csrf'}:path==='/api/v1/sites'?value:path==='/api/v1/system/status'?{mode:'observe',gateway_healthy:true,version:'synthetic fixture',database_bytes:1024}:{items:[]};
   await route.fulfill({json:body});
  });
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Your security, in focus.',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Findings',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Findings',exact:true})).toBeVisible();
  expect(errors).toEqual([]);
 });
}
