// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
test.use({trace:'off'});
test('deployed owner catalogue retains truthful result availability',async({page},info)=>{
 test.skip(process.env.AEGIS_LIVE_CATALOGUE_TEST!=='1','Explicit named local demo only');
 const origin='http://127.0.0.1:7410';
 const response=await page.request.post(origin+'/api/v1/auth/login',{data:{password:readFileSync(process.env.AEGIS_TEST_CREDENTIAL_FILE||'/private/tmp/aegis-demo-test-credential','utf8')}});
 if(response.status()!==200)throw new Error('Local demo owner login failed');
 const source=await page.request.get(origin+'/api/v1/findings/catalogue?limit=20');if(source.status()!==200)throw new Error('Local owner catalogue unavailable');const data=await source.json();
 await page.goto(origin);await page.getByRole('button',{name:'Findings',exact:true}).click();await expect(page.locator('.catalogue-results')).toContainText(data.retained_result_count+' retained scan results');
 if(data.retained_result_count===0){await expect(page.locator('.catalogue-results')).toContainText('does not establish zero findings');await expect(page.locator('.finding-record')).toHaveCount(0)}else{await expect(page.locator('.finding-record').first()).toContainText('Evidence: T0')}
 await page.screenshot({path:info.outputPath('catalogue-live.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});
