import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';

test.use({trace:'off'}); // Real demo credential/session material must never enter traces.
test('deployed owner console queues and cancels a real offline request',async({page})=>{
 test.skip(process.env.AEGIS_LIVE_UI_TEST!=='1','Explicit named local demo only');
 const credential=process.env.AEGIS_TEST_CREDENTIAL_FILE||'/private/tmp/aegis-demo-test-credential';
 const origin='http://127.0.0.1:7410';
 const response=await page.request.post(origin+'/api/v1/auth/login',{data:{password:readFileSync(credential,'utf8')}});
 if(response.status()!==200)throw new Error('Local demo owner login failed');
 await page.goto(origin);
 await page.getByRole('button',{name:'Scans',exact:true}).click();
 const select=page.getByLabel('Connected repository');
 const option=select.locator('option').filter({hasText:/^safe ·/});await expect(option).toHaveCount(1);
 const value=await option.getAttribute('value');if(!value)throw new Error('Safe provisioned repository missing');await select.selectOption(value);
 await page.getByLabel('Time limit per tool (seconds)').fill('5');
 await page.getByRole('checkbox',{name:/I authorize these read-only tools/}).check();
 await page.getByRole('button',{name:'Queue scan',exact:true}).click();
 await expect(page.locator('.scan-detail')).toContainText('This job has not acquired execution admission.');
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toHaveCount(0);
 await page.screenshot({path:test.info().outputPath('triage-phase-scanner-console-live-queued.png'),fullPage:true});
 await page.getByRole('button',{name:'Cancel selected scan'}).click();
 await expect(page.locator('.scan-detail')).toContainText('Resource cleanup is unconfirmed.');
 await expect(page.locator('.scan-detail')).toContainText('cancelled');
 await expect(page.getByRole('heading',{name:'Static scan evidence'})).toHaveCount(0);
 await page.screenshot({path:test.info().outputPath('triage-phase-scanner-console-live-cancelled.png'),fullPage:true});
 await page.getByRole('button',{name:'Sign out'}).click();
 await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
});
