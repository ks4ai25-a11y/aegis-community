import {defineConfig} from '@playwright/test';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
export default defineConfig({
 testDir:'./tests',fullyParallel:false,workers:1,timeout:30000,
 reporter:[['list'],['json',{outputFile:process.env.AEGIS_BROWSER_REPORT||join(tmpdir(),'aegis-scanner-console-browser-results.json')}]],
 use:{baseURL:'http://127.0.0.1:4173',channel:process.env.AEGIS_BROWSER_CHANNEL||undefined,viewport:{width:1440,height:1100},trace:'retain-on-failure'},
 webServer:{command:'npm run build && npm run preview -- --port 4173 --strictPort',url:'http://127.0.0.1:4173',reuseExistingServer:false,timeout:60000},
 outputDir:process.env.AEGIS_BROWSER_OUTPUT||join(tmpdir(),'aegis-scanner-console-test-output'),
});
