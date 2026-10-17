// SPDX-License-Identifier: BUSL-1.1
// Design preview: screenshots every console page with realistic mocked data.
// Not part of the test suite. Run: npx playwright test -c preview/preview.config.ts
import {defineConfig} from '@playwright/test';
export default defineConfig({
 testDir:'.',fullyParallel:false,workers:1,timeout:60000,reporter:[['list']],
 use:{baseURL:'http://127.0.0.1:4174',channel:process.env.AEGIS_BROWSER_CHANNEL||'chrome',viewport:{width:1440,height:960},timezoneId:'UTC',actionTimeout:5000},
 webServer:{command:'npm run build && npm run preview -- --port 4174 --strictPort',url:'http://127.0.0.1:4174',reuseExistingServer:false,timeout:90000},
 outputDir:process.env.AEGIS_PREVIEW_OUT||'/tmp/aegis-preview-output',
});
