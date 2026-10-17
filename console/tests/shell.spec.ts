import {test, expect, Page} from '@playwright/test';

async function mock(page: Page, extra: (path: string) => any = () => undefined) {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    const custom = extra(path);
    if (custom !== undefined) return route.fulfill({json: custom});
    if (path === '/auth/session') return route.fulfill({json: {owner_id: 'owner', csrf_token: 'csrf'}});
    if (path === '/system/status') return route.fulfill({json: {mode: 'observe', gateway_healthy: true, version: 'test', requests_retained: 1234567, open_incidents: 2, events_dropped_total: 0, database_bytes: 2048}});
    return route.fulfill({json: {items: []}});
  });
}

test('the command palette jumps to a page by keyboard', async ({page}) => {
  await mock(page);
  await page.goto('/');
  await expect(page.getByRole('heading', {name: 'Your security, in focus.', exact: true})).toBeVisible();
  await expect(page.getByText('1,234,567')).toBeVisible();
  await page.keyboard.press('ControlOrMeta+k');
  const dialog = page.getByRole('dialog', {name: 'Jump to a page'});
  await expect(dialog).toBeVisible();
  await page.keyboard.type('find');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('heading', {name: 'Findings', exact: true}).first()).toBeVisible();
  await expect(page.getByRole('button', {name: 'Findings', exact: true})).toHaveAttribute('aria-current', 'page');
  await page.getByRole('button', {name: 'Search pages'}).click();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
});

test('the theme toggle switches and is remembered', async ({page}) => {
  await page.emulateMedia({colorScheme: 'dark'});
  await mock(page);
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('button', {name: 'Switch to light theme'}).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

test('on a phone the navigation is a drawer that is not focusable while closed', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await mock(page);
  await page.goto('/');
  const sites = page.getByRole('button', {name: 'Sites', exact: true});
  await expect(sites).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.getByRole('button', {name: 'Open navigation'}).click();
  await expect(sites).toBeVisible();
  await sites.click();
  await expect(sites).toBeHidden();
  await expect(page.getByRole('heading', {name: 'Sites', exact: true}).first()).toBeVisible();
});

test('a page that fails to render does not blank the console', async ({page}) => {
  await mock(page, path => path === '/sites/site_demo/incidents' ? {items: [{incident_id: 'i1', summary: 'x', detector_id: 'd', opened_at: '2026-10-17T00:00:00Z', state: 'open', severity: 'low'}]} : path === '/incidents/i1' ? {incident_id: 'i1', summary: 'x', confidence: 'low', unknowns: [], evidence: []} : path === '/incidents/i1/proposals' ? {} : undefined);
  await page.goto('/');
  await page.getByRole('button', {name: 'Incidents', exact: true}).click();
  await page.getByRole('button', {name: /^x/}).click();
  await expect(page.getByText('This view could not be displayed')).toBeVisible();
  await page.getByRole('button', {name: 'Policies', exact: true}).click();
  await expect(page.getByText('This view could not be displayed')).toBeHidden();
  await expect(page.getByRole('heading', {name: 'Review a policy change'})).toBeVisible();
});

test('an action error stays visible while status keeps polling', async ({page}) => {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    if (path === '/auth/session') return route.fulfill({json: {owner_id: 'owner', csrf_token: 'csrf'}});
    if (path === '/system/status') return route.fulfill({json: {mode: 'observe', gateway_healthy: true}});
    if (path === '/demo/traffic') return route.fulfill({status: 422, json: {error: {message: 'Demo traffic refused'}}});
    return route.fulfill({json: {items: []}});
  });
  await page.goto('/');
  await page.getByRole('button', {name: 'Run safe demo traffic'}).click();
  await expect(page.getByRole('alert').filter({hasText: 'Demo traffic refused'})).toBeVisible();
  await page.waitForTimeout(6500); // more than one status poll
  await expect(page.getByRole('alert').filter({hasText: 'Demo traffic refused'})).toBeVisible();
  await page.getByRole('button', {name: 'Dismiss error'}).click();
  await expect(page.getByText('Demo traffic refused')).toBeHidden();
});

test('an expired session returns to sign-in with an explanation', async ({page}) => {
  let expired = false;
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    if (path === '/auth/session') return expired ? route.fulfill({status: 401, json: {error: {message: 'authentication required'}}}) : route.fulfill({json: {owner_id: 'owner', csrf_token: 'csrf'}});
    if (expired) return route.fulfill({status: 401, json: {error: {message: 'authentication required'}}});
    if (path === '/system/status') return route.fulfill({json: {mode: 'observe', gateway_healthy: true}});
    return route.fulfill({json: {items: []}});
  });
  await page.goto('/');
  await expect(page.getByRole('heading', {name: 'Your security, in focus.', exact: true})).toBeVisible();
  expired = true;
  await expect(page.getByRole('heading', {name: 'Welcome back.'})).toBeVisible({timeout: 8000});
  await expect(page.getByText('Your session ended. Sign in again to continue.')).toBeVisible();
});

test('switching site discards a policy preview made for the other site', async ({page}) => {
  const digest = 'sha256:' + 'a'.repeat(64);
  const policy = {schema_version: '1.1', parent_revision: '', requested_mode: 'observe', crs: {blocking_paranoia: 1, executing_paranoia: 1, inbound_anomaly_threshold: 5}, exclusions: [], sites: [{site_id: 'site_shop', display_name: 'Shop', hostnames: ['shop.example.com'], origin: 'shop:3000', requested_mode: 'observe', crs: {blocking_paranoia: 1, executing_paranoia: 1, inbound_anomaly_threshold: 5}, exclusions: []}], metadata: {rationale: 'x', requested_by: 'system'}};
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    if (path === '/auth/session') return route.fulfill({json: {owner_id: 'owner', csrf_token: 'csrf'}});
    if (path === '/system/status') return route.fulfill({json: {mode: 'observe', gateway_healthy: true}});
    if (path === '/sites') return route.fulfill({json: {items: [{site_id: 'site_demo', display_name: 'Bundled demo'}, {site_id: 'site_shop', display_name: 'Shop'}]}});
    if (path.endsWith('/policy')) return route.fulfill({json: {digest, policy}});
    if (path.endsWith('/policies/validate')) return route.fulfill({json: {candidate_digest: 'sha256:' + 'b'.repeat(64), fixture_result: 'PASS', report: {overall: 'PASS', checks: [], limitations: []}}});
    return route.fulfill({json: {items: []}});
  });
  await page.goto('/');
  await page.getByLabel('Selected site').selectOption('site_shop');
  await page.getByRole('button', {name: 'Policies', exact: true}).click();
  await page.getByRole('button', {name: 'Validate and preview'}).click();
  await expect(page.getByText('Candidate preview')).toBeVisible();
  await page.getByLabel('Selected site').selectOption('site_demo');
  await expect(page.getByText('Candidate preview')).toBeHidden();
});
