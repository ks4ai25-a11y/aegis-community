import {test, expect, Page} from '@playwright/test';

const digest = 'sha256:' + 'a'.repeat(64);
const policy = {schema_version: '1.0', site_id: 'site_demo', parent_revision: '', requested_mode: 'observe', crs: {blocking_paranoia: 1, executing_paranoia: 1, inbound_anomaly_threshold: 5}, exclusions: [], metadata: {rationale: 'Initial Observe policy', requested_by: 'system'}};
const demo = {site_id: 'site_demo', display_name: 'Bundled demo', hostname: 'demo.example.test', hostnames: ['demo.example.test'], origin_url: 'http://demo-origin:8080', mode: 'observe', synthetic: true};
const report = {overall: 'PASS', checks: [], limitations: []};

async function mock(page: Page, extra: (path: string, method: string, body: any) => any) {
  const calls: {path: string; method: string; body: any; headers: Record<string, string>}[] = [];
  page.on('pageerror', e => { throw e; });
  await page.route('**/api/v1/**', async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace('/api/v1', '');
    const body = req.postData() ? JSON.parse(req.postData()!) : undefined;
    calls.push({path, method: req.method(), body, headers: req.headers()});
    const custom = extra(path, req.method(), body);
    if (custom !== undefined) return route.fulfill(custom.status ? custom : {json: custom});
    if (path === '/auth/session') return route.fulfill({json: {owner_id: 'owner', csrf_token: 'csrf'}});
    if (path === '/system/status') return route.fulfill({json: {mode: 'observe', gateway_healthy: true, version: 'test', canary: {outcome: 'PASS', checked_at: '2026-10-16T12:00:00Z'}}});
    if (path === '/sites') return route.fulfill({json: {items: [demo]}});
    if (path.endsWith('/policy')) return route.fulfill({json: {digest, policy}});
    if (path === '/ai/status') return route.fulfill({json: {provider: 'none', deterministic_available: true}});
    return route.fulfill({json: {items: []}});
  });
  return calls;
}

test('registering a site previews an Observe-only 1.1 candidate and activates it against the current revision', async ({page}) => {
  const calls = await mock(page, (path, method) => {
    if (path === '/sites/site_demo/policies/validate') return {candidate_digest: 'sha256:' + 'b'.repeat(64), current_digest: digest, fixture_result: 'PASS', report};
    if (path === '/sites/site_demo/policies' && method === 'POST') return {status: 201, json: {digest: 'sha256:' + 'b'.repeat(64), state: 'PENDING_APPROVAL'}};
    if (path.endsWith('/activate')) return {state: 'ACTIVE'};
  });
  await page.goto('/');
  await page.getByRole('button', {name: 'Sites', exact: true}).click();
  await page.getByPlaceholder('shop', {exact: true}).fill('Shop-1');
  await page.getByPlaceholder('Shop', {exact: true}).fill('Shop');
  await page.getByPlaceholder('shop.example.com www.shop.example.com').fill('shop.example.com, www.shop.example.com');
  await page.getByPlaceholder('shop-app:3000').fill('shop-app:3000');
  await page.getByLabel('HTTPS').selectOption('acme');
  await page.getByLabel('ACME contact email (optional)').fill('ops@shop.example.com');
  await page.getByLabel('Rate limit (requests per minute per client)').fill('600');
  await page.getByRole('button', {name: 'Validate and preview'}).first().click();
  await expect(page.getByText('Candidate preview')).toBeVisible();
  const preview = calls.find(c => c.path === '/sites/site_demo/policies/validate')!;
  expect(preview.body.schema_version).toBe('1.1');
  expect(preview.body.parent_revision).toBe(digest);
  expect(preview.body.sites).toEqual([{site_id: 'site_shop_1', display_name: 'Shop', hostnames: ['shop.example.com', 'www.shop.example.com'], origin: 'shop-app:3000', requested_mode: 'observe', crs: {blocking_paranoia: 1, executing_paranoia: 1, inbound_anomaly_threshold: 5}, exclusions: [], tls: 'acme', acme_email: 'ops@shop.example.com', rate_limit: {requests: 600, window_seconds: 60}}]);
  const approve = page.getByRole('button', {name: 'Approve and activate'});
  await expect(approve).toBeDisabled();
  await page.getByText('I understand that gateway routing').click();
  await approve.click();
  await expect(page.getByText('Gateway activation confirmed.')).toBeVisible();
  const activate = calls.find(c => c.path.endsWith('/activate'))!;
  expect(activate.headers['if-match']).toBe('"' + digest + '"');
  expect(activate.headers['idempotency-key']).toBeTruthy();
  expect(activate.body.acknowledge_disruption_risk).toBe(true);
});

test('incident panel shows detector record, advisory assessment and a proposal that must be previewed', async ({page}) => {
  const incident = {incident_id: 'inc-1', summary: 'Synthetic request matched CRS rule 942100', opened_at: '2026-10-16T12:00:00Z', state: 'open', severity: 'medium', confidence: 'high', synthetic: true, detector_id: 'DET-01'};
  const calls = await mock(page, (path, method) => {
    if (path === '/sites/site_demo/incidents') return {items: [incident]};
    if (path === '/incidents/inc-1') return {...incident, site_id: 'site_demo', detector: {detector_id: 'DET-01', detector_version: '1.0', assumption: 'A CRS rule matched request metadata.'}, evidence: [{event_id: 'ev-1', rule_ids: ['942100'], decision: 'unknown', target: 'ARGS:query'}], unknowns: ['Pattern detection does not prove successful exploitation.']};
    if (path === '/incidents/inc-1/assessment' && method === 'GET') return {status: 404, json: {error: {message: 'none'}}};
    if (path === '/incidents/inc-1/assessment') return {schema_version: '1.0', incident_id: 'inc-1', observed_facts: ['CRS rules matched: 942100.'], hypotheses: [{statement: '<img src=x onerror=alert(1)>', confidence: 'medium', evidence_refs: ['ev-1']}], uncertainties: ['u'], recommendations: [{action: 'Review routes', kind: 'investigate', risk_of_action: 'low'}], recommended_tests: [], provenance: {assessor: 'deterministic', dossier_digest: digest, generated_at: 'now'}, advisory_only: true};
    if (path === '/incidents/inc-1/proposals') return {proposals: [{proposal_id: 'p1', incident_id: 'inc-1', site_id: 'site_demo', kind: 'protect', priority: 'P2', title: 'Enable Protect for site_demo', rationale: 'r', expected_impact: 'i', side_effects: ['Legitimate requests may be blocked.'], evidence_refs: ['ev-1'], tests_to_run: [], candidate_policy: {...policy, parent_revision: digest, requested_mode: 'protect'}, advisory_only: true}], not_proposed: ['No matched parameter name was recorded.']};
    if (path === '/sites/site_demo/policies/validate') return {candidate_digest: 'sha256:' + 'c'.repeat(64), fixture_result: 'FAIL', report: {...report, overall: 'FAIL'}};
  });
  await page.goto('/');
  await page.getByRole('button', {name: 'Incidents', exact: true}).click();
  await page.getByRole('button', {name: /Synthetic request matched/}).click();
  await expect(page.getByText('A CRS rule matched request metadata.')).toBeVisible();
  await page.getByRole('button', {name: 'Deterministic assessment'}).click();
  // Model or detector text is rendered as text, never as markup.
  await expect(page.getByText('<img src=x onerror=alert(1)>')).toBeVisible();
  expect(await page.locator('img[src="x"]').count()).toBe(0);
  await expect(page.getByText('Not proposed: No matched parameter name was recorded.')).toBeVisible();
  await page.getByRole('button', {name: 'Validate and preview'}).click();
  await page.getByText('I reviewed the side effects').click();
  await expect(page.getByRole('button', {name: 'Approve and activate'})).toBeDisabled();
  expect(calls.some(c => c.path.endsWith('/activate'))).toBe(false);
});

test('assistant connection shows the token once and revokes', async ({page}) => {
  let items: any[] = [];
  const calls = await mock(page, (path, method) => {
    if (path === '/connectors' && method === 'POST') { items = [{connector_id: 'c1', name: 'Claude Desktop', scope: 'read_defence_v1', state: 'active', created_at: 'now', expires_unix: 1900000000, last_used_unix: 0}]; return {status: 201, json: {connector: items[0], token: 'aegis_ct_' + '1'.repeat(64), token_shown_once: true}}; }
    if (path === '/connectors') return {items, scope: 'read_defence_v1'};
    if (path === '/connectors/c1/revoke') { items = [{...items[0], state: 'revoked'}]; return {state: 'revoked'}; }
  });
  await page.goto('/');
  await page.getByRole('button', {name: 'AI Apps', exact: true}).click();
  await expect(page.getByText('Deterministic only')).toBeVisible();
  await page.getByRole('button', {name: 'Create connection'}).click();
  await expect(page.getByText('aegis_ct_' + '1'.repeat(64))).toBeVisible();
  await expect(page.getByText('"AEGIS_CONNECTOR_TOKEN_FILE"', {exact: false})).toBeVisible();
  await page.getByRole('button', {name: 'Revoke'}).click();
  await expect(page.getByText('revoked')).toBeVisible();
  expect(calls.filter(c => c.path === '/connectors' && c.method === 'POST')[0].body).toEqual({name: 'Claude Desktop', lifetime_hours: 168});
});

test('an owner opts a repository into change-triggered rescans with the fixed scanner set', async ({page}) => {
  const repo = {schema_version: '1.0', repository_id: 'repo-1', owner_id: 'owner', app_id: 'app_demo', asset_id: 'shop-src', mode: 'repo_offline', map_digest: digest, created_at: '2026-10-17T00:00:00Z'};
  let enabled = false;
  const calls = await mock(page, (path, method, body) => {
    if (path === '/repos/assets') return {asset_ids: ['shop-src']};
    if (path === '/repos') return {items: [repo]};
    if (path === '/repos/repo-1/rescan') {
      if (method === 'POST') enabled = body.enabled;
      return {schema_version: '1.0', repository_id: 'repo-1', enabled, tool_ids: enabled ? body.tool_ids : [], last_outcome: undefined};
    }
  });
  await page.goto('/');
  await page.getByRole('button', {name: 'Repositories', exact: true}).click();
  const toggle = page.getByLabel('Rescan repo-1 on change');
  await expect(toggle).not.toBeChecked();
  await toggle.click();
  await expect(page.getByText('Automatic rescans enabled for this repository.')).toBeVisible();
  const set = calls.find(c => c.path === '/repos/repo-1/rescan' && c.method === 'POST')!;
  expect(set.body).toEqual({enabled: true, tool_ids: ['bandit', 'gitleaks', 'osv_v2', 'semgrep_ce', 'syft', 'trivy'], tool_timeout_seconds: 120});
  expect(set.headers['x-csrf-token']).toBe('csrf');
  await expect(toggle).toBeChecked();
});

test('the research planner shows catalogue hypotheses and rejected model suggestions without running anything', async ({page}) => {
  const repo = {schema_version: '1.0', repository_id: 'repo-1', owner_id: 'owner', app_id: 'app_demo', asset_id: 'shop-src', mode: 'repo_offline', map_digest: digest, created_at: '2026-10-17T00:00:00Z'};
  const map = {schema_version: '1.0', application_id: 'app_demo', source_ref: 'mounted-asset:shop-src', commit_sha: '', observed_at: '2026-10-17T00:00:00Z', extractors: [], sensitive_ops: [], models: [], auth_boundaries: [], frameworks: ['express'], files: [{path: 'src/routes/accounts.js', digest, size: 10}], routes: [{method: 'GET', pattern: '/api/accounts/{parameter}', origin: 'declared_route', auth_signal: 'not assessed', confidence: 'medium', source_path: 'src/routes/accounts.js'}], unknowns: [], content_digest: digest};
  const plan = {plans: [{hypothesis_id: 'hyp_1', claim: 'GET /api/accounts/{parameter} might lack object ownership validation.', source_refs: ['src/routes/accounts.js'], test_template_id: 'cross_tenant_read_fixture_v1', security_requirement_id: 'tenant_isolation_01', runner: 'operator_lab_cli', next_step: 'On the operator host run aegis-research tenant-verify owner_fix.', evidence_status: 'hypothesis_unverified', origin: 'model'}],
    planner: 'ollama', model: 'llama3.2:3b', rejected_model_output: ['tool not in catalogue: run_shell_anywhere'], tool_log: [], limitations: ['Plans are hypotheses for a human; none is a confirmed vulnerability.'], plan_set_digest: digest};
  const calls = await mock(page, (path, method) => {
    if (path === '/repos/assets') return {asset_ids: ['shop-src']};
    if (path === '/repos') return {items: [repo]};
    if (path === '/repos/repo-1/map') return map;
    if (path === '/repos/repo-1/rescan') return {enabled: false, tool_ids: []};
    if (path === '/ai/status') return {provider: 'ollama'};
    if (path === '/repos/repo-1/research-plan' && method === 'POST') return plan;
  });
  await page.goto('/');
  await page.getByRole('button', {name: 'Repositories', exact: true}).click();
  await page.getByRole('button', {name: 'View map'}).click();
  await page.getByRole('button', {name: 'Plan with local model'}).click();
  await expect(page.getByText('might lack object ownership validation')).toBeVisible();
  await expect(page.getByText('hypothesis unverified · model')).toBeVisible();
  await page.getByText('1 model suggestions rejected').click();
  await expect(page.getByText('tool not in catalogue: run_shell_anywhere')).toBeVisible();
  expect(calls.find(c => c.path === '/repos/repo-1/research-plan')!.body).toEqual({use_model: true});
  expect(calls.filter(c => c.method === 'POST').map(c => c.path)).toEqual(['/repos/repo-1/research-plan']);
});
