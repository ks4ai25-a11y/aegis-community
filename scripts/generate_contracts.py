#!/usr/bin/env python3
"""Generate deterministic type bindings for the bounded JSON-schema subset used here."""
import json,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCHEMA='https://json-schema.org/draft/2020-12/schema'
def string(**kw):return {'type':'string',**kw}
def obj(properties,required=None):return {'type':'object','additionalProperties':False,'properties':properties,'required':list(properties) if required is None else required}
def array(items,**kw):return {'type':'array','items':items,**kw}
def integer(lo=0,hi=2147483647):return {'type':'integer','minimum':lo,'maximum':hi}
hash=string(pattern=r'^sha256:[0-9a-f]{64}$')
crs=obj({'blocking_paranoia':integer(1,4),'executing_paranoia':integer(1,4),'inbound_anomaly_threshold':integer(5,20)})
exclusion=obj({'rule_id':{'type':'integer','enum':[942100,941100]},'method':string(enum=['GET','POST']),'path':string(enum=['/catalog','/test-pattern']),'parameter':string(pattern=r'^[a-zA-Z][a-zA-Z0-9_]{0,31}$')})
policy=obj({'schema_version':string(const='1.0'),'site_id':string(const='site_demo'),'parent_revision':string(pattern=r'^(|sha256:[0-9a-f]{64})$'),'requested_mode':string(enum=['observe','protect']),'crs':crs,'exclusions':array(exclusion,maxItems=8),'metadata':obj({'rationale':string(minLength=5,maxLength=512),'requested_by':string(maxLength=128)})})
source=obj({'tool_id':string(maxLength=32),'tool_version':string(maxLength=64),'tool_image_digest':hash,'parser_version':string(enum=['1.0','1.1','1.2']),'input_digest':hash,'rule_id':string(maxLength=160),'severity_claimed':string(enum=['informational','low','medium','high','critical'])},['tool_id','tool_version','tool_image_digest','parser_version','input_digest'])
finding=obj({'schema_version':string(const='1.0'),'id':hash,'app_id':string(maxLength=128),'repository_id':string(maxLength=128),'category':string(enum=['static_pattern','secret_candidate','known_vulnerable_dependency','configuration_claim']),'summary':string(maxLength=512),'status':string(enum=['suspected','corroborated','reproduced','remediating','fixed_or_mitigated','monitored']),'severity':string(enum=['informational','low','medium','high','critical']),'confidence':string(enum=['low','medium','high']),'evidence_tier':string(enum=['T0','T1','T2','T3','T4','T5']),'path':string(maxLength=512),'line':integer(0,10000000),'package_name':string(maxLength=256),'package_url':string(maxLength=1024),'installed_version':string(maxLength=128),'advisories':array(string(maxLength=128),maxItems=64),'secret_fingerprint':hash,'provenance':array(source,minItems=1,maxItems=16),'coverage_note':string(maxLength=512),'created_at':string(format='date-time')},['schema_version','id','app_id','repository_id','category','summary','status','severity','confidence','evidence_tier','provenance','coverage_note','created_at'])

uuid=string(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
grant=obj({'schema_version':string(const='1.0'),'scope_grant_id':uuid,'owner_id':string(maxLength=128),'app_id':string(const='app_demo'),'asset_id':string(const='bundled-waf-fixture'),'ownership_evidence':string(const='Aegis-owned bundled synthetic fixture'),'mode':string(const='test_lab'),'allowed_protocols':array(string(enum=['http']),minItems=1,maxItems=1),'allowed_routes':array(string(enum=['/catalog','/test-pattern']),minItems=2,maxItems=2),'allowed_tests':array(string(const='crs-synthetic-sqli-pattern-v1'),minItems=1,maxItems=1),'network_profile':string(const='test_lab_only'),'network_addresses':array(string(const='fixture-origin:8080'),minItems=1,maxItems=1),'max_concurrency':integer(1,1),'max_requests':integer(4,4),'max_duration_seconds':integer(30,30),'created_at':string(format='date-time'),'expires_at':string(format='date-time')})
grant_record=obj({'grant':grant,'approved_digest':hash,'state':string(enum=['draft','active','revoked']),'requests_remaining':integer(0,4)})
job_input=obj({'schema_version':string(const='1.0'),'app_id':string(const='app_demo'),'scope_grant_id':uuid,'scope_digest':hash,'fixture_id':string(const='crs-synthetic-sqli-pattern-v1'),'policy_digest':hash})
job=obj({'schema_version':string(const='1.0'),'job_id':uuid,'owner_id':string(maxLength=128),'app_id':string(const='app_demo'),'job_type':string(const='waf_fixture'),'scope_grant_id':uuid,'input_digest':hash,'state':string(enum=['queued','running','success','failed','cancelled','timeout']),'attempts':integer(),'created_at':string(format='date-time'),'finished_at':string(format='date-time'),'error_code':string(maxLength=64),'report_digest':hash},['schema_version','job_id','owner_id','app_id','job_type','scope_grant_id','input_digest','state','attempts','created_at'])
check=obj({'id':string(enum=['control-allowed','negative-matched-and-mode-correct']),'result':string(enum=['PASS','FAIL','INCONCLUSIVE']),'baseline_http_status':integer(0,599),'candidate_http_status':integer(0,599),'rule_ids':array(string(pattern=r'^[0-9]{1,10}$'),maxItems=64),'baseline_rule_ids':array(string(pattern=r'^[0-9]{1,10}$'),maxItems=64)},['id','result','baseline_http_status','candidate_http_status','rule_ids'])
verification=obj({'schema_version':string(const='1.0'),'report_id':uuid,'test_scope':string(const='bundled-synthetic-fixture'),'scope_grant_id':uuid,'job_id':uuid,'scope_digest':hash,'claim_level':string(const='LEVEL_1_CONTROL_TEST'),'fixture_id':string(const='crs-synthetic-sqli-pattern-v1'),'fixture_digest':hash,'baseline_policy_digest':hash,'candidate_policy_digest':hash,'gateway_binary_digest':hash,'started_at':string(format='date-time'),'completed_at':string(format='date-time'),'checks':array(check,minItems=2,maxItems=2),'overall':string(enum=['PASS','FAIL','INCONCLUSIVE']),'limitations':array(string(maxLength=512),minItems=1,maxItems=16),'canonical_sha256':hash},['schema_version','report_id','test_scope','claim_level','fixture_id','fixture_digest','baseline_policy_digest','candidate_policy_digest','gateway_binary_digest','started_at','completed_at','checks','overall','limitations','canonical_sha256'])
schemas={'PolicyRevisionV1':policy,'FindingV1':finding,'ScopeGrantV1':grant,'ScopeGrantRecordV1':grant_record,'VerificationJobInputV1':job_input,'ResearchJobV1':job,'VerificationReportV1':verification}

schemas.update({
 'ScopeGrantDraftRequestV1':obj({'app_id':string(const='app_demo'),'mode':string(const='test_lab'),'fixture_id':string(const='crs-synthetic-sqli-pattern-v1'),'lifetime_minutes':integer(1,60)}),
 'ScopeGrantApprovalRequestV1':obj({'approved_digest':hash,'acknowledge_test_scope':{'type':'boolean','const':True}}),
 'EmptyObjectV1':obj({}),
 'ScopeRevocationReceiptV1':obj({'state':string(const='revoked')}),
 'ScopeGrantListV1':obj({'items':array(grant_record,maxItems=100)}),
 'ResearchJobListV1':obj({'items':array(job,maxItems=100)}),
 'ErrorEnvelopeV1':obj({'error':obj({'code':string(maxLength=64),'message':string(maxLength=512),'request_id':uuid,'retryable':{'type':'boolean'}})})
})

file_ref=obj({'path':string(maxLength=512),'digest':hash,'size':integer(0,1048576)})
route_ref=obj({'method':string(enum=['unknown']),'pattern':string(maxLength=512),'origin':string(const='declared_route'),'auth_signal':string(const='not assessed'),'confidence':string(const='low'),'source_path':string(maxLength=512)})
application_map=obj({'schema_version':string(const='1.0'),'application_id':string(const='app_demo'),'source_ref':string(maxLength=128),'commit_sha':string(pattern=r'^(|[0-9a-f]{40}|[0-9a-f]{64})$'),'observed_at':string(format='date-time'),'extractors':array(obj({'id':string(maxLength=64),'version':string(maxLength=32)}),maxItems=16),'sensitive_ops':array(string(maxLength=512),maxItems=100),'models':array(string(maxLength=512),maxItems=100),'auth_boundaries':array(string(maxLength=512),maxItems=100),'frameworks':array(string(maxLength=32),maxItems=16),'files':array(file_ref,maxItems=10000),'routes':array(route_ref,maxItems=10000),'unknowns':array(string(maxLength=512),minItems=1,maxItems=32),'content_digest':hash})
repository=obj({'schema_version':string(const='1.0'),'repository_id':uuid,'owner_id':string(maxLength=128),'app_id':string(const='app_demo'),'asset_id':string(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$'),'mode':string(const='repo_offline'),'map_digest':hash,'created_at':string(format='date-time')})
schemas.update({
 'ApplicationMapV1':application_map,
 'RepositoryV1':repository,
 'RepositoryConnectionRequestV1':obj({'app_id':string(const='app_demo'),'asset_id':repository['properties']['asset_id'],'acknowledge_read_only':{'type':'boolean','const':True}}),
 'RepositoryListV1':obj({'items':array(repository,maxItems=100)}),
 'RepositoryAssetListV1':obj({'asset_ids':array(repository['properties']['asset_id'],maxItems=100)})
})

snapshot=obj({'schema_version':string(const='1.0'),'input_map_digest':hash,'commit_sha':string(pattern=r'^(|[0-9a-f]{40}|[0-9a-f]{64})$'),'files':array(file_ref,maxItems=10000),'included_bytes':integer(0,67108864),'snapshot_digest':hash})
scanner_status=string(enum=['completed','completed_partial','completed_stale_db','tool_error'])
sbom=obj({'bomFormat':string(const='CycloneDX'),'specVersion':string(enum=['1.4','1.5','1.6','1.7']),'version':integer(1,1),'components':array(obj({'name':string(minLength=1,maxLength=256),'version':string(maxLength=128),'purl':string(maxLength=1024)}),maxItems=10000)})
scan_result=obj({'status':scanner_status,'findings':array(finding,maxItems=10000),'diagnostics':array(obj({'code':string(maxLength=64),'message':string(maxLength=512)}),maxItems=64),'sbom':sbom},['status','findings','diagnostics'])
execution=obj({'parser_version':string(enum=['1.0','1.1','1.2']),'invocation':obj({'args':array(string(maxLength=1024),maxItems=32),'network_profile':string(const='none'),'timeout_seconds':integer(120,120),'max_output_bytes':integer(8388608,8388608),'finding_exit_codes':array(integer(0,255),minItems=1,maxItems=4)}),'sandbox_profile':string(const='repo_offline-network-none-v1'),'schema_version':string(const='1.0'),'tool_id':string(enum=['semgrep_ce','osv_v2','trivy','syft','gitleaks','bandit']),'tool_version':string(maxLength=64),'tool_image_digest':hash,'tool_lock_digest':hash,'rule_pack_digest':hash,'guard_binary_digest':hash,'duration_limit_seconds':integer(1,120),'source_snapshot':snapshot,'started_at':string(format='date-time'),'duration_ms':integer(0,140000),'exit_code':integer(-1,255),'status':scanner_status,'cleanup_state':string(enum=['complete','unconfirmed']),'container_id':string(pattern=r'^aegis-scan-[0-9a-f]{32}$'),'result':scan_result,'limitations':array(string(maxLength=512),minItems=1,maxItems=16)},['invocation','sandbox_profile','schema_version','tool_id','tool_version','tool_image_digest','tool_lock_digest','guard_binary_digest','duration_limit_seconds','source_snapshot','started_at','duration_ms','exit_code','status','cleanup_state','container_id','result','limitations'])
schemas.update({'SourceSnapshotManifestV1':snapshot,'ScannerExecutionV1':execution})
scan_input=obj({'schema_version':string(const='1.0'),'app_id':string(const='app_demo'),'repository_id':uuid,'map_digest':hash,'mode':string(const='repo_offline'),'tool_ids':array(execution['properties']['tool_id'],minItems=1,maxItems=6,uniqueItems=True),'tool_timeout_seconds':integer(1,120)})
scan_job=obj({'schema_version':string(const='1.0'),'job_id':uuid,'owner_id':string(minLength=1,maxLength=128),'input':scan_input,'tool_lock_digest':hash,'request_digest':hash,'state':string(enum=['queued','running','cancelled','timeout','failed','completed','completed_partial','completed_stale_db','tool_error']),'cancel_requested':{'type':'boolean'},'created_at':string(format='date-time'),'expires_at':string(format='date-time'),'finished_at':string(format='date-time'),'error_code':string(maxLength=64)},['schema_version','job_id','owner_id','input','tool_lock_digest','request_digest','state','cancel_requested','created_at','expires_at'])
scan_status=obj({'job':scan_job,'execution_admission':string(enum=['not_claimed','unconfirmed','active','cleanup_required'])})
schemas.update({'ScannerJobInputV1':scan_input,'ScannerJobV1':scan_job,'ScannerJobListV1':obj({'items':array(scan_job,maxItems=100)}),'ScannerJobStatusV1':scan_status})

suite_tool=obj({'tool_id':string(enum=['semgrep_ce','osv_v2','trivy','syft','gitleaks','bandit']),'receipt_digest':hash,'status':scanner_status,'finding_claims':integer(0,10000),'has_sbom':{'type':'boolean'}})
suite=obj({'schema_version':string(const='1.0'),'owner_id':string(minLength=1,maxLength=128),'job_id':uuid,'request_digest':hash,'app_id':string(const='app_demo'),'repository_id':string(minLength=1,maxLength=128),'map_digest':hash,'tool_lock_digest':hash,'snapshot_digest':hash,'status':scanner_status,'tools':array(suite_tool,minItems=1,maxItems=6),'finding_claims':integer(0,60000),'has_partial':{'type':'boolean'},'has_stale_database':{'type':'boolean'},'has_tool_error':{'type':'boolean'},'evidence_tier':string(const='T0'),'cleanup_required':{'type':'boolean','const':True},'created_at':string(format='date-time')})
schemas.update({'ScannerSuiteV1':suite,'ScannerSuiteResultV1':obj({'result_digest':hash,'document':suite})})
launch_plan=obj({'tool_id':string(enum=['semgrep_ce','osv_v2','trivy','syft','gitleaks','bandit']),'container_id':string(pattern=r'^aegis-scan-[0-9a-f]{32}$'),'engine_digest':hash,'workspace_id':string(pattern=r'^run-[0-9a-f]{32}$'),'registry_digest':hash,'snapshot_digest':hash})
launch=obj({'schema_version':string(const='1.0'),'owner_id':string(minLength=1,maxLength=128),'job_id':uuid,'request_digest':hash,'app_id':string(const='app_demo'),'repository_id':string(minLength=1,maxLength=128),'map_digest':hash,'tool_lock_digest':hash,'tool_version':string(minLength=1,maxLength=64),'tool_image_digest':hash,'sandbox_profile':string(const='repo_offline-network-none-v1'),'duration_limit_seconds':integer(1,120),'plan':launch_plan,'created_at':string(format='date-time'),'deadline':string(format='date-time')})
schemas.update({'ScannerLaunchPlanV1':launch_plan,'ScannerLaunchV1':launch,'ScannerLaunchRecordV1':obj({'launch_digest':hash,'document':launch})})

workspace_plan=obj({'tool_id':launch_plan['properties']['tool_id'],'workspace_id':launch_plan['properties']['workspace_id'],'registry_digest':hash,'snapshot_digest':hash})
workspace=obj({'schema_version':string(const='1.0'),'owner_id':string(minLength=1,maxLength=128),'job_id':uuid,'request_digest':hash,'app_id':string(const='app_demo'),'repository_id':string(minLength=1,maxLength=128),'map_digest':hash,'tool_lock_digest':hash,'plan':workspace_plan,'created_at':string(format='date-time'),'deadline':string(format='date-time')})
schemas.update({'ScannerWorkspacePlanV1':workspace_plan,'ScannerWorkspaceV1':workspace,'ScannerWorkspaceRecordV1':obj({'workspace_digest':hash,'document':workspace})})

guard_set=obj({'schema_version':string(const='1.0'),'protocol':string(const='absolute-deadline-v1'),'linux_amd64':hash,'linux_arm64':hash,'guard_set_digest':hash})
launch_plan_v2=obj({**launch_plan['properties'],'guard_binary_digest':hash,'guard_architecture':string(enum=['amd64','arm64'])})
launch_v2=obj({**launch['properties'],'schema_version':string(const='1.1'),'plan':launch_plan_v2,'guard_set_digest':hash,'guard_protocol':string(const='absolute-deadline-v1')})
schemas.update({'ScannerGuardSetV1':guard_set,'ScannerLaunchPlanV2':launch_plan_v2,'ScannerLaunchV2':launch_v2,'ScannerLaunchRecordV2':obj({'launch_digest':hash,'document':launch_v2})})

for name,body in schemas.items():
 document={'$schema':SCHEMA,'$id':'https://aegis.invalid/contracts/'+name+'.json','title':name,**body}
 (ROOT/'contracts/schemas'/f'{name}.json').write_text(json.dumps(document,indent=2)+'\n')
# Flatten nested objects into named types to generate equivalent field bindings.
def flatten(name,schema,types):
 if schema.get('type')!='object':return
 if name in types:return
 types[name]=schema
 for key,value in schema['properties'].items():
  child=name+''.join(x.title() for x in key.split('_'))
  if value.get('type')=='object':value['_binding']=child;flatten(child,value,types)
  if value.get('type')=='array' and value['items'].get('type')=='object':value['items']['_binding']=child+'Item';flatten(child+'Item',value['items'],types)
types={}
workspace_plan=obj({'tool_id':launch_plan['properties']['tool_id'],'workspace_id':launch_plan['properties']['workspace_id'],'registry_digest':hash,'snapshot_digest':hash})
workspace=obj({'schema_version':string(const='1.0'),'owner_id':string(minLength=1,maxLength=128),'job_id':uuid,'request_digest':hash,'app_id':string(const='app_demo'),'repository_id':string(minLength=1,maxLength=128),'map_digest':hash,'tool_lock_digest':hash,'plan':workspace_plan,'created_at':string(format='date-time'),'deadline':string(format='date-time')})
schemas.update({'ScannerWorkspacePlanV1':workspace_plan,'ScannerWorkspaceV1':workspace,'ScannerWorkspaceRecordV1':obj({'workspace_digest':hash,'document':workspace})})

guard_set=obj({'schema_version':string(const='1.0'),'protocol':string(const='absolute-deadline-v1'),'linux_amd64':hash,'linux_arm64':hash,'guard_set_digest':hash})
launch_plan_v2=obj({**launch_plan['properties'],'guard_binary_digest':hash,'guard_architecture':string(enum=['amd64','arm64'])})
launch_v2=obj({**launch['properties'],'schema_version':string(const='1.1'),'plan':launch_plan_v2,'guard_set_digest':hash,'guard_protocol':string(const='absolute-deadline-v1')})
schemas.update({'ScannerGuardSetV1':guard_set,'ScannerLaunchPlanV2':launch_plan_v2,'ScannerLaunchV2':launch_v2,'ScannerLaunchRecordV2':obj({'launch_digest':hash,'document':launch_v2})})

for name,body in schemas.items():flatten(name,body,types)
def ts(s):
 if '_binding' in s:return s['_binding']
 if 'const' in s:return json.dumps(s['const'])
 if 'enum' in s:return ' | '.join(json.dumps(x) for x in s['enum'])
 t=s['type'];return {'string':'string','integer':'number','boolean':'boolean'}.get(t,'Array<'+ts(s['items'])+'>' if t=='array' else 'unknown')
def go(s):
 if '_binding' in s:return s['_binding']
 t=s['type'];return {'string':'string','integer':'int64','boolean':'bool'}.get(t,'[]'+go(s['items']) if t=='array' else 'any')
def py(s):
 if '_binding' in s:return s['_binding']
 t=s['type'];return {'string':'str','integer':'int','boolean':'bool'}.get(t,'list['+py(s['items'])+']' if t=='array' else 'Any')
TS=['// Generated by scripts/generate_contracts.py; do not edit.']
GO=['// Generated by scripts/generate_contracts.py; DO NOT EDIT.','package contracts']
PY=['# Generated by scripts/generate_contracts.py; do not edit.','from __future__ import annotations','from typing import TypedDict, NotRequired, Any']
for name,body in types.items():
 TS.append('export interface '+name+' {');GO.append('type '+name+' struct {');PY.append('class '+name+'(TypedDict):')
 for field,s in body['properties'].items():
  optional=field not in body['required'];TS.append('  '+field+('?' if optional else '')+': '+ts(s)+';')
  GO.append('  '+''.join(x.title() for x in field.split('_'))+' '+go(s)+' `json:"'+field+(',omitempty' if optional else '')+'"`')
  PY.append('    '+field+': '+('NotRequired['+py(s)+']' if optional else py(s)))
 if not body['properties']:PY.append('    pass')
 TS.append('}');GO.append('}')
for f,lines in [('contracts.ts',TS),('contracts.go',GO),('contracts.py',PY)]:
 (ROOT/'contracts/generated'/f).write_text('\n'.join(lines)+'\n')

# Keep the console import local to its independently built source tree.
console=ROOT/'console/src/generated'
console.mkdir(exist_ok=True)
(console/'contracts.ts').write_text((ROOT/'contracts/generated/contracts.ts').read_text())

subprocess.run(["gofmt","-w",str(ROOT/"contracts/generated/contracts.go")],check=True)
