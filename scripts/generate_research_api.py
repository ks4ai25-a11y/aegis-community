#!/usr/bin/env python3
"""Generate OpenAPI 3.1 and clients for the implemented scoped research surface."""
import json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
def schema(name):return {'$ref':'#/components/schemas/'+name}
# name, method, path, request, response, success status, idempotency requirement
ops=[
 ('connectRepository','post','/repos','RepositoryConnectionRequestV1','RepositoryV1',201,False),
 ('listRepositories','get','/repos',None,'RepositoryListV1',200,False),
 ('listRepositoryAssets','get','/repos/assets',None,'RepositoryAssetListV1',200,False),
 ('getRepository','get','/repos/{id}',None,'RepositoryV1',200,False),
 ('getApplicationMap','get','/repos/{id}/map',None,'ApplicationMapV1',200,False),
 ('createScopeGrant','post','/scope-grants','ScopeGrantDraftRequestV1','ScopeGrantRecordV1',201,False),
 ('listScopeGrants','get','/scope-grants',None,'ScopeGrantListV1',200,False),
 ('getScopeGrant','get','/scope-grants/{id}',None,'ScopeGrantRecordV1',200,False),
 ('approveScopeGrant','post','/scope-grants/{id}/approve','ScopeGrantApprovalRequestV1','ScopeGrantRecordV1',200,False),
 ('revokeScopeGrant','post','/scope-grants/{id}/revoke','EmptyObjectV1','ScopeRevocationReceiptV1',200,False),
 ('createVerification','post','/verifications','VerificationJobInputV1','ResearchJobV1',202,True),
 ('listVerifications','get','/verifications',None,'ResearchJobListV1',200,False),
 ('getVerification','get','/verifications/{id}',None,'ResearchJobV1',200,False),
 ('cancelVerification','post','/verifications/{id}/cancel','EmptyObjectV1','ResearchJobV1',200,False),
 ('getVerificationReport','get','/verify/reports/{id}',None,'VerificationReportV1',200,False),
]
paths={}
for name,method,path,body,result,status,key in ops:
 operation={'operationId':name,'security':[{'ownerSession':[]}],'responses':{str(status):{'description':'Successful owner-scoped operation','content':{'application/json':{'schema':schema(result)}}},'default':{'description':'Typed failure; never a success or clean-scan conclusion','content':{'application/json':{'schema':schema('ErrorEnvelopeV1')}}}}}
 params=[]
 if '{id}' in path:params.append({'name':'id','in':'path','required':True,'schema':{'type':'string','maxLength':80}})
 if method=='post':params.append({'name':'X-CSRF-Token','in':'header','required':True,'schema':{'type':'string'}})
 if key:params.append({'name':'Idempotency-Key','in':'header','required':True,'schema':{'type':'string','minLength':8,'maxLength':128}})
 if params:operation['parameters']=params
 if body:operation['requestBody']={'required':True,'content':{'application/json':{'schema':schema(body)}}}
 paths.setdefault(path,{})[method]=operation
spec={'openapi':'3.1.0','info':{'title':'Aegis scoped research API','version':'0.1.0-alpha.1','description':'Implemented provisioned read-only repositories and bundled test_lab surface only. This is not the complete v4 API catalogue.'},'servers':[{'url':'http://127.0.0.1:7410/api/v1'}],'paths':paths,'components':{'securitySchemes':{'ownerSession':{'type':'apiKey','in':'cookie','name':'aegis_session'}},'schemas':{p.stem:{'$ref':'schemas/'+p.name} for p in sorted((root/'contracts/schemas').glob('*.json'))}}}
(root/'contracts/openapi-research.json').write_text(json.dumps(spec,indent=2)+'\n')
# Clients are generated from the written OpenAPI operations, not separately maintained methods.
spec=json.loads((root/'contracts/openapi-research.json').read_text())
operations=[]
for path,methods in spec['paths'].items():
 for method,op in methods.items():
  body=op.get('requestBody',{}).get('content',{}).get('application/json',{}).get('schema',{}).get('$ref','').split('/')[-1] or None
  response=next(v for k,v in op['responses'].items() if k.isdigit())['content']['application/json']['schema']['$ref'].split('/')[-1]
  operations.append((op['operationId'],method,path,body,response,any(p['name']=='Idempotency-Key' for p in op.get('parameters',[]))))
# TypeScript uses the console's authenticated, CSRF-aware, same-origin transport.
names=sorted({t for _,_,_,body,result,_ in operations for t in [body,result] if t})
ts=['// Generated from contracts/openapi-research.json; do not edit.','import {api} from "../client";','import type {'+', '.join(names)+'} from "./contracts";']
py=['# Generated from contracts/openapi-research.json; do not edit.','from __future__ import annotations','import json, urllib.request, urllib.error, urllib.parse','from .contracts import *',
'''class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
class ResearchClient:
    def __init__(self, base_url="http://127.0.0.1:7410/api/v1", session_cookie="", csrf_token=""):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost", "::1") or parsed.path.rstrip("/") != "/api/v1" or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("Only explicit loopback administration URLs are supported")
        self.base_url = base_url.rstrip("/")
        self._cookie, self._csrf = session_cookie, csrf_token
        self._http = urllib.request.build_opener(_NoRedirect())
    def _request(self, method, path, body=None, key=None):
        headers = {"Content-Type":"application/json", "Cookie":"aegis_session="+self._cookie, "X-CSRF-Token":self._csrf}
        if key is not None: headers["Idempotency-Key"] = key
        req = urllib.request.Request(self.base_url+path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
        try:
            with self._http.open(req, timeout=15) as response:
                raw=response.read(65537)
                if len(raw)>65536: raise ValueError("Response exceeds bounded size")
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            raise RuntimeError("Aegis API rejected request with HTTP "+str(e.code)) from None
''']
go=['// Generated from contracts/openapi-research.json; DO NOT EDIT.','package contracts',
'''import("bytes";"context";"encoding/json";"fmt";"io";"net/http";"net/url";"strings";"time")
type ResearchClient struct {base string; cookie string; csrf string; http *http.Client}
func NewResearchClient(base,session,csrf string)(*ResearchClient,error){
 u,e:=url.Parse(base);if e!=nil{return nil,e}
 host:=u.Hostname();if (u.Scheme!="http"&&u.Scheme!="https") || (host!="127.0.0.1"&&host!="localhost"&&host!="::1") || strings.TrimRight(u.Path,"/")!="/api/v1" || u.RawQuery!="" || u.Fragment!="" || u.User!=nil{return nil,fmt.Errorf("only explicit loopback administration URLs supported")}
 return &ResearchClient{strings.TrimRight(base,"/"),session,csrf,&http.Client{Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}},nil
}
func(c *ResearchClient)request(ctx context.Context,method,path,key string,body,out any)error {
 var raw []byte;var e error;if body!=nil{raw,e=json.Marshal(body);if e!=nil{return e}}
 req,e:=http.NewRequestWithContext(ctx,method,c.base+path,bytes.NewReader(raw));if e!=nil{return e}
 req.Header.Set("Content-Type","application/json");req.Header.Set("Cookie","aegis_session="+c.cookie);req.Header.Set("X-CSRF-Token",c.csrf);if key!=""{req.Header.Set("Idempotency-Key",key)}
 resp,e:=c.http.Do(req);if e!=nil{return fmt.Errorf("Aegis API unavailable")};defer resp.Body.Close()
 if resp.StatusCode<200||resp.StatusCode>=300{return fmt.Errorf("Aegis API rejected request with HTTP %d",resp.StatusCode)}
 b,e:=io.ReadAll(io.LimitReader(resp.Body,65537));if e!=nil||len(b)>65536{return fmt.Errorf("response exceeds bounded size")}
 dec:=json.NewDecoder(bytes.NewReader(b));dec.DisallowUnknownFields();if e=dec.Decode(out);e!=nil{return e};var extra any;if dec.Decode(&extra)!=io.EOF{return fmt.Errorf("trailing response data")};return nil
}
''']
for name,method,path,body,result,key in operations:
 params=[];gop=[];pyp=[]
 if '{id}' in path:params.append('id: string');gop.append('id string');pyp.append('id: str')
 if body:params.append('body: '+body);gop.append('body '+body);pyp.append('body: '+body)
 if key:params.append('idempotencyKey: string');gop.append('idempotencyKey string');pyp.append('idempotency_key: str')
 tspath='`'+path.replace('{id}','${encodeURIComponent(id)}')+'`'
 ts.append('export function '+name+'('+', '.join(params)+'): Promise<'+result+'> { return api<'+result+'>('+tspath+(', body' if body else '')+(', {"Idempotency-Key":idempotencyKey}' if key else '')+'); }')
 gopath='"'+path+'"' if '{id}' not in path else '"'+path.replace('{id}','"+url.PathEscape(id)+"')+'"'
 go.append('func(c *ResearchClient)'+name[0].upper()+name[1:]+'(ctx context.Context'+(', '+', '.join(gop) if gop else '')+')('+result+',error){var out '+result+';e:=c.request(ctx,"'+method.upper()+'",'+gopath+','+('idempotencyKey' if key else '""')+','+('body' if body else 'nil')+',&out);return out,e}')
 pypath='"'+path+'"' if '{id}' not in path else '"'+path.replace('{id}','"+urllib.parse.quote(id,safe="")+"')+'"'
 py.append('    def '+name+'(self'+(', '+', '.join(pyp) if pyp else '')+') -> '+result+':\n        return self._request("'+method.upper()+'", '+pypath+(', body' if body else ', None')+(', idempotency_key' if key else '')+')')
(root/'console/src/generated/research-client.ts').write_text('\n'.join(ts)+'\n')
(root/'contracts/generated/research_client.py').write_text('\n'.join(py)+'\n')
(root/'contracts/generated/research_client.go').write_text('\n'.join(go)+'\n')
(root/'contracts/generated/__init__.py').write_text('')

subprocess.run(["gofmt","-w",str(root/"contracts/generated/research_client.go")],check=True)
