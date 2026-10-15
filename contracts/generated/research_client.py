# Generated from contracts/openapi-research.json; do not edit.
from __future__ import annotations
import json, urllib.request, urllib.error, urllib.parse
from .contracts import *
class _NoRedirect(urllib.request.HTTPRedirectHandler):
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
                raw=response.read(131073)
                if len(raw)>131072: raise ValueError("Response exceeds bounded size")
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            raise RuntimeError("Aegis API rejected request with HTTP "+str(e.code)) from None

    def listFindingCatalogue(self, query: FindingCatalogueQueryV1) -> FindingCataloguePageV1:
        return self._request("GET", "/findings/catalogue" + "?" + urllib.parse.urlencode(query), None)
    def getFindingTriageHistory(self, query: FindingTriageHistoryQueryV1, id: str) -> FindingTriageHistoryV1:
        return self._request("GET", "/scans/"+urllib.parse.quote(id,safe="")+"/finding-triage-history" + "?" + urllib.parse.urlencode(query), None)
    def getFindingTriage(self, query: FindingTriageQueryV1, id: str) -> FindingTriageRecordV1:
        return self._request("GET", "/scans/"+urllib.parse.quote(id,safe="")+"/finding-triage" + "?" + urllib.parse.urlencode(query), None)
    def setFindingTriage(self, id: str, body: FindingTriageInputV1, idempotency_key: str) -> FindingTriageRecordV1:
        return self._request("POST", "/scans/"+urllib.parse.quote(id,safe="")+"/finding-triage", body, idempotency_key)
    def listFindings(self, query: FindingQueryV1) -> FindingPageV1:
        return self._request("GET", "/findings" + "?" + urllib.parse.urlencode(query), None)
    def createScan(self, body: ScannerJobInputV1, idempotency_key: str) -> ScannerJobV1:
        return self._request("POST", "/scans", body, idempotency_key)
    def listScans(self) -> ScannerJobListV1:
        return self._request("GET", "/scans", None)
    def getScan(self, id: str) -> ScannerJobStatusV1:
        return self._request("GET", "/scans/"+urllib.parse.quote(id,safe="")+"", None)
    def cancelScan(self, id: str, body: EmptyObjectV1) -> ScannerJobStatusV1:
        return self._request("POST", "/scans/"+urllib.parse.quote(id,safe="")+"/cancel", body)
    def getScanResult(self, id: str) -> ScannerSuiteResultV1:
        return self._request("GET", "/scans/"+urllib.parse.quote(id,safe="")+"/result", None)
    def connectRepository(self, body: RepositoryConnectionRequestV1) -> RepositoryV1:
        return self._request("POST", "/repos", body)
    def listRepositories(self) -> RepositoryListV1:
        return self._request("GET", "/repos", None)
    def listRepositoryAssets(self) -> RepositoryAssetListV1:
        return self._request("GET", "/repos/assets", None)
    def getRepository(self, id: str) -> RepositoryV1:
        return self._request("GET", "/repos/"+urllib.parse.quote(id,safe="")+"", None)
    def getApplicationMap(self, id: str) -> ApplicationMapV1:
        return self._request("GET", "/repos/"+urllib.parse.quote(id,safe="")+"/map", None)
    def createScopeGrant(self, body: ScopeGrantDraftRequestV1) -> ScopeGrantRecordV1:
        return self._request("POST", "/scope-grants", body)
    def listScopeGrants(self) -> ScopeGrantListV1:
        return self._request("GET", "/scope-grants", None)
    def getScopeGrant(self, id: str) -> ScopeGrantRecordV1:
        return self._request("GET", "/scope-grants/"+urllib.parse.quote(id,safe="")+"", None)
    def approveScopeGrant(self, id: str, body: ScopeGrantApprovalRequestV1) -> ScopeGrantRecordV1:
        return self._request("POST", "/scope-grants/"+urllib.parse.quote(id,safe="")+"/approve", body)
    def revokeScopeGrant(self, id: str, body: EmptyObjectV1) -> ScopeRevocationReceiptV1:
        return self._request("POST", "/scope-grants/"+urllib.parse.quote(id,safe="")+"/revoke", body)
    def createVerification(self, body: VerificationJobInputV1, idempotency_key: str) -> ResearchJobV1:
        return self._request("POST", "/verifications", body, idempotency_key)
    def listVerifications(self) -> ResearchJobListV1:
        return self._request("GET", "/verifications", None)
    def getVerification(self, id: str) -> ResearchJobV1:
        return self._request("GET", "/verifications/"+urllib.parse.quote(id,safe="")+"", None)
    def cancelVerification(self, id: str, body: EmptyObjectV1) -> ResearchJobV1:
        return self._request("POST", "/verifications/"+urllib.parse.quote(id,safe="")+"/cancel", body)
    def getVerificationReport(self, id: str) -> VerificationReportV1:
        return self._request("GET", "/verify/reports/"+urllib.parse.quote(id,safe="")+"", None)
