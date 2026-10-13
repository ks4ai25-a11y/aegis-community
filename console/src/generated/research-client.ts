// Generated from contracts/openapi-research.json; do not edit.
import {api} from "../client";
import type {ApplicationMapV1, EmptyObjectV1, RepositoryAssetListV1, RepositoryConnectionRequestV1, RepositoryListV1, RepositoryV1, ResearchJobListV1, ResearchJobV1, ScopeGrantApprovalRequestV1, ScopeGrantDraftRequestV1, ScopeGrantListV1, ScopeGrantRecordV1, ScopeRevocationReceiptV1, VerificationJobInputV1, VerificationReportV1} from "./contracts";
export function connectRepository(body: RepositoryConnectionRequestV1): Promise<RepositoryV1> { return api<RepositoryV1>(`/repos`, body); }
export function listRepositories(): Promise<RepositoryListV1> { return api<RepositoryListV1>(`/repos`); }
export function listRepositoryAssets(): Promise<RepositoryAssetListV1> { return api<RepositoryAssetListV1>(`/repos/assets`); }
export function getRepository(id: string): Promise<RepositoryV1> { return api<RepositoryV1>(`/repos/${encodeURIComponent(id)}`); }
export function getApplicationMap(id: string): Promise<ApplicationMapV1> { return api<ApplicationMapV1>(`/repos/${encodeURIComponent(id)}/map`); }
export function createScopeGrant(body: ScopeGrantDraftRequestV1): Promise<ScopeGrantRecordV1> { return api<ScopeGrantRecordV1>(`/scope-grants`, body); }
export function listScopeGrants(): Promise<ScopeGrantListV1> { return api<ScopeGrantListV1>(`/scope-grants`); }
export function getScopeGrant(id: string): Promise<ScopeGrantRecordV1> { return api<ScopeGrantRecordV1>(`/scope-grants/${encodeURIComponent(id)}`); }
export function approveScopeGrant(id: string, body: ScopeGrantApprovalRequestV1): Promise<ScopeGrantRecordV1> { return api<ScopeGrantRecordV1>(`/scope-grants/${encodeURIComponent(id)}/approve`, body); }
export function revokeScopeGrant(id: string, body: EmptyObjectV1): Promise<ScopeRevocationReceiptV1> { return api<ScopeRevocationReceiptV1>(`/scope-grants/${encodeURIComponent(id)}/revoke`, body); }
export function createVerification(body: VerificationJobInputV1, idempotencyKey: string): Promise<ResearchJobV1> { return api<ResearchJobV1>(`/verifications`, body, {"Idempotency-Key":idempotencyKey}); }
export function listVerifications(): Promise<ResearchJobListV1> { return api<ResearchJobListV1>(`/verifications`); }
export function getVerification(id: string): Promise<ResearchJobV1> { return api<ResearchJobV1>(`/verifications/${encodeURIComponent(id)}`); }
export function cancelVerification(id: string, body: EmptyObjectV1): Promise<ResearchJobV1> { return api<ResearchJobV1>(`/verifications/${encodeURIComponent(id)}/cancel`, body); }
export function getVerificationReport(id: string): Promise<VerificationReportV1> { return api<VerificationReportV1>(`/verify/reports/${encodeURIComponent(id)}`); }
