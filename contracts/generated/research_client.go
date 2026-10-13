// Generated from contracts/openapi-research.json; DO NOT EDIT.
package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ResearchClient struct {
	base   string
	cookie string
	csrf   string
	http   *http.Client
}

func NewResearchClient(base, session, csrf string) (*ResearchClient, error) {
	u, e := url.Parse(base)
	if e != nil {
		return nil, e
	}
	host := u.Hostname()
	if (u.Scheme != "http" && u.Scheme != "https") || (host != "127.0.0.1" && host != "localhost" && host != "::1") || strings.TrimRight(u.Path, "/") != "/api/v1" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("only explicit loopback administration URLs supported")
	}
	return &ResearchClient{strings.TrimRight(base, "/"), session, csrf, &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *ResearchClient) request(ctx context.Context, method, path, key string, body, out any) error {
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "aegis_session="+c.cookie)
	req.Header.Set("X-CSRF-Token", c.csrf)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return fmt.Errorf("Aegis API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Aegis API rejected request with HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(b) > 65536 {
		return fmt.Errorf("response exceeds bounded size")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(out); e != nil {
		return e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing response data")
	}
	return nil
}

func (c *ResearchClient) ConnectRepository(ctx context.Context, body RepositoryConnectionRequestV1) (RepositoryV1, error) {
	var out RepositoryV1
	e := c.request(ctx, "POST", "/repos", "", body, &out)
	return out, e
}
func (c *ResearchClient) ListRepositories(ctx context.Context) (RepositoryListV1, error) {
	var out RepositoryListV1
	e := c.request(ctx, "GET", "/repos", "", nil, &out)
	return out, e
}
func (c *ResearchClient) ListRepositoryAssets(ctx context.Context) (RepositoryAssetListV1, error) {
	var out RepositoryAssetListV1
	e := c.request(ctx, "GET", "/repos/assets", "", nil, &out)
	return out, e
}
func (c *ResearchClient) GetRepository(ctx context.Context, id string) (RepositoryV1, error) {
	var out RepositoryV1
	e := c.request(ctx, "GET", "/repos/"+url.PathEscape(id)+"", "", nil, &out)
	return out, e
}
func (c *ResearchClient) GetApplicationMap(ctx context.Context, id string) (ApplicationMapV1, error) {
	var out ApplicationMapV1
	e := c.request(ctx, "GET", "/repos/"+url.PathEscape(id)+"/map", "", nil, &out)
	return out, e
}
func (c *ResearchClient) CreateScopeGrant(ctx context.Context, body ScopeGrantDraftRequestV1) (ScopeGrantRecordV1, error) {
	var out ScopeGrantRecordV1
	e := c.request(ctx, "POST", "/scope-grants", "", body, &out)
	return out, e
}
func (c *ResearchClient) ListScopeGrants(ctx context.Context) (ScopeGrantListV1, error) {
	var out ScopeGrantListV1
	e := c.request(ctx, "GET", "/scope-grants", "", nil, &out)
	return out, e
}
func (c *ResearchClient) GetScopeGrant(ctx context.Context, id string) (ScopeGrantRecordV1, error) {
	var out ScopeGrantRecordV1
	e := c.request(ctx, "GET", "/scope-grants/"+url.PathEscape(id)+"", "", nil, &out)
	return out, e
}
func (c *ResearchClient) ApproveScopeGrant(ctx context.Context, id string, body ScopeGrantApprovalRequestV1) (ScopeGrantRecordV1, error) {
	var out ScopeGrantRecordV1
	e := c.request(ctx, "POST", "/scope-grants/"+url.PathEscape(id)+"/approve", "", body, &out)
	return out, e
}
func (c *ResearchClient) RevokeScopeGrant(ctx context.Context, id string, body EmptyObjectV1) (ScopeRevocationReceiptV1, error) {
	var out ScopeRevocationReceiptV1
	e := c.request(ctx, "POST", "/scope-grants/"+url.PathEscape(id)+"/revoke", "", body, &out)
	return out, e
}
func (c *ResearchClient) CreateVerification(ctx context.Context, body VerificationJobInputV1, idempotencyKey string) (ResearchJobV1, error) {
	var out ResearchJobV1
	e := c.request(ctx, "POST", "/verifications", idempotencyKey, body, &out)
	return out, e
}
func (c *ResearchClient) ListVerifications(ctx context.Context) (ResearchJobListV1, error) {
	var out ResearchJobListV1
	e := c.request(ctx, "GET", "/verifications", "", nil, &out)
	return out, e
}
func (c *ResearchClient) GetVerification(ctx context.Context, id string) (ResearchJobV1, error) {
	var out ResearchJobV1
	e := c.request(ctx, "GET", "/verifications/"+url.PathEscape(id)+"", "", nil, &out)
	return out, e
}
func (c *ResearchClient) CancelVerification(ctx context.Context, id string, body EmptyObjectV1) (ResearchJobV1, error) {
	var out ResearchJobV1
	e := c.request(ctx, "POST", "/verifications/"+url.PathEscape(id)+"/cancel", "", body, &out)
	return out, e
}
func (c *ResearchClient) GetVerificationReport(ctx context.Context, id string) (VerificationReportV1, error) {
	var out VerificationReportV1
	e := c.request(ctx, "GET", "/verify/reports/"+url.PathEscape(id)+"", "", nil, &out)
	return out, e
}
