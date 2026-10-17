// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineprofile"
	"aegis.local/alpha/enginetls"
	"aegis.local/source"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const engineAPIVersion = "1.55"

var errEngine = errors.New("tracked scanner engine operation unconfirmed")

type responseCapture struct {
	mu                  sync.Mutex
	operation, id, name string
	status              int
	complete            bool
	failed              bool
	payload             []byte
}
type captureKey struct{}
type boundedEngineBody struct {
	body      io.ReadCloser
	remaining int64
	capture   *responseCapture
	used      int64
	closed    bool
}

func (b *boundedEngineBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errEngine
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, e := b.body.Read(p)
	b.remaining -= int64(n)
	b.used += int64(n)
	if b.capture != nil {
		b.capture.mu.Lock()
		if (b.capture.operation == "create" || b.capture.operation == "info" || b.capture.operation == "image") && b.used <= 65536 {
			b.capture.payload = append(b.capture.payload, p[:n]...)
		}
		if b.used > 65536 || e != nil && e != io.EOF {
			b.capture.failed = true
		}
		b.capture.mu.Unlock()
	}
	if b.used > 65536 {
		return n, errEngine
	}
	if b.remaining < 1 && e != io.EOF {
		return n, errEngine
	}
	if e == io.EOF && b.capture != nil {
		b.capture.mu.Lock()
		b.capture.complete = true
		b.capture.mu.Unlock()
	}
	return n, e
}
func (b *boundedEngineBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	// The request context bounds this drain. An oversized/truncated/cancelled
	// response never becomes a completed response merely because Close ran.
	_, _ = io.Copy(io.Discard, b)
	return b.body.Close()
}
func engineHooks(nameValue string, idValue *string) (client.RequestHook, client.ResponseHook) {
	request := func(r *http.Request) error {
		base := "/v" + engineAPIVersion + "/containers/"
		path := r.URL.Path
		c, _ := r.Context().Value(captureKey{}).(*responseCapture)
		if c != nil {
			good := false
			switch c.operation {
			case "create":
				good = r.Method == "POST" && path == base+"create" && r.URL.Query().Get("name") == nameValue
			case "start":
				good = r.Method == "POST" && path == base+c.id+"/start" && c.id == *idValue
			case "remove":
				good = r.Method == "DELETE" && path == base+c.id && c.id == *idValue && r.URL.Query().Get("force") == "1" && r.URL.Query().Get("v") == "1"
			}
			if !good {
				return errEngine
			}
			return nil
		}
		if *idValue != "" && r.Method == "POST" && (path == base+*idValue+"/attach" || path == base+*idValue+"/wait") {
			return nil
		}
		if r.Method == "GET" && path == base+"json" && r.URL.Query().Get("all") == "1" {
			var filters client.Filters
			if json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters) == nil && len(filters) == 1 && len(filters["name"]) == 1 && filters["name"]["^/"+nameValue+"$"] {
				return nil
			}
		}
		return errEngine
	}
	response := func(r *http.Response) {
		if r.StatusCode == 101 {
			return
		}
		var c *responseCapture
		if r.Request != nil {
			c, _ = r.Request.Context().Value(captureKey{}).(*responseCapture)
		}
		if c != nil {
			c.mu.Lock()
			c.status = r.StatusCode
			if r.ContentLength == 0 {
				c.complete = true
			}
			c.mu.Unlock()
		}
		r.Body = &boundedEngineBody{body: r.Body, remaining: 65537, capture: c}
	}
	return request, response
}
func observed(c *responseCapture, status int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status == status && c.complete && !c.failed
}
func observedCreate(c *responseCapture, id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var response struct {
		ID string `json:"Id"`
	}
	return c.status == 201 && c.complete && !c.failed && json.Unmarshal(c.payload, &response) == nil && response.ID == id
}

type engineTransport struct {
	base     *http.Transport
	request  client.RequestHook
	response client.ResponseHook
	identity *enginetls.Identity
}

func (t *engineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.identity != nil && t.identity.Check() != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, errEngine
	}
	if e := t.request(r); e != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, e
	}
	response, e := t.base.RoundTrip(r)
	if e == nil {
		t.response(response)
	}
	return response, e
}

type scannerEngineClient struct {
	*client.Client
	http      *http.Client
	transport *http.Transport
	scheme    string
	identity  *enginetls.Identity
}

func (c *scannerEngineClient) Close() error {
	c.transport.CloseIdleConnections()
	return c.Client.Close()
}

// Use the ordinary HTTP transport's bounded upgrade support for attach. The
// SDK's raw-hijack fallback does not retain our context-aware custom transport.
func (c *scannerEngineClient) attach(ctx context.Context, id string) (io.ReadCloser, error) {
	r, e := http.NewRequestWithContext(ctx, "POST", c.scheme+"://docker/v"+engineAPIVersion+"/containers/"+id+"/attach?stderr=1&stdout=1&stream=1", nil)
	if e != nil {
		return nil, errEngine
	}
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "tcp")
	response, e := c.http.Do(r)
	if e != nil {
		return nil, errEngine
	}
	if response.StatusCode != 101 || !strings.EqualFold(response.Header.Get("Upgrade"), "tcp") {
		response.Body.Close()
		return nil, errEngine
	}
	return response.Body, nil
}
func newEngineSDK(endpoint, nameValue string, idValue *string) (*scannerEngineClient, error) {
	req, resp := engineHooks(nameValue, idValue)
	return newRestrictedEngineSDK(endpoint, req, resp)
}
func newRestrictedEngineSDK(endpoint string, req client.RequestHook, resp client.ResponseHook) (*scannerEngineClient, error) {
	raw, e := localEndpoint(endpoint)
	if e != nil {
		return nil, errEngine
	}
	u, _ := url.Parse(raw)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{Protocols: protocols, Proxy: nil, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 65536, DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", u.Path)
	}}
	scheme := "http"
	var identity *enginetls.Identity
	if directory := os.Getenv("AEGIS_SCANNER_ENGINE_TLS_DIR"); directory != "" {
		identity, e = enginetls.Load(directory, enginetls.Broker)
		if e != nil {
			return nil, errEngine
		}
		tr.TLSClientConfig = identity.TLS
		scheme = "https"
		tr.TLSHandshakeTimeout = 3 * time.Second
	}
	hc := &http.Client{Transport: &engineTransport{base: tr, request: req, response: resp, identity: identity}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sdk, e := client.New(client.WithHost(raw), client.WithHTTPClient(hc), client.WithScheme(scheme), client.WithAPIVersion(engineAPIVersion), client.WithUserAgent("aegis-scanner-tracked/1"))
	if e != nil {
		tr.CloseIdleConnections()
		return nil, e
	}
	return &scannerEngineClient{Client: sdk, http: hc, transport: tr, scheme: scheme, identity: identity}, nil
}
func copyEngineStreams(r io.Reader, stdout, stderr io.Writer) error {
	header := make([]byte, 8)
	for frames := 0; frames < 65536; frames++ {
		n, e := io.ReadFull(r, header)
		if e == io.EOF && n == 0 {
			return nil
		}
		if e != nil {
			return errEngine
		}
		size := int64(binary.BigEndian.Uint32(header[4:]))
		if header[1] != 0 || header[2] != 0 || header[3] != 0 || size > 8<<20 {
			return errEngine
		}
		var out io.Writer
		switch header[0] {
		case 1:
			out = stdout
		case 2:
			out = stderr
		default:
			return errEngine
		}
		if _, e = io.CopyN(out, r, size); e != nil {
			return errEngine
		}
	}
	return errEngine
}

type sdkOutcome struct {
	exit     int
	duration int64
	cleanup  bool
	err      error
}

func sdkCreateOptions(tool Tool, nameValue, sourceDir, rulesDir, guardDir string, seconds int, deadline time.Time, db *engineprofile.Database) client.ContainerCreateOptions {
	p := engineprofile.CreateWithDatabase(tool.ID, tool.Image, nameValue, sourceDir, rulesDir, guardDir, seconds, deadline, os.Geteuid(), os.Getegid(), os.Getpid(), db)
	return client.ContainerCreateOptions{Name: nameValue, Config: p.Config, HostConfig: p.HostConfig}
}
func (c Config) runEngineSDK(runCtx context.Context, endpoint, engine, nameValue string, options client.ContainerCreateOptions, stdout, stderr io.Writer, cancelRun context.CancelFunc) (out sdkOutcome) {
	defer func() {
		if !out.cleanup && out.err == nil {
			out.err = errEngine
		}
	}()
	if !filepath.IsAbs(c.EngineJournalRoot) || filepath.Clean(c.EngineJournalRoot) != c.EngineJournalRoot {
		out.exit = -1
		out.err = errEngine
		return
	}
	if c.ScratchParent != "" {
		rel, e := filepath.Rel(c.ScratchParent, c.EngineJournalRoot)
		if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			out.exit = -1
			out.err = errEngine
			return
		}
	}
	out.exit = -1
	out.err = errEngine
	open := enginejournal.Open
	if c.ExpectedJournalNamespace != "" || c.ExpectedJournalRootDigest != "" {
		if !observationHash.MatchString(c.ExpectedJournalNamespace) || c.ExpectedJournalRootDigest != source.Hash([]byte("aegis-scanner-engine-journal-root-v1\n"+c.EngineJournalRoot+"\n"+strconv.Itoa(os.Geteuid()))) {
			return
		}
		open = enginejournal.OpenExisting
	}
	j, e := open(c.EngineJournalRoot, engine)
	if e != nil {
		out.err = e
		return
	}
	defer j.Close()
	if c.ExpectedJournalNamespace != "" && j.Observe().Namespace != c.ExpectedJournalNamespace {
		return
	}
	var containerID string
	cli, e := newEngineSDK(endpoint, nameValue, &containerID)
	if e != nil {
		return
	}
	defer cli.Close()
	if cli.identity != nil {
		if c.engineTLSIdentity == "" || cli.identity.Digest != c.engineTLSIdentity || options.HostConfig == nil {
			return
		}
		options.HostConfig.AutoRemove = false
	} else if c.engineTLSIdentity != "" {
		return
	}
	descriptor, _ := json.Marshal(options)
	attempt, e := j.Begin(nameValue, source.Hash(descriptor))
	if e != nil {
		out.err = e
		return
	}
	ticket, e := attempt.Begin("create", "")
	if e != nil {
		out.err = e
		return
	}
	create := &responseCapture{operation: "create", name: nameValue}
	ctx, cancel := context.WithTimeout(context.WithValue(runCtx, captureKey{}, create), 5*time.Second)
	created, e := cli.ContainerCreate(ctx, options)
	cancel()
	if e != nil || !observationID.MatchString(created.ID) || !observedCreate(create, created.ID) {
		return
	}
	containerID = created.ID
	if ticket.Confirm(201, containerID) != nil {
		return
	}
	// From here a known, settled create can be cleaned up by exact ID even if
	// setup failed. A later unresolved start keeps cleanup unconfirmed.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if out.exit >= 0 && (options.HostConfig == nil || options.HostConfig.AutoRemove) {
			// AutoRemove is asynchronous after next-exit. Observe its completion
			// before sending DELETE, which otherwise races it and returns 409.
			// This is a read; it cannot settle an unanswered mutation intent.
			removed := cli.ContainerWait(cleanupCtx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionRemoved})
			select {
			case <-removed.Result:
			case <-removed.Error:
			}
			if cleanupCtx.Err() != nil {
				return
			}
		}
		ticket, e := attempt.Begin("remove", containerID)
		if e != nil {
			return
		}
		cap := &responseCapture{operation: "remove", id: containerID}
		ctx := context.WithValue(cleanupCtx, captureKey{}, cap)
		_, removeErr := cli.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
		status := 204
		if observed(cap, 404) && cli.identity == nil {
			status = 404
		} else if removeErr != nil || !observed(cap, 204) {
			cap.mu.Lock()
			out.err = fmt.Errorf("tracked scanner remove response unconfirmed (status=%d complete=%t)", cap.status, cap.complete && !cap.failed)
			cap.mu.Unlock()
			return
		}
		if ticket.Confirm(status, containerID) != nil {
			return
		}
		remaining, e := cli.ContainerList(cleanupCtx, client.ContainerListOptions{All: true, Filters: client.Filters{"name": {"^/" + nameValue + "$": true}}})
		if e != nil || len(remaining.Items) != 0 {
			return
		}
		if attempt.Finish() != nil {
			return
		}
		out.cleanup = true
	}()
	if len(created.Warnings) != 0 {
		return
	}
	attached, e := cli.attach(runCtx, containerID)
	if e != nil {
		return
	}
	stopClose := context.AfterFunc(runCtx, func() { attached.Close() })
	defer func() { stopClose(); attached.Close() }()
	streamDone := make(chan error, 1)
	go func() {
		e := copyEngineStreams(attached, stdout, stderr)
		if e != nil {
			cancelRun()
		}
		streamDone <- e
	}()
	defer func() { attached.Close(); <-streamDone }()
	waitCtx, waitCancel := context.WithCancel(runCtx)
	defer waitCancel()
	wait := cli.ContainerWait(waitCtx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	// A failed registration returns an already-buffered error. Do not start a
	// container when the daemon never acknowledged the next-exit waiter.
	select {
	case <-wait.Error:
		return
	default:
	}
	type waited struct {
		status int
		err    error
	}
	waitDone := make(chan waited, 1)
	go func() {
		select {
		case r := <-wait.Result:
			if r.Error != nil {
				waitDone <- waited{err: errEngine}
			} else {
				waitDone <- waited{status: int(r.StatusCode)}
			}
		case e := <-wait.Error:
			waitDone <- waited{err: e}
		}
	}()
	// The receiver remains present after cancellation, so the SDK's unbuffered
	// result channel cannot strand a completed waiter.
	joined := false
	defer func() {
		waitCancel()
		if !joined {
			<-waitDone
		}
	}()
	if runCtx.Err() != nil {
		return
	}
	ticket, e = attempt.Begin("start", containerID)
	if e != nil {
		out.err = e
		return
	}
	start := &responseCapture{operation: "start", id: containerID}
	ctx, startCancel := context.WithTimeout(context.WithValue(runCtx, captureKey{}, start), 5*time.Second)
	started := time.Now()
	_, e = cli.ContainerStart(ctx, containerID, client.ContainerStartOptions{})
	startCancel()
	if e != nil || !observed(start, 204) {
		return
	}
	if ticket.Confirm(204, containerID) != nil {
		return
	}
	var result waited
	select {
	case result = <-waitDone:
		joined = true
	case <-runCtx.Done():
		out.duration = time.Since(started).Milliseconds()
		return
	}
	out.duration = time.Since(started).Milliseconds()
	if result.err != nil || result.status < 0 || result.status > 255 {
		return
	}
	out.exit = result.status
	// EOF must arrive while the guarded request still has time to finish. Closing
	// the attachment on cancellation ensures the receiver is always joined.
	select {
	case e = <-streamDone:
		streamDone <- e
	case <-runCtx.Done():
		return
	}
	if e != nil {
		return
	}
	out.err = nil
	return
}

// RemoveRepaired sends exactly one DELETE for a crash-repaired allocation
// through the dedicated TLS engine as the broker (ADR 057). The quarantined
// plugin admits it against the controller's retained repair, or refuses; this
// client retries nothing and reports success only for a complete 204.
func RemoveRepaired(ctx context.Context, name, id string) error {
	if os.Getenv("AEGIS_SCANNER_ENGINE_TLS_DIR") == "" || !scannerName.MatchString(name) || !observationID.MatchString(id) {
		return errEngine
	}
	_, endpoint, e := Config{}.engine(ctx)
	if e != nil {
		return errEngine
	}
	target := id
	cli, e := newEngineSDK(endpoint, name, &target)
	if e != nil {
		return errEngine
	}
	defer cli.Close()
	if cli.identity == nil {
		return errEngine
	}
	capture := &responseCapture{operation: "remove", id: id}
	bounded, cancel := context.WithTimeout(context.WithValue(ctx, captureKey{}, capture), 10*time.Second)
	defer cancel()
	if _, e = cli.ContainerRemove(bounded, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); e != nil || !observed(capture, 204) {
		return errEngine
	}
	return nil
}
