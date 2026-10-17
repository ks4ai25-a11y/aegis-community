// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"net/url"
	"testing"
)

const otherID = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func (w WriteProbe) request(user string) Request {
	uri := w.URI
	if !w.Raw {
		uri = api + uri
	}
	r := Request{User: user, UserAuthNMethod: "TLS", RequestPeerCertificates: nativeTestPeer(user), RequestMethod: w.Method, RequestURI: uri}
	if w.Body != "" {
		r.RequestBody = []byte(w.Body)
	}
	if w.ContentType != "" {
		r.RequestHeaders = map[string]string{"Content-Type": w.ContentType}
	}
	return r
}

// refusesSurface asserts every write probe, from every principal, is refused
// on both request and forged response callbacks, and that no refusal changes
// the plugin journal or the in-memory pending ticket.
func refusesSurface(t *testing.T, p *Policy) {
	t.Helper()
	before := p.Observation()
	pending, operation := p.pending, p.operation
	for _, w := range WriteSurface(testID, otherID, testName, testImage) {
		for _, user := range []string{Broker, Observer, "aegis-engine-admin", ""} {
			r := w.request(user)
			if d := p.AuthorizeRequest(r); d.Allow {
				t.Fatalf("%s %s %s by %q admitted", w.Class, w.Method, w.URI, user)
			}
			for _, status := range []int{200, 201, 204} {
				r.ResponseStatusCode = status
				r.ResponseBody = []byte(`{"Id":"` + otherID + `","Warnings":[]}`)
				if d := p.AuthorizeResponse(r); d.Allow {
					t.Fatalf("%s %s %s response by %q accepted", w.Class, w.Method, w.URI, user)
				}
			}
		}
	}
	if after := p.Observation(); after != before || p.pending != pending || p.operation != operation {
		t.Fatalf("refused writes changed plugin state: %+v -> %+v", before, after)
	}
}

func TestEveryUnadmittedWriteIsRefusedInEveryLifecycleState(t *testing.T) {
	p, _, r := fixture(t)
	start := call("POST", "/containers/"+testID+"/start")
	remove := call("DELETE", "/containers/"+testID+"?force=1&v=1")
	t.Run("before-create", func(t *testing.T) { refusesSurface(t, p) })
	must(t, p.AuthorizeRequest(r), true)
	t.Run("create-pending", func(t *testing.T) { refusesSurface(t, p) })
	r.ResponseStatusCode = 201
	r.ResponseBody = []byte(`{"Id":"` + testID + `","Warnings":[]}`)
	must(t, p.AuthorizeResponse(r), true)
	t.Run("created", func(t *testing.T) { refusesSurface(t, p) })
	must(t, p.AuthorizeRequest(start), true)
	t.Run("start-pending", func(t *testing.T) { refusesSurface(t, p) })
	start.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(start), true)
	t.Run("running", func(t *testing.T) { refusesSurface(t, p) })
	must(t, p.AuthorizeRequest(remove), true)
	t.Run("remove-pending", func(t *testing.T) { refusesSurface(t, p) })
	remove.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(remove), true)
	t.Run("removed", func(t *testing.T) { refusesSurface(t, p) })
	if o := p.Observation(); o.Attempts != 1 || o.Unresolved != 0 || o.Unfinished != 0 {
		t.Fatalf("admitted lifecycle did not settle exactly once: %+v", o)
	}
}

// admittedForm names the only non-GET requests the policy may allow: the three
// journalled mutations and the broker's output-only wait/attach of its own
// tracked container.
func admittedForm(r Request) string {
	u, e := url.ParseRequestURI(r.RequestURI)
	if e != nil || r.User != Broker {
		return ""
	}
	q := u.Query()
	switch {
	case r.RequestMethod == "POST" && u.Path == api+"/containers/create" && len(q) == 1 && namePattern.MatchString(q.Get("name")):
		return "create"
	case r.RequestMethod == "POST" && u.Path == api+"/containers/"+testID+"/start" && u.RawQuery == "":
		return "start"
	case r.RequestMethod == "DELETE" && u.Path == api+"/containers/"+testID && u.RawQuery == "force=1&v=1":
		return "remove"
	case r.RequestMethod == "POST" && u.Path == api+"/containers/"+testID+"/wait":
		return "wait"
	case r.RequestMethod == "POST" && u.Path == api+"/containers/"+testID+"/attach" && u.RawQuery == "stderr=1&stdout=1&stream=1":
		return "attach-output"
	}
	return ""
}

// Every method applied to every admitted, read and write URI: the only
// non-GET allows are the exact admitted forms, so the policy is default-deny
// for anything else rather than relying on an enumerated deny list.
func TestOnlyExactAdmittedFormsAreAllowedForAnyMethod(t *testing.T) {
	p, _, r := fixture(t)
	created(t, p, r)
	uris := map[string]bool{}
	for _, w := range WriteSurface(testID, otherID, testName, testImage) {
		x := w.request(Broker)
		uris[x.RequestURI] = true
	}
	for _, path := range []string{"/containers/" + testID + "/start", "/containers/" + testID + "?force=1&v=1", "/containers/" + testID + "/wait?condition=next-exit", "/containers/" + testID + "/attach?stderr=1&stdout=1&stream=1", "/containers/" + testID + "/json", "/containers/" + testName + "/json", "/info", "/images/" + testImage + "/json", "/_ping", "/version", "/events", "/containers/" + testID + "/export", "/containers/" + testID + "/logs?stdout=1", "/containers/" + testID + "/archive?path=%2F", "/images/get?names=" + testImage, "/system/df", "/distribution/" + testImage + "/json"} {
		uris[api+path] = true
	}
	allowed := map[string]int{}
	for uri := range uris {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "get", "post"} {
			for _, user := range []string{Broker, Observer} {
				x := Request{User: user, UserAuthNMethod: "TLS", RequestPeerCertificates: nativeTestPeer(user), RequestMethod: method, RequestURI: uri}
				if !p.AuthorizeRequest(x).Allow || method == "GET" {
					continue
				}
				form := admittedForm(x)
				if form == "" {
					t.Fatalf("non-admitted %s %s by %s allowed", method, uri, user)
				}
				allowed[form]++
				if form == "start" || form == "remove" {
					// Settle the ticket so the sweep continues from a clean state;
					// one admitted start is expected, nothing else may consume it.
					x.ResponseStatusCode = 204
					must(t, p.AuthorizeResponse(x), true)
				}
			}
		}
	}
	if allowed["create"] != 0 || allowed["start"] > 1 || allowed["remove"] > 1 {
		t.Fatalf("unexpected admitted mutations in sweep: %v", allowed)
	}
	for _, uri := range []string{"/containers/" + testID + "/attach/ws?stdin=1&stream=1", "/containers/" + testID + "/archive?path=%2F", "/containers/" + testID + "/export", "/_ping"} {
		if p.AuthorizeRequest(call("GET", uri)).Allow {
			t.Fatalf("GET %s allowed", uri)
		}
	}
}

// The authz envelope omits non-JSON bodies, so any admitted operation must
// either require an exact JSON body (create) or an empty one (start/remove).
func TestHiddenOrUnexpectedBodiesCannotReachAdmittedForms(t *testing.T) {
	p, _, r := fixture(t)
	hidden := r
	hidden.RequestHeaders = map[string]string{"Content-Type": "application/octet-stream"}
	must(t, p.AuthorizeRequest(hidden), false)
	hidden.RequestBody = nil
	must(t, p.AuthorizeRequest(hidden), false)
	twice := r
	twice.RequestHeaders = map[string]string{"Content-Type": "application/json", "content-type": "application/json"}
	must(t, p.AuthorizeRequest(twice), false)
	created(t, p, r)
	for _, body := range []string{"{}", `{"HostConfig":{"Privileged":true}}`, " "} {
		x := call("POST", "/containers/"+testID+"/start")
		x.RequestBody = []byte(body)
		must(t, p.AuthorizeRequest(x), false)
		x = call("DELETE", "/containers/"+testID+"?force=1&v=1")
		x.RequestBody = []byte(body)
		must(t, p.AuthorizeRequest(x), false)
	}
	if o := p.Observation(); o.Unresolved != 0 || o.Unfinished != 1 {
		t.Fatalf("refused bodies changed journal: %+v", o)
	}
}
