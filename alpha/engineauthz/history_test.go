// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"bytes"
	"strings"
	"testing"
)

func TestHistoricalObserverReadsOnlyExactRetainedAllocations(t *testing.T) {
	p, cfg, create := fixture(t)
	created(t, p, create)
	remove := call("DELETE", "/containers/"+testID+"?force=1&v=1")
	must(t, p.AuthorizeRequest(remove), true)
	remove.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(remove), true)

	secondName := "aegis-scan-" + strings.Repeat("b", 32)
	secondID := strings.Repeat("b", 64)
	second := create
	second.RequestURI = strings.ReplaceAll(create.RequestURI, testName, secondName)
	second.RequestBody = bytes.ReplaceAll(create.RequestBody, []byte(testName), []byte(secondName))
	must(t, p.AuthorizeRequest(second), true)
	second.ResponseStatusCode = 201
	second.ResponseBody = []byte(`{"Id":"` + secondID + `","Warnings":[]}`)
	must(t, p.AuthorizeResponse(second), true)

	checkHistory := func(p *Policy) {
		t.Helper()
		before := p.Observation()
		for _, exact := range []string{testID, testName, secondID, secondName} {
			x := call("GET", "/containers/"+exact+"/json")
			x.User = Observer
			x.RequestPeerCertificates = nativeTestPeer(Observer)
			must(t, p.AuthorizeRequest(x), true)
			x.ResponseStatusCode = 404
			must(t, p.AuthorizeResponse(x), true)
		}
		for _, path := range []string{"/containers/json", "/containers/" + strings.Repeat("c", 64) + "/json", "/containers/aegis-scan-" + strings.Repeat("c", 32) + "/json", "/containers/" + testID[:12] + "/json", "/containers/" + testID + "/json?all=1", "/containers/" + testID + "/json/extra"} {
			x := call("GET", path)
			x.User = Observer
			x.RequestPeerCertificates = nativeTestPeer(Observer)
			must(t, p.AuthorizeRequest(x), false)
		}
		for _, x := range []Request{call("POST", "/containers/"+testID+"/start"), call("DELETE", "/containers/"+testID+"?force=1&v=1"), call("POST", "/containers/"+testID+"/wait?condition=removed")} {
			x.User = Observer
			x.RequestPeerCertificates = nativeTestPeer(Observer)
			must(t, p.AuthorizeRequest(x), false)
		}
		if p.Observation() != before {
			t.Fatal("historical reads changed native execution state")
		}
	}
	checkHistory(p)
	for _, exact := range []string{testID, testName} {
		must(t, p.AuthorizeRequest(call("GET", "/containers/"+exact+"/json")), false)
	}
	must(t, p.AuthorizeRequest(call("GET", "/containers/"+secondID+"/json")), true)
	remove = call("DELETE", "/containers/"+secondID+"?force=1&v=1")
	must(t, p.AuthorizeRequest(remove), true)
	remove.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(remove), true)
	p.Close()
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	checkHistory(reopened)
	for _, exact := range []string{testID, testName, secondID, secondName} {
		must(t, reopened.AuthorizeRequest(call("GET", "/containers/"+exact+"/json")), false)
	}
}
