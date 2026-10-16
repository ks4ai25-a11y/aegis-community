package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEV001SanitizesBeforePersistence(t *testing.T) {
	raw := `{"logger":"http.log.access.demo","ts":1791619200,"request":{"method":"GET","uri":"/catalog?token=CANARY_SECRET","headers":{"Authorization":["Bearer CANARY_SECRET"],"Cookie":["secret=CANARY_SECRET"]}},"status":200,"resp_headers":{"X-Aegis-Request-ID":["request-1"],"X-Aegis-Revision":["sha256:abc"],"Set-Cookie":["CANARY_SECRET"]}}`
	v := Sanitize([]byte(raw))
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "CANARY_SECRET") {
		t.Fatal("secret persisted")
	}
	if v["route_template"] != "/catalog" {
		t.Fatal(v)
	}
}
func TestCorazaMatchProvenance(t *testing.T) {
	raw := `{"logger":"http.handlers.waf","ts":1791619200,"msg":"[id \"942100\"] [data \"CANARY_SECRET\"] [unique_id \"request-1\"]"}`
	v := Sanitize([]byte(raw))
	if v["rule_id"] != "942100" || v["request_id"] != "request-1" {
		t.Fatal(v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "CANARY_SECRET") {
		t.Fatal("raw match persisted")
	}
}
func TestRouteCardinality(t *testing.T) {
	for _, v := range []string{"/api/users/123", "/api/users/456"} {
		if Route(v) != "/api/users/{id}" {
			t.Fatal(Route(v))
		}
	}
}
func FuzzSanitize(f *testing.F) {
	f.Add([]byte(`{"msg":"hello"}`))
	f.Fuzz(func(t *testing.T, b []byte) { Sanitize(b) })
}

func TestPseudonymsReplaceAddressesAndPaths(t *testing.T) {
	raw := `{"logger":"http.log.access.demo","ts":1791619200,"request":{"method":"GET","uri":"/private/CANARY_PATH?x=1","client_ip":"203.0.113.77","remote_ip":"203.0.113.77"},"status":404,"resp_headers":{}}`
	v := Sanitize([]byte(raw))
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "203.0.113.77") || strings.Contains(string(b), "CANARY_PATH") {
		t.Fatal("address or raw path persisted", string(b))
	}
	client, _ := v["client_key"].(string)
	path, _ := v["path_key"].(string)
	if len(client) != 16 || len(path) != 16 || client == path {
		t.Fatal(v)
	}
	again := Sanitize([]byte(raw))
	if again["client_key"] != client || again["path_key"] != path {
		t.Fatal("pseudonyms unstable within a day")
	}
	other := Sanitize([]byte(strings.ReplaceAll(raw, "203.0.113.77", "198.51.100.9")))
	if other["client_key"] == client {
		t.Fatal("distinct clients collapsed")
	}
}
