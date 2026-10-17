package assess

import "testing"

func TestKeyRequiresHTTPSForPublicHosts(t *testing.T) {
	base := Config{Provider: "openai_compatible", Model: "m", KeyFile: "/run/secrets/k"}
	for url, ok := range map[string]bool{"http://api.example.com": false, "https://api.example.com": true, "http://127.0.0.1:8080": true, "http://ollama:11434": true, "http://10.0.0.5:8000": true} {
		c := base
		c.URL = url
		if (c.Validate() == nil) != ok {
			t.Error(url, c.Validate())
		}
	}
}
