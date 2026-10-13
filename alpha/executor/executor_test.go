package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOutputLimitCancelsAndNeverRetainsOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &cappedOutput{limit: 4, cancel: cancel}
	if _, e := w.Write([]byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Write([]byte("private overflow")); e == nil {
		t.Fatal("overflow accepted")
	}
	bytes, exceeded := w.Bytes()
	if !exceeded || string(bytes) != "1234" || ctx.Err() == nil {
		t.Fatal("overflow not contained")
	}
}
func TestLockRequiresUniqueImmutableImages(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock.json")
	for _, data := range []string{`{"schema_version":"1.0","tools":[{"id":"semgrep_ce","version":"test","image":"semgrep/semgrep:latest"}]}`, `{"schema_version":"1.0","tools":[]}`, `not json`} {
		os.WriteFile(p, []byte(data), 0600)
		if _, _, e := resolve(p, "semgrep_ce"); e == nil {
			t.Fatal("invalid pin accepted")
		}
	}
}

func TestLocalEngineRefusesRemoteEndpoints(t *testing.T) {
	for _, endpoint := range []string{"tcp://127.0.0.1:2375", "ssh://operator@host", "unix://host/socket", "unix:///tmp/docker.sock?x=1", "unix:///tmp/docker.sock#x", "unix:relative", "unix:///tmp/socket\n"} {
		if _, e := localEndpoint(endpoint); e == nil {
			t.Fatalf("remote or malformed endpoint accepted: %q", endpoint)
		}
	}
	if got, e := localEndpoint("unix:///tmp/docker.sock"); e != nil || got != "unix:///tmp/docker.sock" {
		t.Fatal(got, e)
	}
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
	t.Setenv("DOCKER_CONTEXT", "")
	if _, _, e := (Config{Docker: "must-not-be-executed"}).engine(context.Background()); e == nil {
		t.Fatal("remote endpoint reached engine")
	}
}
