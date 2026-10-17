// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"aegis.local/source"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func localEndpoint(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "unix" || u.Host != "" || !filepath.IsAbs(u.Path) || u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.ContainsAny(u.Path, "\x00\r\n") {
		return "", fmt.Errorf("local Unix Docker socket required")
	}
	return "unix://" + u.Path, nil
}
func dockerEnv() []string {
	out := []string{}
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		switch key {
		case "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
			continue
		}
		out = append(out, v)
	}
	return out
}

// Resolve once, then bind every operation to the same local endpoint. No
// remote engine may receive private host-source mount paths.
func (c Config) engine(ctx context.Context) (string, string, error) {
	if os.Getenv("AEGIS_SCANNER_ENGINE_TLS_DIR") != "" {
		if os.Getenv("DOCKER_CONTEXT") != "" {
			return "", "", errEngine
		}
		endpoint, e := localEndpoint(os.Getenv("DOCKER_HOST"))
		if e != nil {
			return "", "", errEngine
		}
		return "", endpoint, nil
	}
	docker := c.Docker
	if docker == "" {
		docker = "docker"
	}
	host := os.Getenv("DOCKER_HOST")
	name := os.Getenv("DOCKER_CONTEXT")
	if name != "" || host == "" {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if name == "" {
			b, e := inspectOutput(bounded, docker, "", 256, "context", "show")
			if e != nil || len(b) > 256 {
				return "", "", fmt.Errorf("Docker context unavailable")
			}
			name = strings.TrimSpace(string(b))
		}
		if name == "" || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") {
			return "", "", fmt.Errorf("invalid Docker context")
		}
		b, e := inspectOutput(bounded, docker, "", 4096, "context", "inspect", name, "--format", "{{.Endpoints.docker.Host}}")
		if e != nil || len(b) > 4096 {
			return "", "", fmt.Errorf("Docker endpoint unavailable")
		}
		host = strings.TrimSpace(string(b))
	}
	endpoint, e := localEndpoint(host)
	return docker, endpoint, e
}
func engineCommand(ctx context.Context, docker, endpoint string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, docker, append([]string{"--host", endpoint}, args...)...)
	command.Env = dockerEnv()
	return command
}

// ContainerAbsent checks only an exact journalled Aegis name and never removes
// a container. Recovery fails closed if the engine cannot answer.
func (c Config) ContainerAbsent(ctx context.Context, name, expectedEngine string) (bool, error) {
	if os.Getenv("AEGIS_SCANNER_ENGINE_TLS_DIR") != "" {
		return false, errEngine
	}
	if !scannerName.MatchString(name) {
		return false, fmt.Errorf("invalid scanner container identity")
	}
	docker, endpoint, e := c.engine(ctx)
	if e != nil {
		return false, e
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	identity, e := inspectOutput(bounded, docker, endpoint, 256, "info", "--format", "{{.ID}}")
	if e != nil || len(identity) > 256 || strings.TrimSpace(string(identity)) == "" || source.Hash([]byte(endpoint+"\n"+strings.TrimSpace(string(identity)))) != expectedEngine {
		return false, fmt.Errorf("journalled scanner engine identity unconfirmed")
	}
	b, e := inspectOutput(bounded, docker, endpoint, 512, "ps", "--all", "--filter", "name=^/"+name+"$", "--format", "{{.Names}}")
	if e != nil || len(b) > 512 {
		return false, fmt.Errorf("container absence unconfirmed")
	}
	return strings.TrimSpace(string(b)) == "", nil
}

// ConfiguredToolLockDigest identifies the bounded operator-provisioned lock;
// it does not authenticate a publisher or accept repository-selected pins.
func ConfiguredToolLockDigest(path string) (string, error) {
	_, digest, e := resolve(path, "bandit")
	return digest, e
}
