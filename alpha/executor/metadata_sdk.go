// SPDX-License-Identifier: Apache-2.0
package executor

import (
	"aegis.local/alpha/scanners"
	"aegis.local/source"
	"context"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var engineIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

type EnginePreflight struct {
	engineTLSIdentity string
	Schema            string `json:"schema_version"`
	Backend           string `json:"backend"`
	Engine            string `json:"engine_digest"`
	Architecture      string `json:"architecture"`
	Tool              string `json:"tool_id"`
	Version           string `json:"tool_version"`
	Image             string `json:"tool_image_digest"`
	Config            string `json:"local_image_config_digest"`
	Lock              string `json:"tool_lock_digest"`
	Writes            bool   `json:"engine_writes_performed"`
	Release           bool   `json:"cleanup_release_authorized"`
}

func canonicalArchitecture(raw string) string {
	switch raw {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "amd64":
		return "amd64"
	}
	return ""
}

// ConfiguredEngineDigest reads only local engine identity. It does not require
// a tool image, allocate a journal, claim a job or perform any engine mutation.
func ConfiguredEngineDigest(ctx context.Context) (string, error) {
	endpoint, e := localEndpoint(os.Getenv("DOCKER_HOST"))
	if e != nil || os.Getenv("DOCKER_CONTEXT") != "" {
		return "", errEngine
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	active := &responseCapture{operation: "info"}
	request, response := metadataHooks("", &active)
	engine, e := newRestrictedEngineSDK(endpoint, request, response)
	if e != nil {
		return "", errEngine
	}
	defer engine.Close()
	if _, e = engine.Info(context.WithValue(ctx, captureKey{}, active), client.InfoOptions{}); e != nil {
		return "", errEngine
	}
	var info system.Info
	if capturedMetadata(active, &info) != nil || info.OSType != "linux" || !engineIdentityPattern.MatchString(info.ID) || canonicalArchitecture(info.Architecture) == "" {
		return "", errEngine
	}
	return sdkEngineDigest(engine, endpoint, info.ID), nil
}
func metadataHooks(image string, active **responseCapture) (client.RequestHook, client.ResponseHook) {
	_, response := engineHooks("", new(string))
	return func(r *http.Request) error {
		capture, _ := r.Context().Value(captureKey{}).(*responseCapture)
		if capture == nil || capture != *active || r.Method != "GET" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			return errEngine
		}
		path := "/v" + engineAPIVersion
		if capture.operation == "info" && r.URL.Path == path+"/info" || capture.operation == "image" && r.URL.Path == path+"/images/"+image+"/json" {
			return nil
		}
		return errEngine
	}, response
}
func capturedMetadata(c *responseCapture, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status != 200 || !c.complete || c.failed || len(c.payload) == 0 || len(c.payload) > 65536 {
		return errEngine
	}
	if inspectionJSON(c.payload, out, 65536) != nil {
		return errEngine
	}
	return nil
}
func preflightSDK(ctx context.Context, endpoint string, tool Tool, lock string) (EnginePreflight, error) {
	out := EnginePreflight{}
	if os.Geteuid() <= 0 || !pinnedImage.MatchString(tool.Image) {
		return out, errEngine
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var active *responseCapture
	request, response := metadataHooks(tool.Image, &active)
	engine, e := newRestrictedEngineSDK(endpoint, request, response)
	if e != nil {
		return out, errEngine
	}
	defer engine.Close()
	active = &responseCapture{operation: "info"}
	infoCtx := context.WithValue(ctx, captureKey{}, active)
	if _, e = engine.Info(infoCtx, client.InfoOptions{}); e != nil {
		return out, errEngine
	}
	var info system.Info
	if capturedMetadata(active, &info) != nil || info.OSType != "linux" || !engineIdentityPattern.MatchString(info.ID) {
		return out, errEngine
	}
	arch := canonicalArchitecture(info.Architecture)
	if arch == "" {
		return out, errEngine
	}
	active = &responseCapture{operation: "image"}
	imageCtx := context.WithValue(ctx, captureKey{}, active)
	if _, e = engine.ImageInspect(imageCtx, tool.Image); e != nil {
		return out, errEngine
	}
	var image client.ImageInspectResult
	if capturedMetadata(active, &image) != nil || image.Os != "linux" || canonicalArchitecture(image.Architecture) != arch || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(image.ID) || len(image.RepoDigests) == 0 || len(image.RepoDigests) > 256 {
		return out, errEngine
	}
	pin := strings.Split(tool.Image, "@")[1]
	matched := false
	for _, value := range image.RepoDigests {
		if pinnedImage.MatchString(value) && strings.HasSuffix(value, "@"+pin) {
			matched = true
		}
	}
	if !matched {
		return out, errEngine
	}
	backend := "unix-sdk-1.55"
	tlsIdentity := ""
	if engine.identity != nil {
		backend = "mtls-unix-sdk-1.55"
		tlsIdentity = engine.identity.Digest
	}
	return EnginePreflight{engineTLSIdentity: tlsIdentity, Schema: "1.0", Backend: backend, Engine: sdkEngineDigest(engine, endpoint, info.ID), Architecture: arch, Tool: tool.ID, Version: tool.Version, Image: pin, Config: image.ID, Lock: lock}, nil
}

// Preflight is read-only. It never pulls images or writes a lifecycle journal.
func (c Config) Preflight(ctx context.Context, toolID string) (EnginePreflight, error) {
	if _, e := scanners.BuildInvocation(toolID); e != nil {
		return EnginePreflight{}, errEngine
	}
	if _, e := localEndpoint(os.Getenv("DOCKER_HOST")); e != nil || os.Getenv("DOCKER_CONTEXT") != "" {
		return EnginePreflight{}, errEngine
	}
	tool, lock, e := resolve(c.LockPath, toolID)
	if e != nil {
		return EnginePreflight{}, errEngine
	}
	if c.ExpectedLockDigest != "" && c.ExpectedLockDigest != lock {
		return EnginePreflight{}, errEngine
	}
	return preflightSDK(ctx, os.Getenv("DOCKER_HOST"), tool, lock)
}

func sdkEngineDigest(client *scannerEngineClient, endpoint, id string) string {
	if client.identity != nil {
		return source.Hash([]byte("aegis-scanner-mtls-engine-v1\n" + endpoint + "\n" + id + "\n" + client.identity.Digest))
	}
	return source.Hash([]byte(endpoint + "\n" + id))
}
