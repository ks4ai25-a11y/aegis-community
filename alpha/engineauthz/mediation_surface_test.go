// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import "strings"

// WriteProbe is one Docker Engine API request that could create, start,
// modify, exec into or delete engine state. URI is relative to the versioned
// API prefix unless Raw is set. Exported only for this package's tests.
type WriteProbe struct {
	Class, Method, URI, Body, ContentType string
	Raw                                   bool
}

// WriteSurface enumerates the Docker Engine API v1.55 write surface the native
// authorization plugin is consulted for, plus encoding and version aliases of
// the three admitted operations. tracked is a container the plugin may already
// track, other is any different container, name is a valid scanner child name
// and image is a pinned tool image. Exact admitted create/start/remove forms are
// included only for other/unregistered targets, never for the tracked one.
func WriteSurface(tracked, other, name, image string) []WriteProbe {
	const js, tar = "application/json", "application/x-tar"
	foreign := `{"Image":"` + image + `","Cmd":["/bin/sh"],"HostConfig":{"Privileged":true}}`
	w := []WriteProbe{
		{"containers", "POST", "/containers/create?name=" + name, foreign, js, false},
		{"containers", "POST", "/containers/create", foreign, js, false},
		// A non-JSON body is omitted from the plugin envelope by the daemon.
		{"containers", "POST", "/containers/create?name=" + name, foreign, "text/plain", false},
		{"containers", "POST", "/containers/create?name=" + name, foreign, "", false},
		{"containers", "POST", "/containers/" + other + "/start", "", "", false},
		{"containers", "POST", "/containers/" + tracked + "/start?checkpoint=aegis-probe", "", "", false},
		{"containers", "POST", "/containers/" + tracked + "/start", "{}", js, false},
		{"containers", "DELETE", "/containers/" + other + "?force=1&v=1", "", "", false},
		{"containers", "DELETE", "/containers/" + tracked, "", "", false},
		{"containers", "DELETE", "/containers/" + tracked + "?force=1", "", "", false},
		{"containers", "DELETE", "/containers/" + tracked + "?force=1&link=1&v=1", "", "", false},
		{"containers", "DELETE", "/containers/" + name + "?force=1&v=1", "", "", false},
		{"containers", "POST", "/containers/prune", "", "", false},
		{"exec", "POST", "/exec/" + other + "/start", `{"Detach":true}`, js, false},
		{"exec", "POST", "/exec/" + other + "/resize?h=1&w=1", "", "", false},
		{"images", "POST", "/images/create?fromImage=busybox&tag=latest", "", "", false},
		{"images", "POST", "/images/create?fromSrc=-&repo=aegis-probe", "", tar, false},
		{"images", "POST", "/images/" + image + "/tag?repo=aegis-probe&tag=probe", "", "", false},
		{"images", "POST", "/images/" + image + "/push", "", "", false},
		{"images", "DELETE", "/images/" + image, "", "", false},
		{"images", "DELETE", "/images/" + image + "?force=1", "", "", false},
		{"images", "POST", "/images/prune", "", "", false},
		{"images", "POST", "/images/load", "", tar, false},
		{"images", "POST", "/commit?container=" + other + "&repo=aegis-probe", "{}", js, false},
		{"build", "POST", "/build?t=aegis-probe", "", tar, false},
		{"build", "POST", "/build/prune", "", "", false},
		{"build", "POST", "/build/cancel?id=aegis-probe", "", "", false},
		{"build", "POST", "/session", "", "", false},
		{"build", "POST", "/grpc", "", "", false},
		{"volumes", "POST", "/volumes/create", `{"Name":"aegis-probe"}`, js, false},
		{"volumes", "PUT", "/volumes/aegis-probe?version=1", `{"Spec":{}}`, js, false},
		{"volumes", "DELETE", "/volumes/aegis-probe", "", "", false},
		{"volumes", "DELETE", "/volumes/aegis-probe?force=1", "", "", false},
		{"volumes", "POST", "/volumes/prune", "", "", false},
		{"networks", "POST", "/networks/create", `{"Name":"aegis-probe"}`, js, false},
		{"networks", "POST", "/networks/none/connect", `{"Container":"` + tracked + `"}`, js, false},
		{"networks", "POST", "/networks/none/disconnect", `{"Container":"` + tracked + `"}`, js, false},
		{"networks", "DELETE", "/networks/none", "", "", false},
		{"networks", "POST", "/networks/prune", "", "", false},
		{"plugins", "POST", "/plugins/pull?remote=aegis-probe", "[]", js, false},
		{"plugins", "POST", "/plugins/create?name=aegis-probe", "", tar, false},
		{"plugins", "POST", "/plugins/aegis-probe/enable", "", "", false},
		{"plugins", "POST", "/plugins/aegis-probe/disable", "", "", false},
		{"plugins", "POST", "/plugins/aegis-probe/set", "[]", js, false},
		{"plugins", "POST", "/plugins/aegis-probe/upgrade?remote=aegis-probe", "[]", js, false},
		{"plugins", "POST", "/plugins/aegis-probe/push", "", "", false},
		{"plugins", "DELETE", "/plugins/aegis-probe", "", "", false},
		{"swarm", "POST", "/swarm/init", `{"ListenAddr":"127.0.0.1:2377"}`, js, false},
		{"swarm", "POST", "/swarm/join", `{}`, js, false},
		{"swarm", "POST", "/swarm/leave?force=1", "", "", false},
		{"swarm", "POST", "/swarm/update?version=1", `{}`, js, false},
		{"swarm", "POST", "/swarm/unlock", `{}`, js, false},
		{"swarm", "POST", "/services/create", `{}`, js, false},
		{"swarm", "POST", "/services/aegis-probe/update?version=1", `{}`, js, false},
		{"swarm", "DELETE", "/services/aegis-probe", "", "", false},
		{"swarm", "POST", "/nodes/aegis-probe/update?version=1", `{}`, js, false},
		{"swarm", "DELETE", "/nodes/aegis-probe", "", "", false},
		{"swarm", "POST", "/secrets/create", `{"Name":"aegis-probe","Data":"eA=="}`, js, false},
		{"swarm", "POST", "/secrets/aegis-probe/update?version=1", `{}`, js, false},
		{"swarm", "DELETE", "/secrets/aegis-probe", "", "", false},
		{"swarm", "POST", "/configs/create", `{"Name":"aegis-probe","Data":"eA=="}`, js, false},
		{"swarm", "POST", "/configs/aegis-probe/update?version=1", `{}`, js, false},
		{"swarm", "DELETE", "/configs/aegis-probe", "", "", false},
		{"system", "POST", "/auth", `{}`, js, false},
	}
	for _, target := range []string{tracked, other} {
		c := "/containers/" + target
		w = append(w,
			WriteProbe{"containers", "POST", c + "/stop", "", "", false},
			WriteProbe{"containers", "POST", c + "/restart", "", "", false},
			WriteProbe{"containers", "POST", c + "/kill?signal=KILL", "", "", false},
			WriteProbe{"containers", "POST", c + "/pause", "", "", false},
			WriteProbe{"containers", "POST", c + "/unpause", "", "", false},
			WriteProbe{"containers", "POST", c + "/update", `{"Memory":0}`, js, false},
			WriteProbe{"containers", "POST", c + "/rename?name=aegis-probe", "", "", false},
			WriteProbe{"containers", "POST", c + "/resize?h=1&w=1", "", "", false},
			WriteProbe{"containers", "POST", c + "/attach?stdin=1&stream=1", "", "", false},
			WriteProbe{"containers", "POST", c + "/attach?stderr=1&stdin=1&stdout=1&stream=1", "", "", false},
			WriteProbe{"containers", "GET", c + "/attach/ws?stdin=1&stream=1", "", "", false},
			WriteProbe{"containers", "PUT", c + "/archive?path=%2Ftmp", "", tar, false},
			WriteProbe{"containers", "POST", c + "/checkpoints", `{"CheckpointID":"aegis-probe"}`, js, false},
			WriteProbe{"containers", "DELETE", c + "/checkpoints/aegis-probe", "", "", false},
			WriteProbe{"exec", "POST", c + "/exec", `{"Cmd":["id"],"AttachStdout":true}`, js, false},
		)
	}
	// Version, case and encoding aliases of the admitted forms. Docker routes the
	// unversioned and older-version paths to the same handlers.
	for _, prefix := range []string{"", "/v1.54", "/v1.56", "/V1.55", "/v1.55.0"} {
		w = append(w,
			WriteProbe{"aliases", "POST", prefix + "/containers/create?name=" + name, foreign, js, true},
			WriteProbe{"aliases", "POST", prefix + "/containers/" + tracked + "/start", "", "", true},
			WriteProbe{"aliases", "DELETE", prefix + "/containers/" + tracked + "?force=1&v=1", "", "", true},
		)
	}
	versioned := "/v1.55"
	for _, uri := range []string{
		"/containers/" + tracked + "/start/",
		"//containers/" + tracked + "/start",
		"/containers/" + tracked + "%2Fstart",
		"/containers/./" + tracked + "/start",
		"/containers/" + strings.ToUpper(tracked) + "/start",
		"/containers/" + tracked + "/start?",
		"/containers/" + tracked + "/start#x",
	} {
		w = append(w, WriteProbe{"aliases", "POST", versioned + uri, "", "", true})
	}
	return w
}
