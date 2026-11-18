// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var inviteShape = regexp.MustCompile(`^[0-9a-f-]{36}:[0-9a-f]{64}$`)

func pairingHash(text string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text)))
}
func pairingSecret() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func pair(input io.Reader, status io.Writer) error {
	base, err := consoleBase()
	if err != nil {
		return err
	}
	path, account, err := credentialLocation()
	if err != nil {
		return err
	}
	var save func(string) error
	if account != "" {
		store, e := openKeychain(base, account)
		if e != nil {
			return e
		}
		defer store.close()
		if e = checkKeychainPairingSlot(store); e != nil {
			return e
		}
		save = func(token string) error { return store.add(false, token) }
	} else {
		if err := checkPairingPath(path); err != nil {
			return err
		}
		save = func(token string) error { return storePairedCredential(path, token) }
	}
	fmt.Fprintln(status, "Provide the one-time invitation from the Aegis console on stdin.")
	in := bufio.NewScanner(input)
	in.Buffer(make([]byte, 256), 256)
	if !in.Scan() || !inviteShape.MatchString(strings.TrimSpace(in.Text())) {
		return errors.New("invalid pairing invitation")
	}
	id, code, _ := strings.Cut(strings.TrimSpace(in.Text()), ":")
	proof, err := pairingSecret()
	if err != nil {
		return errors.New("could not generate pairing proof")
	}
	secret, err := pairingSecret()
	if err != nil {
		return errors.New("could not generate connector credential")
	}
	token := "aegis_dp_" + secret
	digest := pairingHash("aegis-paired-token-v1\x00" + token)
	c := &client{base: base, http: connectorHTTPClient()}
	defer c.http.CloseIdleConnections()
	claim, _ := json.Marshal(map[string]string{"pairing_id": id, "invite_code": code, "device_proof": proof, "credential_digest": digest})
	if _, err = c.request(http.MethodPost, "/desktop/pairing/claim", claim, ""); err != nil {
		return err
	}
	fingerprint := pairingHash("aegis-pairing-v1\n" + id + "\n" + proof + "\n" + digest)[7:27]
	fmt.Fprintf(status, "Device fingerprint: %s\nConfirm this fingerprint in Aegis.\n", fingerprint)
	redeem, _ := json.Marshal(map[string]string{"pairing_id": id, "device_proof": proof})
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var raw string
		raw, err = c.request(http.MethodPost, "/desktop/pairing/redeem", redeem, "")
		if err == nil {
			var result struct {
				ID    string `json:"connector_id"`
				Scope string `json:"scope"`
				State string `json:"state"`
			}
			if json.Unmarshal([]byte(raw), &result) != nil || result.ID != id || result.Scope != "desktop_handoff_v1" || result.State != "active" {
				return errors.New("invalid pairing confirmation")
			}
			if err = save(token); err != nil {
				return err
			}
			fmt.Fprintln(status, "Paired. Start a new desktop app session and call aegis_status.")
			return nil
		}
		if err != httpStatusError(http.StatusConflict) && err != httpStatusError(http.StatusTooManyRequests) {
			return err
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("pairing invitation expired")
}

func checkPairingPath(path string) error {
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Stat(parent)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || err != nil || canonical != parent ||
		statErr != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("set AEGIS_CONNECTOR_TOKEN_FILE to a new path in a private directory")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("choose a new connector token file")
	}
	return nil
}

func storePairedCredential(path, token string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("could not create private connector file")
	}
	info, _ := file.Stat()
	ok := false
	defer func() {
		if !ok {
			found, e := os.Lstat(path)
			if e == nil && info != nil && os.SameFile(info, found) {
				_ = os.Remove(path)
			}
		}
	}()
	_, writeErr := file.WriteString(token + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("could not save the connector credential")
	}
	ok = true
	return nil
}
