// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

var (
	pairedTokenShape       = regexp.MustCompile(`^aegis_dp_[0-9a-f]{64}$`)
	keychainAccountShape   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	errKeychainItemMissing = errors.New("paired credential missing from Keychain")
)

type keychainStore interface {
	read(pending bool) (string, error)
	add(pending bool, token string) error
	replace(token string) error
	clearPending() error
	close()
}

func credentialLocation() (path, account string, err error) {
	path = os.Getenv("AEGIS_CONNECTOR_TOKEN_FILE")
	account = os.Getenv("AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT")
	switch {
	case path != "" && account != "":
		return "", "", errors.New("choose either AEGIS_CONNECTOR_TOKEN_FILE or AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT")
	case account != "" && !keychainAccountShape.MatchString(account):
		return "", "", errors.New("Keychain account must use 1–64 letters, digits, periods, underscores or hyphens and start with a letter or digit")
	case path == "" && account == "":
		return "", "", errors.New("set AEGIS_CONNECTOR_TOKEN_FILE or AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT")
	}
	return path, account, nil
}

func checkKeychainPairingSlot(store keychainStore) error {
	for _, pending := range []bool{false, true} {
		if _, err := store.read(pending); !errors.Is(err, errKeychainItemMissing) {
			if err != nil {
				return err
			}
			return errors.New("choose a new Keychain account for this console")
		}
	}
	return nil
}

func renew(status io.Writer) error {
	base, err := consoleBase()
	if err != nil {
		return err
	}
	path, account, err := credentialLocation()
	if err != nil {
		return err
	}
	httpClient, err := configuredHTTPClient(base)
	if err != nil {
		return err
	}
	defer httpClient.CloseIdleConnections()
	confirm := func(old, next string) error { return confirmRotation(base, old, next, httpClient) }
	if account == "" {
		err = renewFile(path, confirm)
	} else {
		err = renewKeychain(base, account, confirm)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(status, "Renewed. Start a new desktop app session and call aegis_status.")
	return nil
}

// rotateKeychain preserves the candidate until it is both active and installed.
func rotateKeychain(store keychainStore, confirm func(old, next string) error) error {
	old, err := store.read(false)
	if err != nil {
		return err
	}
	next, err := store.read(true)
	if errors.Is(err, errKeychainItemMissing) {
		secret, e := pairingSecret()
		if e != nil {
			return errors.New("could not generate replacement credential")
		}
		next = "aegis_dp_" + secret
		err = store.add(true, next)
	}
	if err != nil {
		return err
	}
	if next != old {
		if err := confirm(old, next); err != nil {
			return err
		}
		if err := store.replace(next); err != nil {
			return err
		}
	}
	return store.clearPending()
}

func confirmRotation(base, old, next string, httpClient *http.Client) error {
	c := &client{base: base, token: old, http: httpClient}
	digest := pairingHash("aegis-paired-token-v1\x00" + next)
	body, _ := json.Marshal(map[string]string{"credential_digest": digest})
	raw, err := c.request(http.MethodPost, "/desktop/renew", body, "")
	var receipt struct {
		ID      string `json:"connector_id"`
		Expires int64  `json:"expires_unix"`
	}
	if err == nil && (json.Unmarshal([]byte(raw), &receipt) != nil || receipt.ID == "" || receipt.Expires <= 0) {
		err = errors.New("renewal response was invalid")
	}
	// The response can be lost after commit. Prove the locally saved replacement
	// is already active before promoting it, including after the receipt expires.
	c.token = next
	verified, lookup := c.get("/desktop/status")
	var device struct {
		ID            string `json:"connector_id"`
		Scope         string `json:"scope"`
		Authenticated bool   `json:"authenticated"`
	}
	if lookup != nil || json.Unmarshal([]byte(verified), &device) != nil || !device.Authenticated || device.Scope != "desktop_handoff_v1" ||
		device.ID == "" || (receipt.ID != "" && device.ID != receipt.ID) {
		if err == httpStatusError(http.StatusNotFound) {
			return errors.New("approve renewal for this device in Aegis, then retry")
		}
		return errors.New("renewal could not be verified; retry using the same credential settings")
	}
	return nil
}
