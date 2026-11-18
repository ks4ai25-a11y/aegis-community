// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"strings"

	"aegis.local/controller/internal/desktopmtls"
)

func configuredHTTPClient(base string) (*http.Client, error) {
	client := connectorHTTPClient()
	ca := os.Getenv("AEGIS_DESKTOP_CA_FILE")
	certificate := os.Getenv("AEGIS_DESKTOP_CLIENT_CERT_FILE")
	key := os.Getenv("AEGIS_DESKTOP_CLIENT_KEY_FILE")
	if ca == "" && certificate == "" && key == "" {
		return client, nil
	}
	if !strings.HasPrefix(base, "https://") {
		return nil, errors.New("desktop TLS settings require an https AEGIS_URL")
	}
	if (certificate == "") != (key == "") || (certificate != "" && ca == "") {
		return nil, errors.New("mutual TLS requires the desktop CA, client certificate and client key together")
	}
	roots, err := desktopmtls.Roots(ca)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if certificate != "" {
		pair, err := desktopmtls.Certificate(certificate, key)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{pair}
	}
	client.Transport.(*http.Transport).TLSClientConfig = config
	return client, nil
}
