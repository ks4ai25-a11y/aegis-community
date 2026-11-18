// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"aegis.local/controller/internal/desktopmtls"
)

func desktopTLSServer(handler http.Handler) (*http.Server, error) {
	addr := os.Getenv("AEGIS_DESKTOP_MTLS_LISTEN")
	cert := os.Getenv("AEGIS_DESKTOP_MTLS_CERT_FILE")
	key := os.Getenv("AEGIS_DESKTOP_MTLS_KEY_FILE")
	ca := os.Getenv("AEGIS_DESKTOP_MTLS_CLIENT_CA_FILE")
	if addr == "" && cert == "" && key == "" && ca == "" {
		return nil, nil
	}
	if addr == "" || cert == "" || key == "" || ca == "" {
		return nil, errors.New("desktop mTLS requires a listen address, certificate, private key and client CA")
	}
	host, port, err := net.SplitHostPort(addr)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || net.ParseIP(host) == nil || portErr != nil || number == 0 {
		return nil, errors.New("desktop mTLS listen address must specify an IP and port")
	}
	config, err := desktopmtls.ServerConfig(cert, key, ca)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
		TLSConfig:         config,
	}, nil
}
