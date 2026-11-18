// SPDX-License-Identifier: BUSL-1.1
package desktopmtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
)

func ServerConfig(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	pair, err := Certificate(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	roots, err := Roots(clientCAPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}, nil
}

func Roots(path string) (*x509.CertPool, error) {
	pem, err := readPEM(path, false)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("desktop TLS trust file must contain PEM certificates")
	}
	return roots, nil
}

func Certificate(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := readPEM(certPath, false)
	if err != nil {
		return tls.Certificate{}, errors.New("desktop TLS certificate must be a readable regular PEM file")
	}
	key, err := readPEM(keyPath, true)
	if err != nil {
		return tls.Certificate{}, errors.New("desktop TLS key must be a readable private regular PEM file (chmod 600)")
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, errors.New("desktop TLS certificate and key must be a matching PEM pair")
	}
	return pair, nil
}

func readPEM(path string, private bool) ([]byte, error) {
	check := func(info os.FileInfo) bool {
		return info.Mode().IsRegular() && (!private || info.Mode().Perm()&0077 == 0)
	}
	before, err := os.Lstat(path)
	if err != nil || !check(before) {
		return nil, errors.New("unusable PEM file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !check(after) || !os.SameFile(before, after) {
		return nil, errors.New("PEM file changed")
	}
	const maxPEMBytes = 256 << 10
	pem, err := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err != nil || len(pem) > maxPEMBytes {
		clear(pem)
		return nil, errors.New("unreadable or oversized PEM file")
	}
	return pem, nil
}
