// SPDX-License-Identifier: Apache-2.0
// Package enginetls loads one private scanner engine client identity. There is
// no remote endpoint selection, ambient Docker TLS configuration or fallback.
package enginetls

import (
	"aegis.local/source"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"time"
)

const ServerName = "aegis-scanner-engine"
const Broker = "aegis-engine-broker"

var ErrIdentity = errors.New("private scanner engine TLS identity unavailable")

type Identity struct {
	Directory, Digest string
	TLS               *tls.Config
}

func Load(directory, role string) (*Identity, error) {
	if role != Broker || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrIdentity
	}
	ca, cert, key, e := readIdentity(directory)
	if e != nil {
		return nil, ErrIdentity
	}
	caBlock, rest := pem.Decode(ca)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrIdentity
	}
	root, e := x509.ParseCertificate(caBlock.Bytes)
	if e != nil || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.CheckSignatureFrom(root) != nil {
		return nil, ErrIdentity
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) != 1 {
		return nil, ErrIdentity
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.Subject.CommonName != role || leaf.IsCA {
		return nil, ErrIdentity
	}
	now := time.Now()
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return nil, ErrIdentity
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); e != nil {
		return nil, ErrIdentity
	}
	pair.Leaf = leaf
	digest := source.Hash(append(append([]byte("aegis-scanner-engine-mtls-identity-v1\n"), root.Raw...), leaf.Raw...))
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ServerName, RootCAs: pool, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	identity := &Identity{Directory: directory, Digest: digest, TLS: config}
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		current, e := Load(directory, role)
		if e != nil || current.Digest != digest {
			return nil, ErrIdentity
		}
		return &current.TLS.Certificates[0], nil
	}
	return identity, nil
}

// Check is called before every HTTP operation, including reused connections.
// Withdrawal, expiry or replacement cannot silently reuse cached authority.
func (i *Identity) Check() error {
	if i == nil {
		return ErrIdentity
	}
	current, e := Load(i.Directory, Broker)
	if e != nil || current.Digest != i.Digest {
		return ErrIdentity
	}
	return nil
}
