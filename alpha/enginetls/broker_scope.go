// SPDX-License-Identifier: Apache-2.0
package enginetls

import (
	"aegis.local/source"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"time"
)

// BrokerCertificateDigest identifies an original broker using only its public
// certificate and this observer's CA. It grants no broker authentication. An
// expired broker certificate can identify historical scope while this observer
// and its CA must still be live. The caller must compare the resulting engine
// scope with the original controller-approved digest.
func (i *Identity) BrokerCertificateDigest(publicCertificate []byte) (string, error) {
	if i == nil || i.role != Observer || len(publicCertificate) == 0 || len(publicCertificate) > 16384 {
		return "", ErrIdentity
	}
	current, err := Load(i.Directory, Observer)
	if err != nil || current.Digest != i.Digest {
		return "", ErrIdentity
	}
	b := bytes.TrimSpace(publicCertificate)
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE-----")) {
		return "", ErrIdentity
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", ErrIdentity
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.IsCA || leaf.Subject.CommonName != Broker || leaf.NotBefore.After(time.Now()) {
		return "", ErrIdentity
	}
	// Verify at a time when the two original public certificates overlap. This
	// validates the original chain, not permission to use an expired broker key.
	verifiedAt := leaf.NotBefore
	if current.root.NotBefore.After(verifiedAt) {
		verifiedAt = current.root.NotBefore
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: current.TLS.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: verifiedAt}); err != nil {
		return "", ErrIdentity
	}
	digest := source.Hash(append(append([]byte("aegis-scanner-engine-mtls-identity-v1\n"), current.root.Raw...), leaf.Raw...))
	if i.Check() != nil {
		return "", ErrIdentity
	}
	return digest, nil
}
