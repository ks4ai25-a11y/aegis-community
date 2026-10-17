// SPDX-License-Identifier: Apache-2.0
package engineauthz

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"time"
)

// nativePeer rechecks the daemon-authenticated TLS envelope for each HTTP
// operation, including requests on an existing TLS connection. The private
// daemon/plugin socket is the trust boundary: this is not an independent CA
// verifier and caller-supplied HTTP headers never establish a peer identity.
func nativePeer(r Request, now time.Time) bool {
	if r.UserAuthNMethod != "TLS" || (r.User != Broker && r.User != Observer) || len(r.RequestPeerCertificates) < 1 || len(r.RequestPeerCertificates) > 8 {
		return false
	}
	total := 0
	for i, raw := range r.RequestPeerCertificates {
		total += len(raw)
		if len(raw) > 16384 || total > 65536 || !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return false
		}
		if i == 0 {
			client := false
			for _, usage := range cert.ExtKeyUsage {
				client = client || usage == x509.ExtKeyUsageClientAuth
			}
			if cert.Subject.CommonName != r.User || cert.IsCA || !client || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				return false
			}
		}
	}
	return true
}
