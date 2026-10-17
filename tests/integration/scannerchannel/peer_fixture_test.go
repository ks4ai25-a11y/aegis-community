// SPDX-License-Identifier: BUSL-1.1
package scannerchannelacceptance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"time"
)

var nativePeerCache sync.Map

// nativeTestPeer models the authenticated private-daemon envelope only; it is
// never installed in an engine or used as a trusted network certificate.
func nativeTestPeer(role string) [][]byte {
	if value, ok := nativePeerCache.Load(role); ok {
		return [][]byte{append([]byte(nil), value.([]byte)...)}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: role}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	value, _ := nativePeerCache.LoadOrStore(role, raw)
	return [][]byte{append([]byte(nil), value.([]byte)...)}
}
