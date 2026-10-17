// SPDX-License-Identifier: BUSL-1.1
package enginetls

import (
	"aegis.local/alpha/internal/testpki"
	"aegis.local/source"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserverDerivesOriginalBrokerScopeWithoutBrokerKey(t *testing.T) {
	f := fixture(t)
	broker, err := Load(f.Directory, Broker)
	if err != nil {
		t.Fatal(err)
	}
	o := f.AdditionalClientAt(t, filepath.Join(filepath.Dir(f.Directory), "observer"), Observer, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	observer, err := Load(o.Directory, Observer)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(f.Directory); err != nil {
		t.Fatal(err)
	}
	digest, err := observer.BrokerCertificateDigest(f.Client)
	if err != nil || digest != broker.Digest || digest == observer.Digest {
		t.Fatal("public broker identity did not preserve original scope", err)
	}
	if _, err = broker.BrokerCertificateDigest(f.Client); err == nil {
		t.Fatal("broker identity selected observer scope operation")
	}
	if err = os.Remove(filepath.Join(o.Directory, "client.key")); err != nil {
		t.Fatal(err)
	}
	if _, err = observer.BrokerCertificateDigest(f.Client); err == nil {
		t.Fatal("withdrawn observer derived accepted scope")
	}
}

func TestPublicBrokerScopeAcceptsHistoricalExpiryWithoutAuthentication(t *testing.T) {
	f := fixture(t)
	dir := filepath.Dir(f.Directory)
	o := f.AdditionalClientAt(t, filepath.Join(dir, "observer"), Observer, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	historical := f.AdditionalClientAt(t, filepath.Join(dir, "expired"), Broker, time.Now().Add(-30*time.Second), time.Now().Add(-time.Second))
	if _, err := Load(historical.Directory, Broker); err == nil {
		t.Fatal("expired broker still authenticates")
	}
	observer, err := Load(o.Directory, Observer)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(f.CA)
	leafBlock, _ := pem.Decode(historical.Client)
	root, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	expected := source.Hash(append(append([]byte("aegis-scanner-engine-mtls-identity-v1\n"), root.Raw...), leafBlock.Bytes...))
	digest, err := observer.BrokerCertificateDigest(historical.Client)
	if err != nil || digest != expected {
		t.Fatal("expired public certificate lost historical scope", err)
	}
}

func TestPublicBrokerScopeRefusesAmbiguousOrForeignCertificates(t *testing.T) {
	f := fixture(t)
	dir := filepath.Dir(f.Directory)
	o := f.AdditionalClientAt(t, filepath.Join(dir, "observer"), Observer, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	observer, err := Load(o.Directory, Observer)
	if err != nil {
		t.Fatal(err)
	}
	foreign := testpki.New(t, filepath.Join(dir, "foreign"), Broker)
	future := f.AdditionalClientAt(t, filepath.Join(dir, "future"), Broker, time.Now().Add(10*time.Minute), time.Now().Add(20*time.Minute))
	for name, cert := range map[string][]byte{
		"empty": nil, "observer": o.Client, "foreign-ca": foreign.Client, "ca": f.CA, "private-key": f.Key,
		"two-certificates":    append(append([]byte(nil), f.Client...), f.Client...),
		"certificate-and-key": append(append([]byte(nil), f.Client...), f.Key...),
		"prefix":              append([]byte("unexpected"), f.Client...), "future": future.Client,
		"oversize": make([]byte, 16385),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := observer.BrokerCertificateDigest(cert); err == nil {
				t.Fatal("unapproved public certificate accepted")
			}
		})
	}
}
