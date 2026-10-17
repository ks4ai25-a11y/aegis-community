// SPDX-License-Identifier: BUSL-1.1
// Package evidence signs exported evidence with an installation-local Ed25519 key
// so a third party can check that a report came unchanged from this installation.
// A signature proves origin and integrity of the bytes, not that the claim is true.
package evidence

import (
	"aegis.local/controller/internal/domain"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	Scheme  = "aegis-evidence-ed25519-v1"
	context = "aegis-evidence-v1\x00"
)

type Signer struct {
	key ed25519.PrivateKey
}

// Envelope is the exported, independently verifiable form.
type Envelope struct {
	Scheme    string          `json:"signature_scheme"`
	KeyID     string          `json:"key_id"`
	PublicKey string          `json:"public_key"`
	Digest    string          `json:"document_digest"`
	Signature string          `json:"signature"`
	Document  json.RawMessage `json:"document"`
	Note      string          `json:"note"`
}

// LoadOrCreate reads the installation key from dir/evidence-signing.key, creating
// a private (0600, exclusive) key on first use.
func LoadOrCreate(dir string) (*Signer, error) {
	path := filepath.Join(dir, "evidence-signing.key")
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		_, priv, ge := ed25519.GenerateKey(rand.Reader)
		if ge != nil {
			return nil, ge
		}
		f, oe := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if oe != nil {
			return nil, oe
		}
		if _, we := f.Write(priv.Seed()); we != nil {
			f.Close()
			return nil, we
		}
		if se := f.Sync(); se != nil {
			f.Close()
			return nil, se
		}
		if ce := f.Close(); ce != nil {
			return nil, ce
		}
		return &Signer{priv}, nil
	}
	if e != nil {
		return nil, e
	}
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm()&0o077 != 0 || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("evidence signing key must be a private 32-byte seed")
	}
	return &Signer{ed25519.NewKeyFromSeed(b)}, nil
}

func (s *Signer) Public() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// KeyID is a short stable identifier for the public key.
func KeyID(pub ed25519.PublicKey) string { return domain.Hash(pub)[7:23] }

// Sign wraps a JSON document whose canonical digest is digest.
func (s *Signer) Sign(document []byte, digest string) Envelope {
	pub := s.Public()
	sig := ed25519.Sign(s.key, []byte(context+digest))
	return Envelope{Scheme: Scheme, KeyID: KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), Digest: digest, Signature: base64.StdEncoding.EncodeToString(sig), Document: document,
		Note: "The signature shows these bytes came unchanged from the Aegis installation holding this key. It does not prove the claims are true or complete."}
}

// Verify checks the envelope's signature and that digest matches the document
// using the supplied canonical digest function. trusted, if non-empty, pins the key.
func Verify(env Envelope, digestOf func(json.RawMessage) (string, error), trusted string) error {
	if env.Scheme != Scheme {
		return errors.New("unsupported signature scheme")
	}
	pub, e := base64.StdEncoding.DecodeString(env.PublicKey)
	if e != nil || len(pub) != ed25519.PublicKeySize || KeyID(pub) != env.KeyID {
		return errors.New("invalid public key")
	}
	if trusted != "" && trusted != env.KeyID && trusted != env.PublicKey {
		return errors.New("signed by an untrusted key")
	}
	sig, e := base64.StdEncoding.DecodeString(env.Signature)
	if e != nil || !ed25519.Verify(pub, []byte(context+env.Digest), sig) {
		return errors.New("signature does not verify")
	}
	d, e := digestOf(env.Document)
	if e != nil || d != env.Digest {
		return errors.New("document does not match the signed digest")
	}
	return nil
}

// ReportDigest is the canonical digest of a verification report document.
func ReportDigest(raw json.RawMessage) (string, error) {
	var r domain.Report
	if e := json.Unmarshal(raw, &r); e != nil {
		return "", e
	}
	d := r.Digest
	r.Digest = ""
	if domain.Digest(r) != d {
		return "", errors.New("report self-digest mismatch")
	}
	return d, nil
}
