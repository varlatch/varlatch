// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authtest is a software WebAuthn authenticator for tests: it
// registers ("none" attestation) and asserts (ES256) as a browser's
// authenticator would, for any origin and RP ID a test names, with a
// counter the test controls.
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/varlatch/varlatch/go/server/auth"
)

// B64 is base64url without padding, as WebAuthn's JSON carries bytes.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func clientData(typ, challenge, from string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": from, "crossOrigin": false})
	return b
}

// Key is a software authenticator holding one credential.
type Key struct {
	Priv       *ecdsa.PrivateKey
	ID         []byte
	Counter    uint32
	UserHandle []byte
	// NoUV leaves user verification out of its assertions.
	NoUV bool
	// FixedCounter keeps the counter where it is (an authenticator
	// without one, or a clone).
	FixedCounter bool
}

// New is a new credential with a fresh P-256 key.
func New(t testing.TB) *Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Key{Priv: priv, ID: id}
}

// COSE is the credential's public key as a COSE_Key.
func (k *Key) COSE(t testing.TB) []byte {
	t.Helper()
	x, y := make([]byte, 32), make([]byte, 32)
	k.Priv.PublicKey.X.FillBytes(x)
	k.Priv.PublicKey.Y.FillBytes(y)
	b, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1, XCoord: x, YCoord: y,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k *Key) flags(attested bool) byte {
	f := byte(0x01) // UP
	if !k.NoUV {
		f |= 0x04 // UV
	}
	if attested {
		f |= 0x40 // AT
	}
	return f
}

// Register answers creation options as navigator.credentials.create would,
// from the origin `from`.
func (k *Key) Register(t testing.TB, o auth.CreationOptions, from string) json.RawMessage {
	t.Helper()
	k.UserHandle, _ = base64.RawURLEncoding.DecodeString(o.User.ID)
	rpHash := sha256.Sum256([]byte(o.RP.ID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, k.flags(true))
	data = binary.BigEndian.AppendUint32(data, k.Counter)
	data = append(data, make([]byte, 16)...) // AAGUID
	data = binary.BigEndian.AppendUint16(data, uint16(len(k.ID)))
	data = append(data, k.ID...)
	data = append(data, k.COSE(t)...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": B64(k.ID), "rawId": B64(k.ID), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": B64(clientData("webauthn.create", o.Challenge, from)), "attestationObject": B64(att),
			"transports": []string{"internal"},
		},
	})
	return b
}

// AssertWith signs an assertion over challenge for rpID, from the origin
// `from`, with the given counter.
func (k *Key) AssertWith(t testing.TB, rpID, challenge, from string, counter uint32) json.RawMessage {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, k.flags(false))
	data = binary.BigEndian.AppendUint32(data, counter)
	cd := clientData("webauthn.get", challenge, from)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, data...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.Priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": B64(k.ID), "rawId": B64(k.ID), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": B64(cd), "authenticatorData": B64(data), "signature": B64(sig), "userHandle": B64(k.UserHandle),
		},
	})
	return b
}

// Assert answers request options, advancing its counter.
func (k *Key) Assert(t testing.TB, o auth.RequestOptions, from string) json.RawMessage {
	t.Helper()
	if !k.FixedCounter {
		k.Counter++
	}
	return k.AssertWith(t, o.RPID, o.Challenge, from, k.Counter)
}
