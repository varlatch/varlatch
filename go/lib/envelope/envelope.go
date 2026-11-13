// SPDX-License-Identifier: Apache-2.0

// Package envelope is Varlatch's encryption envelope (ADR-0011, kept
// unchanged by ADR-0059 Decision 2): AES-256-GCM with a random 96-bit nonce
// and a 128-bit tag, the associated data being the canonical JSON of a
// context naming the envelope's purpose and the identifiers it belongs to,
// stored as a JSON object of base64 strings. It reads and writes exactly
// what the TypeScript server does (services/varlatchd/src/crypto), which
// testdata/ fixtures check in both directions.
//
// Errors never contain plaintext, key material or the associated data.
package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// FormatVersion is the only envelope format there is.
	FormatVersion = 1
	// Algorithm is the only algorithm.
	Algorithm = "aes-256-gcm"
	// KeySize is the size of every key: Root KEK, org KEKs, DEKs.
	KeySize = 32

	nonceSize = 12
	tagSize   = 16
)

var (
	// ErrDecrypt means authentication failed: a wrong key, a wrong context,
	// or a changed envelope.
	ErrDecrypt = errors.New("envelope: decryption failed: authentication error")
	// ErrKeySize means a key is not KeySize bytes.
	ErrKeySize = errors.New("envelope: invalid key length")
	// ErrMalformed means the envelope is not one this package can open.
	ErrMalformed = errors.New("envelope: malformed envelope")
)

// Envelope is a sealed value as stored (in a JSON column). It carries no key
// material.
type Envelope struct {
	FormatVersion int    `json:"formatVersion"`
	Algorithm     string `json:"algorithm"`
	Nonce         string `json:"nonce"`      // base64
	Ciphertext    string `json:"ciphertext"` // base64; as long as the plaintext
	AuthTag       string `json:"authTag"`    // base64

	// missing is set when decoded JSON lacked a field or had a format
	// version that is not the number 1; Open then refuses the envelope, as
	// the TypeScript server does.
	missing bool
}

// UnmarshalJSON reads an envelope the way the TypeScript server's decrypt
// sees one (JSON.parse, then property lookups):
//
//   - field names match exactly (encoding/json alone would also take
//     "FORMATVERSION");
//   - formatVersion must be the JSON number 1 (1.0 is the same number, the
//     string "1" is not), and every field must be a JSON string otherwise;
//   - nonce, ciphertext and authTag are decoded as Node decodes them, from
//     the UTF-16 code units of the JSON strings (encoding/json would turn a
//     lone surrogate into U+FFFD first), and kept in standard base64, which
//     decodes to the same bytes in both servers.
//
// An envelope that does not meet this decodes without error but is refused
// by Open, as the TypeScript server refuses it at decryption.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.New("envelope: not a JSON object")
	}
	*e = Envelope{}
	ok := true
	// A JSON number, never a string: json.Number alone would also accept "1".
	var version json.Number
	if raw := bytes.TrimSpace(fields["formatVersion"]); len(raw) > 0 && raw[0] != '"' && json.Unmarshal(raw, &version) == nil {
		if f, err := version.Float64(); err == nil && f == FormatVersion {
			e.FormatVersion = FormatVersion
		}
	}
	if e.FormatVersion != FormatVersion {
		ok = false
	}
	if raw, found := fields["algorithm"]; !found || json.Unmarshal(raw, &e.Algorithm) != nil {
		ok = false
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"nonce", &e.Nonce}, {"ciphertext", &e.Ciphertext}, {"authTag", &e.AuthTag}} {
		units, isString := jsonStringUnits(fields[f.name])
		if !isString {
			ok = false
			continue
		}
		*f.dst = base64.StdEncoding.EncodeToString(nodeBase64Units(units))
	}
	e.missing = !ok
	return nil
}

// GenerateKey returns a new random key.
func GenerateKey() []byte {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		panic("envelope: crypto/rand failed: " + err.Error())
	}
	return k
}

// Seal encrypts plaintext under key, bound to ctx.
func Seal(key, plaintext []byte, ctx Context) (Envelope, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("envelope: crypto/rand: %w", err)
	}
	return seal(key, plaintext, ctx, nonce)
}

func seal(key, plaintext []byte, ctx Context, nonce []byte) (Envelope, error) {
	aead, err := newGCM(key)
	if err != nil {
		return Envelope{}, err
	}
	aad, err := ctx.aad()
	if err != nil {
		return Envelope{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	ct, tag := sealed[:len(plaintext)], sealed[len(plaintext):]
	return Envelope{
		FormatVersion: FormatVersion,
		Algorithm:     Algorithm,
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(ct),
		AuthTag:       base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// Open decrypts env with key, checking that it was sealed for ctx.
func Open(key []byte, env Envelope, ctx Context) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if env.missing || env.FormatVersion != FormatVersion || env.Algorithm != Algorithm {
		return nil, ErrMalformed
	}
	// The TypeScript server decodes these leniently (Node's Buffer); so do we.
	nonce := nodeBase64(env.Nonce)
	tag := nodeBase64(env.AuthTag)
	if len(nonce) != nonceSize || len(tag) != tagSize {
		return nil, ErrMalformed
	}
	aad, err := ctx.aad()
	if err != nil {
		return nil, err
	}
	sealed := append(nodeBase64(env.Ciphertext), tag...)
	pt, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKeySize
	}
	return cipher.NewGCMWithTagSize(block, tagSize)
}
