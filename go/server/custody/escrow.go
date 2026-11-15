// SPDX-License-Identifier: AGPL-3.0-or-later

// Package custody holds the Root KEK's recovery copies (crypto/escrow.ts;
// ADR-0059 step 4.14): a passphrase escrow blob, safe to store anywhere,
// and Shamir shares over GF(2^8), any k of n reconstructing the key. Never
// logs, and never puts key material in an error.
package custody

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"golang.org/x/crypto/scrypt"
)

// Error is a refusal with the TypeScript server's message (CryptoError).
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

const (
	escrowFormatVersion = 1
	escrowKind          = "varlatch-kek-escrow"
	// MinPassphraseLength is the escrow passphrase's minimum, in UTF-16
	// units as JavaScript counts a string's length.
	MinPassphraseLength = 12
	// The scrypt parameters a new blob uses (~128 MiB, ~0.5 s).
	scryptN, scryptR, scryptP = 1 << 17, 8, 1
	// scryptMaxMem is Node's maxmem for the derivation: a blob asking for
	// more is refused, as Node refuses it.
	scryptMaxMem = 256 << 20
	saltBytes    = 16
	keyBytes     = 32
)

// KDF is a blob's key derivation parameters. N, r and p are JavaScript
// numbers, as the TypeScript server reads them (131072.0 is 131072).
type KDF struct {
	Algorithm string  `json:"algorithm"`
	N         float64 `json:"N"`
	R         float64 `json:"r"`
	P         float64 `json:"p"`
	// Salt is base64.
	Salt string `json:"salt"`
}

// Blob is a passphrase escrow blob (EscrowBlob).
type Blob struct {
	FormatVersion int               `json:"formatVersion"`
	Kind          string            `json:"kind"`
	KDF           KDF               `json:"kdf"`
	Envelope      envelope.Envelope `json:"envelope"`
}

// context binds the KDF's parameters into the envelope's additional data,
// so they cannot be weakened after the fact.
func (k KDF) context() envelope.Context {
	return envelope.Context{"purpose": "kek-escrow", "kdfAlgorithm": k.Algorithm, "N": int64(k.N), "r": int64(k.R), "p": int64(k.P), "salt": k.Salt}
}

// nodeUint32 is Node's validateUint32 on a scrypt option: an integer from
// 0 to 2^32 - 1, refused with Node's message (its ERR_OUT_OF_RANGE writes
// an integer beyond 2^32 with _ between groups of three digits).
func nodeUint32(name string, v float64) error {
	received := string(jsvalue.Stringify(v))
	if v != math.Trunc(v) || math.IsInf(v, 0) {
		return &Error{fmt.Sprintf("The value of %q is out of range. It must be an integer. Received %s", name, received)}
	}
	if v < 0 || v > math.MaxUint32 {
		if math.Abs(v) > 1<<32 {
			received = separated(received)
		}
		return &Error{fmt.Sprintf("The value of %q is out of range. It must be >= 0 && <= 4294967295. Received %s", name, received)}
	}
	return nil
}

// separated is Node's addNumericalSeparator: _ between groups of three
// digits of an integer's text.
func separated(s string) string {
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte('_')
		}
		b.WriteRune(c)
	}
	return sign + b.String()
}

// derive is Node's scryptSync with maxmem 256 MiB: N, r and p each an
// unsigned 32-bit integer (Node's own check), then OpenSSL's scrypt
// checks: N a power of two over 1 and r, p positive, then no more memory
// than maxmem (its blocks, 128 * r * p, and its table, 128 * r * (N + 2)).
func (k KDF) derive(passphrase string) ([]byte, error) {
	for _, o := range []struct {
		name string
		v    float64
	}{{"N", k.N}, {"r", k.R}, {"p", k.P}} {
		if err := nodeUint32(o.name, o.v); err != nil {
			return nil, err
		}
	}
	n, r, p := int64(k.N), int64(k.R), int64(k.P)
	if r <= 0 || p <= 0 || n < 2 || n&(n-1) != 0 {
		return nil, &Error{"Invalid scrypt params"}
	}
	if 128*r*p+128*r*(n+2) > scryptMaxMem {
		return nil, &Error{"Invalid scrypt params: error:030000AC:digital envelope routines::memory limit exceeded"}
	}
	return scrypt.Key([]byte(passphrase), envelope.NodeBase64(k.Salt), int(n), int(r), int(p), keyBytes)
}

func jsLength(s string) int { return len(utf16.Encode([]rune(s))) }

// Export wraps the Root KEK in a passphrase escrow blob (exportKekEscrow).
func Export(rootKEK []byte, passphrase string) (Blob, error) {
	if len(rootKEK) != keyBytes {
		return Blob{}, &Error{"Invalid KEK length"}
	}
	if jsLength(passphrase) < MinPassphraseLength {
		return Blob{}, &Error{"Escrow passphrase must be at least 12 characters"}
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return Blob{}, err
	}
	kdf := KDF{Algorithm: "scrypt", N: scryptN, R: scryptR, P: scryptP, Salt: base64.StdEncoding.EncodeToString(salt)}
	key, err := kdf.derive(passphrase)
	if err != nil {
		return Blob{}, err
	}
	defer clear(key)
	env, err := envelope.Seal(key, rootKEK, kdf.context())
	if err != nil {
		return Blob{}, err
	}
	return Blob{FormatVersion: escrowFormatVersion, Kind: escrowKind, KDF: kdf, Envelope: env}, nil
}

// Restore opens a passphrase escrow blob (restoreKekEscrow).
func Restore(blob Blob, passphrase string) ([]byte, error) {
	if blob.Kind != escrowKind || blob.FormatVersion != escrowFormatVersion {
		return nil, &Error{"Not a supported varlatch KEK escrow blob"}
	}
	if blob.KDF.Algorithm != "scrypt" {
		return nil, &Error{"Unsupported escrow KDF"}
	}
	// Maliciously weakened parameters are refused, even though the
	// additional data would already fail a blob made with others.
	if blob.KDF.N < 1<<14 || blob.KDF.R < 8 || blob.KDF.P < 1 {
		return nil, &Error{"Escrow KDF parameters below the accepted minimum"}
	}
	key, err := blob.KDF.derive(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	kek, err := envelope.Open(key, blob.Envelope, blob.KDF.context())
	if err != nil {
		return nil, &Error{"Decryption failed: authentication error"}
	}
	if len(kek) != keyBytes {
		clear(kek)
		return nil, &Error{"Escrowed key has invalid length"}
	}
	return kek, nil
}

// ParseBlob reads a blob as JSON.parse and the field accesses of
// restoreKekEscrow read it.
func ParseBlob(raw []byte) (Blob, error) {
	var b Blob
	if err := json.Unmarshal(raw, &b); err != nil {
		return Blob{}, errors.Join(&Error{"Not a supported varlatch KEK escrow blob"}, err)
	}
	return b, nil
}
