// SPDX-License-Identifier: AGPL-3.0-or-later

package custody

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Shamir secret sharing over GF(2^8) with the reduction polynomial
// x^8 + x^4 + x^3 + x + 1 (escrow.ts splitKek and combineKek): one random
// polynomial of degree k-1 per key byte, its constant term the byte, the
// shares its values at x = 1..n. A share is
//
//	vlks1.<x>.<k>.<the 32 values, base64url>.<fingerprint>
//
// the fingerprint the first 8 hex digits of the key's SHA-256, so a
// mistyped or mixed set of shares is noticed offline.

const sharePrefix = "vlks1"

func gfMul(a, b byte) byte {
	var p byte
	for b > 0 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// gfInv is a^254, the inverse of a nonzero a.
func gfInv(a byte) byte {
	r := byte(1)
	for range 254 {
		r = gfMul(r, a)
	}
	return r
}

// Fingerprint is the key's fingerprint as a share carries it.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:8]
}

// Split splits the Root KEK into n shares, any k of which reconstruct it
// (2 <= k <= n <= 255).
func Split(rootKEK []byte, n, k int) ([]string, string, error) {
	if len(rootKEK) != keyBytes {
		return nil, "", &Error{"Invalid KEK length"}
	}
	if k < 2 || n < k || n > 255 {
		return nil, "", &Error{"Require 2 <= threshold <= shares <= 255"}
	}
	polys := make([][]byte, keyBytes)
	for i := range polys {
		polys[i] = make([]byte, k)
		polys[i][0] = rootKEK[i]
		if _, err := rand.Read(polys[i][1:]); err != nil {
			return nil, "", err
		}
	}
	defer func() {
		for _, p := range polys {
			clear(p)
		}
	}()
	fp := Fingerprint(rootKEK)
	shares := make([]string, 0, n)
	for x := 1; x <= n; x++ {
		y := make([]byte, keyBytes)
		for i, poly := range polys {
			var acc byte
			for c := k - 1; c >= 0; c-- {
				acc = gfMul(acc, byte(x)) ^ poly[c]
			}
			y[i] = acc
		}
		shares = append(shares, fmt.Sprintf("%s.%d.%d.%s.%s", sharePrefix, x, k, base64.RawURLEncoding.EncodeToString(y), fp))
		clear(y)
	}
	return shares, fp, nil
}

type share struct {
	x           int
	threshold   float64 // a JavaScript number: Number.isInteger allows any size
	y           []byte
	fingerprint string
}

// jsInteger is Number(s) when Number.isInteger holds for it.
func jsInteger(s string) (float64, bool) {
	n := jsvalue.ToNumber(s)
	return n, !math.IsNaN(n) && !math.IsInf(n, 0) && n == math.Trunc(n)
}

var hex8 = func(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func parseShare(s string) (share, error) {
	parts := strings.Split(strings.TrimFunc(s, jsvalue.IsWhitespace), ".")
	if len(parts) != 5 || parts[0] != sharePrefix {
		return share{}, &Error{"Malformed share (expected vlks1.<x>.<k>.<data>.<fingerprint>)"}
	}
	x, okX := jsInteger(parts[1])
	k, okK := jsInteger(parts[2])
	if !okX || x < 1 || x > 255 || !okK || k < 2 {
		return share{}, &Error{"Malformed share coordinates"}
	}
	y := envelope.NodeBase64(parts[3])
	if len(y) != keyBytes || !hex8(parts[4]) {
		return share{}, &Error{"Malformed share payload"}
	}
	return share{x: int(x), threshold: k, y: y, fingerprint: parts[4]}, nil
}

// Combine reconstructs the Root KEK from shares of one split: every share
// of the same threshold and fingerprint, no x twice, at least the
// threshold of them (the first that many are used); the result must match
// the fingerprint.
func Combine(shareStrings []string) ([]byte, error) {
	if len(shareStrings) == 0 {
		return nil, &Error{"No shares provided"}
	}
	shares := make([]share, 0, len(shareStrings))
	for _, s := range shareStrings {
		p, err := parseShare(s)
		if err != nil {
			return nil, err
		}
		shares = append(shares, p)
	}
	threshold, fp := shares[0].threshold, shares[0].fingerprint
	xs := map[int]bool{}
	for _, s := range shares {
		if s.threshold != threshold || s.fingerprint != fp {
			return nil, &Error{"Shares are from different splits (threshold/fingerprint mismatch)"}
		}
	}
	for _, s := range shares {
		xs[s.x] = true
	}
	if len(xs) != len(shares) {
		return nil, &Error{"Duplicate shares provided"}
	}
	if float64(len(shares)) < threshold {
		return nil, &Error{fmt.Sprintf("Need %s distinct shares, got %d", jsvalue.Stringify(threshold), len(shares))}
	}
	used := shares[:int(threshold)]
	secret := make([]byte, keyBytes)
	for b := range keyBytes {
		var acc byte
		for _, si := range used {
			// The Lagrange basis at 0: the product of x_j / (x_j ^ x_i).
			basis := byte(1)
			for _, sj := range used {
				if sj.x == si.x {
					continue
				}
				basis = gfMul(basis, gfMul(byte(sj.x), gfInv(byte(sj.x^si.x))))
			}
			acc ^= gfMul(si.y[b], basis)
		}
		secret[b] = acc
	}
	if Fingerprint(secret) != fp {
		clear(secret)
		return nil, &Error{"Combined key does not match the split's fingerprint (wrong or corrupted share)"}
	}
	return secret, nil
}

var randRead = rand.Read
