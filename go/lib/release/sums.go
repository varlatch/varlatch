// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Sums maps an asset's file name to its SHA-256, as SHA256SUMS lists it.
type Sums map[string][sha256.Size]byte

var (
	// ErrNotListed means SHA256SUMS has no line for the asset.
	ErrNotListed = errors.New("release: the asset is not listed in SHA256SUMS")
	// ErrMismatch means the asset's content is not what SHA256SUMS lists:
	// changed, or cut off.
	ErrMismatch = errors.New("release: the asset does not match SHA256SUMS")
)

// ParseSums reads SHA256SUMS in the format sha256sum writes: one line per
// file, 64 hex digits, a space, then a space (text) or '*' (binary), then
// the name. Names are plain file names; a line that is not well formed, or
// a name listed twice, is an error.
func ParseSums(data []byte) (Sums, error) {
	sums := Sums{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			continue
		}
		if len(line) < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') {
			return nil, fmt.Errorf("release: SHA256SUMS line %d is not \"<sha256>  <name>\"", n)
		}
		digest, err := hex.DecodeString(line[:64])
		if err != nil {
			return nil, fmt.Errorf("release: SHA256SUMS line %d has no SHA-256", n)
		}
		name := line[66:]
		if strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
			return nil, fmt.Errorf("release: SHA256SUMS line %d names a path, not a file", n)
		}
		if _, dup := sums[name]; dup {
			return nil, fmt.Errorf("release: SHA256SUMS lists %s twice", name)
		}
		sums[name] = [sha256.Size]byte(digest)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("release: reading SHA256SUMS: %w", err)
	}
	if len(sums) == 0 {
		return nil, errors.New("release: SHA256SUMS lists nothing")
	}
	return sums, nil
}

// Check reads an asset to the end and compares it with its line. A cut-off
// download fails as a mismatch.
func (s Sums) Check(name string, r io.Reader) error {
	want, ok := s[name]
	if !ok {
		return ErrNotListed
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("release: reading %s: %w", name, err)
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want[:]) != 1 {
		return fmt.Errorf("%w: %s", ErrMismatch, name)
	}
	return nil
}
