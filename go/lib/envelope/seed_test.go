// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"testing"
)

// A seed opens only as a seed, with the ids and the parameters it was
// sealed with; opened as a value, it is an envelope without the seed in it.
func TestSeedsOpenAsSeedsOnly(t *testing.T) {
	kek, seed := GenerateKey(), []byte("otpauth://totp/x?secret=MADEUPMADEUPMADEUP")
	const params = `{"issuer":"x"}`
	v, err := EncryptSeed(kek, "org", "val", "ver", params, seed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSeed(kek, "org", "val", "ver", params, v)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("%q, %v", got, err)
	}
	value, err := DecryptValue(kek, "org", "val", "ver", v)
	if err != nil || bytes.Contains(value, []byte("otpauth")) || bytes.Contains(value, []byte("MADEUP")) {
		t.Errorf("as a value: %q, %v", value, err)
	}
	for what, open := range map[string]func() ([]byte, error){
		"another organization": func() ([]byte, error) { return DecryptSeed(kek, "other", "val", "ver", params, v) },
		"another value":        func() ([]byte, error) { return DecryptSeed(kek, "org", "other", "ver", params, v) },
		"another version":      func() ([]byte, error) { return DecryptSeed(kek, "org", "val", "other", params, v) },
		"other parameters":     func() ([]byte, error) { return DecryptSeed(kek, "org", "val", "ver", `{"issuer":"y"}`, v) },
		"another key":          func() ([]byte, error) { return DecryptSeed(GenerateKey(), "org", "val", "ver", params, v) },
	} {
		if p, err := open(); err == nil {
			t.Errorf("%s: opened %q", what, p)
		}
	}
	// A value is no seed.
	plain, err := EncryptValue(kek, "org", "val", "ver", seed)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := DecryptSeed(kek, "org", "val", "ver", params, plain); err == nil {
		t.Errorf("a value opened as a seed: %q", p)
	}
}
