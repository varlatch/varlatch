// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/lib/release/releasetest"
)

// The test Sigstore (releasetest), which self-update's and the installers'
// tests sign their fake releases with, verifies through the real verifier
// exactly what it signed, for the identity it signed, and nothing else:
// another identity, issuer, file or Sigstore is refused.
func TestTheTestSigstoreVerifies(t *testing.T) {
	s := releasetest.New()
	v, err := NewVerifier(s.TrustedRoot())
	if err != nil {
		t.Fatal(err)
	}
	const version = "0.50.0-rc.2"
	sums := []byte(string(bytes.Repeat([]byte("ab"), 32)) + "  varlatch-0.50.0-rc.2-linux-amd64\n")
	good := s.Sign(sums, Identity(version), Issuer)
	got, err := v.VerifySums(version, sums, good)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["varlatch-0.50.0-rc.2-linux-amd64"]; !ok {
		t.Fatalf("sums %v", got)
	}

	// The trusted root survives the trip through trusted_root.json, as the
	// process tests pass it.
	tr, err := root.NewTrustedRootFromJSON(s.TrustedRootJSON())
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := NewVerifier(tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fromJSON.VerifySums(version, sums, good); err != nil {
		t.Fatalf("through trusted_root.json: %v", err)
	}

	changed := bytes.Clone(sums)
	changed[0] = 'c'
	other := releasetest.New()
	for name, check := range map[string]func() error{
		"changed SHA256SUMS": func() error { _, err := v.VerifySums(version, changed, good); return err },
		"another release's identity": func() error {
			_, err := v.VerifySums(version, sums, s.Sign(sums, Identity("0.50.0-rc.1"), Issuer))
			return err
		},
		"another workflow": func() error {
			_, err := v.VerifySums(version, sums, s.Sign(sums, "https://github.com/"+Repository+"/.github/workflows/other.yml@refs/tags/v"+version, Issuer))
			return err
		},
		"another repository": func() error {
			_, err := v.VerifySums(version, sums, s.Sign(sums, "https://github.com/someone/varlatch/.github/workflows/release.yml@refs/tags/v"+version, Issuer))
			return err
		},
		"another issuer": func() error {
			_, err := v.VerifySums(version, sums, s.Sign(sums, Identity(version), "https://issuer.releasetest.invalid"))
			return err
		},
		"another Sigstore": func() error {
			_, err := v.VerifySums(version, sums, other.Sign(sums, Identity(version), Issuer))
			return err
		},
		"asked as another version": func() error { _, err := v.VerifySums("0.50.0-rc.3", sums, good); return err },
	} {
		if check() == nil {
			t.Errorf("%s: verified", name)
		}
	}
}
