// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// The testdata are public: v0.20.0's and v0.21.0's SHA256SUMS and
// SHA256SUMS.sigstore.json as published on GitHub, and Sigstore's
// trusted_root.json fetched through its TUF repository on 2026-11-13.
func verifier(t *testing.T) *Verifier {
	t.Helper()
	tr, err := root.NewTrustedRootFromPath("testdata/trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(tr)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifiesSignedReleases(t *testing.T) {
	v := verifier(t)
	for _, version := range []string{"0.20.0", "0.21.0"} {
		sums, err := v.VerifySums(version, read(t, "testdata/v"+version+"/SHA256SUMS"), read(t, "testdata/v"+version+"/SHA256SUMS.sigstore.json"))
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if _, ok := sums["varlatch-cli-"+version+".cjs"]; !ok || len(sums) < 5 {
			t.Fatalf("%s: sums %v", version, sums)
		}
	}
}

// A bundle in the newer Sigstore format verifies too: cosign 3.1.4's own
// signed checksums (signed by Sigstore's release identity, used here
// through the internal hook only tests have).
func TestVerifiesNewBundleFormat(t *testing.T) {
	v := verifier(t)
	blob, bundle := read(t, "testdata/cosign-v3.1.4/cosign_checksums.txt"), read(t, "testdata/cosign-v3.1.4/cosign_checksums.txt.sigstore.json")
	const san, issuer = "keyless@projectsigstore.iam.gserviceaccount.com", "https://accounts.google.com"
	if err := v.verifyBlob(blob, bundle, san, issuer); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(blob)
	changed[0] ^= 1
	for name, err := range map[string]error{
		"changed blob": v.verifyBlob(changed, bundle, san, issuer),
		"other SAN":    v.verifyBlob(blob, bundle, "keyless@example.com", issuer),
		"other issuer": v.verifyBlob(blob, bundle, san, Issuer),
		"as a release": func() error { _, err := v.VerifySums("0.21.0", blob, bundle); return err }(),
	} {
		if err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// The conversion of cosign's earlier bundle refuses what it cannot carry
// over faithfully, rather than guessing.
func TestCosignBundleConversionRefuses(t *testing.T) {
	orig := read(t, "testdata/v0.21.0/SHA256SUMS.sigstore.json")
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(orig, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	rekor := func(m map[string]any) map[string]any { return m["rekorBundle"].(map[string]any) }
	payload := func(m map[string]any) map[string]any { return rekor(m)["Payload"].(map[string]any) }
	for name, data := range map[string][]byte{
		"no rekorBundle": edit(func(m map[string]any) { delete(m, "rekorBundle") }),
		"no SET":         edit(func(m map[string]any) { delete(rekor(m), "SignedEntryTimestamp") }),
		"no cert":        edit(func(m map[string]any) { m["cert"] = "" }),
		"cert not PEM":   edit(func(m map[string]any) { m["cert"] = base64.StdEncoding.EncodeToString([]byte("nope")) }),
		"log id not hex": edit(func(m map[string]any) { payload(m)["logID"] = "zz" }),
		"body not an entry": edit(func(m map[string]any) {
			payload(m)["body"] = base64.StdEncoding.EncodeToString([]byte(`{"kind":"intoto"}`))
		}),
		"neither format": []byte(`{"signature":"x"}`),
	} {
		if _, err := readBundle(data); err == nil {
			t.Errorf("%s: converted", name)
		}
	}
	// A converted bundle whose evidence was changed does not verify.
	v := verifier(t)
	sums := read(t, "testdata/v0.21.0/SHA256SUMS")
	for name, data := range map[string][]byte{
		"later integrated time": edit(func(m map[string]any) { payload(m)["integratedTime"] = payload(m)["integratedTime"].(float64) + 1 }),
		"other log index":       edit(func(m map[string]any) { payload(m)["logIndex"] = payload(m)["logIndex"].(float64) + 1 }),
		"other signature": edit(func(m map[string]any) {
			sig, _ := base64.StdEncoding.DecodeString(m["base64Signature"].(string))
			sig[len(sig)-1] ^= 1
			m["base64Signature"] = base64.StdEncoding.EncodeToString(sig)
		}),
	} {
		if _, err := v.VerifySums("0.21.0", sums, data); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// Fail closed on everything that is not this release's own signature.
func TestRefuses(t *testing.T) {
	v := verifier(t)
	sums21, bundle21 := read(t, "testdata/v0.21.0/SHA256SUMS"), read(t, "testdata/v0.21.0/SHA256SUMS.sigstore.json")
	sums20, bundle20 := read(t, "testdata/v0.20.0/SHA256SUMS"), read(t, "testdata/v0.20.0/SHA256SUMS.sigstore.json")
	tampered := bytes.Clone(sums21)
	tampered[0] ^= 1
	for name, tc := range map[string]struct {
		version      string
		sums, bundle []byte
	}{
		"another release's identity": {"0.20.0", sums21, bundle21},
		"a later release's identity": {"0.22.0", sums21, bundle21},
		"another release's bundle":   {"0.21.0", sums21, bundle20},
		"another release's sums":     {"0.21.0", sums20, bundle21},
		"changed sums":               {"0.21.0", tampered, bundle21},
		"cut-off sums":               {"0.21.0", sums21[:len(sums21)-10], bundle21},
		"no bundle":                  {"0.21.0", sums21, nil},
		"cut-off bundle":             {"0.21.0", sums21, bundle21[:len(bundle21)/2]},
		"not JSON":                   {"0.21.0", sums21, []byte("not a bundle")},
	} {
		if _, err := v.VerifySums(tc.version, tc.sums, tc.bundle); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestVersions(t *testing.T) {
	v := verifier(t)
	sums, bundle := read(t, "testdata/v0.21.0/SHA256SUMS"), read(t, "testdata/v0.21.0/SHA256SUMS.sigstore.json")
	for _, version := range []string{"", "v0.21.0", "0.21", "0.21.0 ", "0.21.0@refs/heads/main", "0.21.0/x", "00.21.0", "0.21.0-", "0.21.0+build", "../0.21.0", "0.21.0\n"} {
		if _, err := v.VerifySums(version, sums, bundle); !errors.Is(err, ErrVersion) {
			t.Errorf("%q: %v", version, err)
		}
	}
	for _, version := range []string{"0.15.0", "0.14.9", "0.1.0", "0.15.0-rc.1"} {
		if _, err := v.VerifySums(version, sums, bundle); !errors.Is(err, ErrUnsigned) {
			t.Errorf("%q: %v", version, err)
		}
	}
	for _, version := range []string{"0.15.1", "0.50.0", "1.0.0", "0.50.0-rc.1", "10.0.0"} {
		if err := checkVersion(version); err != nil {
			t.Errorf("%q refused: %v", version, err)
		}
	}
	if Identity("0.21.0") != "https://github.com/varlatch/varlatch/.github/workflows/release.yml@refs/tags/v0.21.0" {
		t.Fatal(Identity("0.21.0"))
	}
}

func TestSums(t *testing.T) {
	asset := []byte("the operator CLI")
	digest := sha256.Sum256(asset)
	line := hex.EncodeToString(digest[:])
	sums, err := ParseSums([]byte(line + "  varlatch\n" + line + " *varlatch.exe\r\n\n"))
	if err != nil || len(sums) != 2 {
		t.Fatalf("%v %v", sums, err)
	}
	if err := sums.Check("varlatch", bytes.NewReader(asset)); err != nil {
		t.Fatal(err)
	}
	if err := sums.Check("varlatch", bytes.NewReader(asset[:5])); !errors.Is(err, ErrMismatch) {
		t.Fatalf("cut-off asset: %v", err)
	}
	if err := sums.Check("varlatch", bytes.NewReader(append(bytes.Clone(asset), 'x'))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("longer asset: %v", err)
	}
	if err := sums.Check("other", bytes.NewReader(asset)); !errors.Is(err, ErrNotListed) {
		t.Fatalf("unlisted: %v", err)
	}
	for _, bad := range []string{
		"", "\n", line + " varlatch", line[:63] + "   varlatch", strings.ToUpper(line[:1]) + "g" + line[2:] + "  x",
		line + "  a/b", line + "  ..", line + "  x\n" + line + "  x", line + "\tvarlatch",
	} {
		if s, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("%q parsed: %v", bad, s)
		}
	}
	// The real file parses.
	real, err := ParseSums(read(t, "testdata/v0.21.0/SHA256SUMS"))
	if err != nil || len(real) < 10 {
		t.Fatalf("%d entries, %v", len(real), err)
	}
}

// The live path, through Sigstore's TUF repository; needs the network, so
// it runs only when asked: VARLATCH_TEST_SIGSTORE_TUF=1.
func TestLiveTrustedRoot(t *testing.T) {
	if os.Getenv("VARLATCH_TEST_SIGSTORE_TUF") != "1" {
		t.Skip("set VARLATCH_TEST_SIGSTORE_TUF=1 to fetch Sigstore's trusted root")
	}
	tr, err := LiveTrustedRoot(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifySums("0.21.0", read(t, "testdata/v0.21.0/SHA256SUMS"), read(t, "testdata/v0.21.0/SHA256SUMS.sigstore.json")); err != nil {
		t.Fatal(fmt.Errorf("live: %w", err))
	}
}
