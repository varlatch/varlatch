// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Public fixtures from lib/release: v0.21.0's SHA256SUMS, its signature
// bundle, one of its assets, and a snapshot of Sigstore's trusted root.
const td = "../../lib/release/testdata/"

func verifyArgs(extra ...string) []string {
	return append([]string{"verify-release", "--version", "0.21.0", "--sums", td + "v0.21.0/SHA256SUMS",
		"--bundle", td + "v0.21.0/SHA256SUMS.sigstore.json", "--trusted-root", td + "trusted_root.json"}, extra...)
}

func TestVerifyRelease(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(verifyArgs("--file", td+"v0.21.0/Caddyfile=Caddyfile"), strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "release.yml@refs/tags/v0.21.0") || !strings.Contains(out.String(), "matches SHA256SUMS (Caddyfile)") {
		t.Fatal(out.String())
	}
}

func TestVerifyReleaseRefuses(t *testing.T) {
	changed := filepath.Join(t.TempDir(), "Caddyfile")
	data, _ := os.ReadFile(td + "v0.21.0/Caddyfile")
	_ = os.WriteFile(changed, append(data, '\n'), 0o600)
	for name, args := range map[string][]string{
		"changed file":      verifyArgs("--file", changed+"=Caddyfile"),
		"unlisted name":     verifyArgs("--file", td+"v0.21.0/Caddyfile=varlatch-0.21.0-linux-amd64"),
		"other release":     {"verify-release", "--version", "0.20.0", "--sums", td + "v0.21.0/SHA256SUMS", "--bundle", td + "v0.21.0/SHA256SUMS.sigstore.json", "--trusted-root", td + "trusted_root.json"},
		"other bundle":      {"verify-release", "--version", "0.21.0", "--sums", td + "v0.21.0/SHA256SUMS", "--bundle", td + "v0.20.0/SHA256SUMS.sigstore.json", "--trusted-root", td + "trusted_root.json"},
		"unsigned version":  {"verify-release", "--version", "0.15.0", "--sums", td + "v0.21.0/SHA256SUMS", "--bundle", td + "v0.21.0/SHA256SUMS.sigstore.json", "--trusted-root", td + "trusted_root.json"},
		"missing sums file": {"verify-release", "--version", "0.21.0", "--sums", "/nonexistent", "--bundle", td + "v0.21.0/SHA256SUMS.sigstore.json", "--trusted-root", td + "trusted_root.json"},
		"bad --file":        verifyArgs("--file", "no-equals-sign"),
	} {
		var out, errOut bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errOut); code != 1 {
			t.Errorf("%s: exit %d, %s", name, code, errOut.String())
		}
		if strings.Contains(out.String(), "matches SHA256SUMS ("+filepath.Base(changed)) && name == "changed file" {
			t.Errorf("%s: reported a match", name)
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"verify-release", "--version", "0.21.0"}, strings.NewReader(""), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
		t.Fatalf("usage: exit %d %s", code, errOut.String())
	}
}

// verify-release's failures never show a URL's user name and password,
// even one %q would escape (Sol, #265 round 1).
func TestVerifyReleaseNeverEchoesUserinfo(t *testing.T) {
	for _, args := range [][]string{
		verifyArgs("--file", `https://alice:fa"ke-pw@h`),
		verifyArgs("--file", `https://alice:se\cret-pw@h`),
		verifyArgs("--file", "https://alice:fake-pw@h=Caddyfile"),
		{"verify-release", "--version", "1.2.3", "--sums", "https://alice:fake-pw@h/SHA256SUMS", "--bundle", "x"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code == 0 {
			t.Fatalf("%q succeeded", args)
		}
		if out := stdout.String() + stderr.String(); strings.Contains(out, "-pw") || strings.Contains(out, "alice") || !strings.Contains(out, "[redacted]@") {
			t.Errorf("%q:\n%s", args, out)
		}
	}
}
