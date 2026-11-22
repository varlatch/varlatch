// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSyncStandIns: the sync case's pieces that need no container: the
// run's CA and the stand-ins' certificate, the target's trust roots, the
// source's Compose overlay, the runner's /etc/hosts lines, and the target
// varlatchd's environment file.
func TestSyncStandIns(t *testing.T) {
	dir := t.TempDir()
	if err := writeFakesCerts(dir, fakeHosts); err != nil {
		t.Fatal(err)
	}
	cert := func(name string) *x509.Certificate {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatalf("%s is not PEM", name)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Run("the certificate verifies for each name against the run's CA", func(t *testing.T) {
		roots := x509.NewCertPool()
		roots.AddCert(cert("ca.pem"))
		leaf := cert("cert.pem")
		for _, h := range fakeHosts {
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: h, Roots: roots}); err != nil {
				t.Errorf("%s: %v", h, err)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "github.com", Roots: roots}); err == nil {
			t.Error("the certificate verifies for a name it was not made for")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: fakeHosts[0]}); err == nil {
			t.Error("the certificate verifies without the run's CA")
		}
		for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
			if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm()&0o004 == 0 {
				t.Errorf("%s is not readable by the stand-ins' user: %v", name, err)
			}
		}
	})
	t.Run("the target's roots: the system's and the run's CA", func(t *testing.T) {
		system := filepath.Join(t.TempDir(), "system.pem")
		if err := os.WriteFile(system, []byte("system roots"), 0o644); err != nil {
			t.Fatal(err)
		}
		path, err := goRoots(dir, system)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		ca, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
		if !strings.HasPrefix(string(b), "system roots\n") || !strings.HasSuffix(string(b), string(ca)) {
			t.Errorf("roots: %q", b)
		}
		// Without the system's: the run's CA alone.
		path, err = goRoots(dir, filepath.Join(dir, "missing.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != string(ca) {
			t.Errorf("roots without the system's: %q", b)
		}
	})
	t.Run("the source's overlay", func(t *testing.T) {
		got := syncOverlay("vl-rh-r1-sync", "172.30.0.2", "/w/sync-fakes")
		for _, want := range []string{
			"    env_file:\n      - /w/sync-fakes/source.env\n",
			`- "api.github.com:172.30.0.2"`, `- "coolify.conformance.test:172.30.0.2"`, `- "convex.conformance.test:172.30.0.2"`,
			"- /w/sync-fakes:/vl-rh-sync:ro",
			"    networks:\n      vl-rh-sync: {}\n",
			"networks:\n  vl-rh-sync:\n    external: true\n    name: vl-rh-r1-sync\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the overlay lacks %q:\n%s", want, got)
			}
		}
		// The default network stays (a map merges with the base file's).
		if strings.Contains(got, "- default") {
			t.Errorf("the overlay lists networks, which replaces the base file's: %s", got)
		}
		// No environment of its own: merged, it reads as a list to migrate.
		if strings.Contains(got, "environment:") {
			t.Errorf("the overlay sets environment: %s", got)
		}
	})
	t.Run("the runner's hosts lines", func(t *testing.T) {
		orig := "127.0.0.1\tlocalhost\n::1\tlocalhost"
		once := withFakeHosts(orig, "172.30.0.2")
		want := orig + "\n172.30.0.2 api.github.com coolify.conformance.test convex.conformance.test " + hostsMarker + "\n"
		if once != want {
			t.Errorf("added: %q, want %q", once, want)
		}
		if again := withFakeHosts(once, "172.30.0.3"); strings.Count(again, hostsMarker) != 1 || !strings.Contains(again, "172.30.0.3 api.github.com") {
			t.Errorf("added twice: %q", again)
		}
		if back := withoutFakeHosts(once); back != orig+"\n" {
			t.Errorf("removed: %q", back)
		}
	})
	t.Run("the target's environment file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "service.env")
		if got := serviceEnv(p); got != nil {
			t.Errorf("missing file: %q", got)
		}
		if err := os.WriteFile(p, []byte("# roots\nSSL_CERT_FILE=/x/roots.pem\n\nnot a line\n A=b \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(serviceEnv(p), ";"); got != "SSL_CERT_FILE=/x/roots.pem;A=b" {
			t.Errorf("read %q", got)
		}
	})
}
