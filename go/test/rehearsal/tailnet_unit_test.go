// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTailnetPieces: the tailnet case's parts that need no container: the
// run's CA and Headscale's certificate for its address, Headscale's
// configuration and policy, the source's overlay, the target's tailnet
// configuration, and the profile's tailnet refusals.
func TestTailnetPieces(t *testing.T) {
	dir := t.TempDir()
	ip := net.ParseIP("172.31.0.5")
	if err := writeTailnetCerts(dir, ip); err != nil {
		t.Fatal(err)
	}
	read := func(name string) *x509.Certificate {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Run("Headscale's certificate verifies for its address against the run's CA only", func(t *testing.T) {
		roots := x509.NewCertPool()
		roots.AddCert(read("ca.pem"))
		leaf := read("hs/tls.crt")
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ip.String(), Roots: roots}); err != nil {
			t.Error(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "172.31.0.6", Roots: roots}); err == nil {
			t.Error("it verifies for another address")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ip.String()}); err == nil {
			t.Error("it verifies without the run's CA")
		}
		if fi, err := os.Stat(filepath.Join(dir, "hs/tls.key")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("tls.key: %v, %v, want 0600", fi.Mode().Perm(), err)
		}
	})
	t.Run("Headscale's configuration and policy", func(t *testing.T) {
		c := headscaleConfig("https://172.31.0.5:8443", "172.31.0.5")
		for _, want := range []string{"server_url: https://172.31.0.5:8443\n", "listen_addr: 0.0.0.0:8443\n", "    ipv4: 172.31.0.5\n", "base_domain: rh.example\n", "urls: []\n", "disable_check_updates: true\n", "logtail:\n  enabled: false\n"} {
			if !strings.Contains(c, want) {
				t.Errorf("the configuration lacks %q", want)
			}
		}
		var p struct {
			TagOwners map[string][]string `json:"tagOwners"`
		}
		if err := json.Unmarshal(headscalePolicy(), &p); err != nil || len(p.TagOwners[tailnetTag]) != 1 || p.TagOwners[tailnetTag][0] != "rh@" {
			t.Errorf("the policy: %s (%v)", headscalePolicy(), err)
		}
	})
	t.Run("the source's overlay", func(t *testing.T) {
		got := tailnetOverlay("https://172.31.0.5:8443", "vl-rh-r1-tailnet", "/w/tailnet")
		for _, want := range []string{
			"  tailscale:\n", "TS_EXTRA_ARGS: --login-server=https://172.31.0.5:8443\n", "SSL_CERT_FILE: /vl-rh-tailnet/ca.pem\n",
			"- /w/tailnet/ca.pem:/vl-rh-tailnet/ca.pem:ro\n", "    networks:\n      vl-rh-tailnet: {}\n", "    external: true\n    name: vl-rh-r1-tailnet\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the overlay lacks %q:\n%s", want, got)
			}
		}
		// Only the CA, never Headscale's key; nothing of varlatchd's.
		if strings.Contains(got, "tls.key") || strings.Contains(got, "varlatchd:") {
			t.Errorf("the overlay: %s", got)
		}
	})
	t.Run("the target's tailnet configuration", func(t *testing.T) {
		got := tailnetConf("rh-tailnet", "https://172.31.0.5:8443")
		want := "tailnet = on\ntailnet_hostname = rh-tailnet\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = {keys}/tailnet-auth-key\ntailnet_control_url = https://172.31.0.5:8443\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		if strings.Contains(tailnetConf("vl-rh-r1-tailnet", ""), "tailnet_control_url") {
			t.Error("Tailscale's control server needs no tailnet_control_url")
		}
	})
	t.Run("an .env loses its auth key line, keeping its mode", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), ".env")
		if err := os.WriteFile(p, []byte("A=1\nTS_AUTHKEY=k\nB=2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := dropEnvLines(p, "TS_AUTHKEY="); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		fi, _ := os.Stat(p)
		if string(b) != "A=1\nB=2\n" || fi.Mode().Perm() != 0o600 {
			t.Errorf("%q, mode %04o", b, fi.Mode().Perm())
		}
		if err := dropEnvLines(filepath.Join(t.TempDir(), "missing"), "TS_AUTHKEY="); err != nil {
			t.Errorf("a missing file: %v", err)
		}
	})
	t.Run("the profile", func(t *testing.T) {
		key := filepath.Join(dir, "key")
		if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		open := filepath.Join(dir, "open-key")
		if err := os.WriteFile(open, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			profile, ingress, oauth, authKey, tailnet, kill, want string
		}{
			{"", "tailnet", "", "", "", "", ""},
			{"", "combined", "", "", "", "", "runs on the box only"},
			{"box", "combined", "", "", "", "", "not built yet"},
			{"", "tailnet", key, key, "tail1.ts.net", "", "owner's session on the box"},
			{"box", "tailnet", key, "", "tail1.ts.net", "", "VL_RH_TAILSCALE_AUTH_KEY_FILE"},
			{"box", "tailnet", key, key, "tail1.ts.net", "", ""},
			{"box", "tailnet", filepath.Join(dir, "missing"), key, "tail1.ts.net", "", "no such file"},
			{"box", "tailnet", key, open, "tail1.ts.net", "", "mode 0644"},
			{"box", "proxy", key, key, "tail1.ts.net", "", "goes with VL_RH_INGRESS=tailnet"},
			{"", "tailnet", "", "", "", "transfer", "leave VL_RH_KILL"},
		} {
			for k, v := range map[string]string{"VL_RH_PROFILE": c.profile, "VL_RH_INGRESS": c.ingress, "VL_RH_TAILSCALE_OAUTH_FILE": c.oauth,
				"VL_RH_TAILSCALE_AUTH_KEY_FILE": c.authKey, "VL_RH_TAILSCALE_TAILNET": c.tailnet, "VL_RH_KILL": c.kill, "VL_RH_ONLY": "", "VL_RH_SYNC": ""} {
				t.Setenv(k, v)
			}
			p, err := readProfile(0)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%+v: %v, want %q", c, err, c.want)
			}
			if err == nil && (p.ingress != "tailnet" || p.tailscaleOAuth != c.oauth) {
				t.Errorf("%+v read as %+v", c, p)
			}
		}
	})
}
