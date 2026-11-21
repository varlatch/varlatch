// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runMove(t *testing.T, env MapEnv, args ...string) (int, string, string) {
	t.Helper()
	full := MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir(), "VARLATCH_ASSISTED": "0"}
	for k, v := range env {
		full[k] = v
	}
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"move"}, args...), full, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

// The refusals before anything changes: a Compose installation's --dir,
// assisted mode, the container, the tailnet ingress, an address that is
// no https host name, the same address, link lifetimes out of range, and
// --abandon with no move open.
func TestMoveRefusals(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a Go installation's move runs on Linux")
	}
	dir := fakeVarlatchd(t)
	conf := filepath.Join(t.TempDir(), "varlatchd.conf")
	if err := os.WriteFile(conf, []byte("public_url = https://vault.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := `{"publicUrl":"https://vault.example.com","ingress":"external","listen":"127.0.0.1:8686","listenHttps":null,"tailnet":true}`
	for _, c := range []struct {
		env     MapEnv
		args    []string
		code    int
		has     string
		varlatd bool // varlatchd is asked (config check) before the refusal
	}{
		{nil, []string{"--public-url", "https://new.example.com", "--dir", "/srv/varlatch"}, 64, "varlatch-ts", false},
		{MapEnv{"VARLATCH_ASSISTED": "1"}, []string{"--public-url", "https://new.example.com"}, 78, "not in assisted mode", false},
		{MapEnv{"VARLATCH_IMAGE": "varlatchd"}, []string{"--public-url", "https://new.example.com"}, 64, "in the container, a move is by hand", false},
		{nil, []string{"--public-url", "https://new.example.com", "--reenroll-hours", "0"}, 64, "from 1 to 168", false},
		{nil, []string{"--public-url", "https://new.example.com", "--reenroll-hours", "169"}, 64, "from 1 to 168", false},
		{nil, []string{"--public-url", "https://new.example.com", "--ingress", "tailnet"}, 64, "the tailnet node keeps its own name and state", true},
		{nil, []string{"--public-url", "https://new.example.com", "--ingress", "sideways"}, 64, "--ingress must be one of public, external", true},
		{nil, []string{"--public-url", "http://new.example.com"}, 64, "an https:// address", true},
		{nil, []string{"--public-url", "https://new.example.com/vault"}, 64, "an https:// address", true},
		{nil, []string{"--public-url", "https://192.0.2.7"}, 64, "IP address", true},
		{nil, []string{"--public-url", "https://VAULT.example.com:443/"}, 64, "already answers at https://vault.example.com", true},
		{nil, []string{"--public-url", "https://vault.example.com", "--ingress", "public"}, 64, "changing only the ingress is not a move", true},
		{nil, []string{}, 64, "pass --public-url", true},
		{nil, []string{"--abandon"}, 64, "no move in progress", false},
		{nil, []string{"--abandon", "--yes"}, 64, "Usage:", false},
	} {
		answer(t, dir, facts, "", 0)
		env := MapEnv{"PATH": dir}
		for k, v := range c.env {
			env[k] = v
		}
		code, out, errText := runMove(t, env, append(c.args, "--config", conf)...)
		if code != c.code || !strings.Contains(errText+out, c.has) {
			t.Errorf("%v: %d %q %q, want %d and %q", c.args, code, out, errText, c.code, c.has)
		}
		got := called(t, dir)
		if c.varlatd != (got != nil) || got != nil && strings.Join(got, " ") != "admin config check --config "+conf {
			t.Errorf("%v: varlatchd ran %q", c.args, got)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(conf), moveJournal)); !os.IsNotExist(err) {
			t.Fatalf("%v: a journal was written", c.args)
		}
		if raw, _ := os.ReadFile(conf); string(raw) != "public_url = https://vault.example.com\n" {
			t.Fatalf("%v: the configuration changed: %q", c.args, raw)
		}
	}
}

// The configuration a move writes: public_url replaced where it is (a
// byte order mark and comments kept, a commented-out setting left alone),
// or added; the listeners of the ingress it goes to; nothing of the
// tailnet touched.
func TestMovedConfig(t *testing.T) {
	bom := "\uFEFF"
	text := bom + "# my installation\n#public_url = https://example.invalid\npublic_url = https://vault.example.com\ntailnet = on\ntailnet_hostname = vault\nlisten = 127.0.0.1:8686\n"
	got := movedConfig(text, "https://vault2.example.com", "external", "external", "")
	want := bom + "# my installation\n#public_url = https://example.invalid\npublic_url = https://vault2.example.com\ntailnet = on\ntailnet_hostname = vault\nlisten = 127.0.0.1:8686\n"
	if got != want {
		t.Fatalf("same ingress:\n%q\nwant\n%q", got, want)
	}
	toPublic := movedConfig(text, "https://vault2.example.com", "external", "public", "")
	if !strings.HasSuffix(toPublic, "listen = 127.0.0.1:8686\nlisten_https = :443\n") || !strings.Contains(toPublic, "tailnet_hostname = vault\n") {
		t.Fatalf("to the public ingress:\n%q", toPublic)
	}
	if got := movedConfig(text, "https://vault2.example.com", "external", "public", "127.0.0.1:8443"); !strings.Contains(got, "listen_https = 127.0.0.1:8443\n") {
		t.Fatalf("--listen-https:\n%q", got)
	}
	public := "public_url = https://vault.example.com\nlisten_https = :443\nlisten_http_redirect = :80\nacme_email = ops@example.com\nacme_ca = https://ca.example/dir\nacme_ca_root = /etc/varlatch/ca.pem\ntailnet = on\n"
	if got := movedConfig(public, "https://proxy.example.com", "public", "external", ""); got != "public_url = https://proxy.example.com\ntailnet = on\n" {
		t.Fatalf("to the external ingress:\n%q", got)
	}
	if got := setConfValue("listen = 127.0.0.1:8686", "public_url", "https://a.example.com"); got != "listen = 127.0.0.1:8686\npublic_url = https://a.example.com\n" {
		t.Fatalf("added: %q", got)
	}
}

// `admin reenroll` runs varlatchd's reenroll with --json and shows each
// person and link, the link's token in full (the fail-safe shows exactly
// it), names through Printable; an answer it does not recognise as a link
// is never printed; assisted mode is refused before varlatchd runs.
func TestAdminReenroll(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake varlatchd is a Unix program here")
	}
	dir := fakeVarlatchd(t)
	token := "vlt_reenroll_" + strings.Repeat("Ab3_", 10)
	answer(t, dir, `{"links":[{"identityId":"idn_a","name":"Ada\u001b[31m","installationAdmin":true,"link":"https://vault.example.com/enroll#`+token+`","expiresAt":"2026-11-21T08:00:00.000Z"}]}`, "", 0)
	code, out, errText := runAdmin(t, dir, "reenroll", "--all", "--hours", "2", "--config", "/etc/varlatch/varlatchd.conf")
	if code != 0 || errText != "" || !strings.Contains(out, "  Ada\\u001b[31m (Installation Admin) [idn_a]\n    https://vault.example.com/enroll#"+token+"\n") ||
		!strings.Contains(out, "They expire 2026-11-21T08:00:00.000Z.") {
		t.Fatalf("%d %q %q", code, out, errText)
	}
	if got := strings.Join(called(t, dir), " "); got != "admin reenroll --json --all --hours 2 --config /etc/varlatch/varlatchd.conf" {
		t.Fatalf("varlatchd ran %q", got)
	}
	answer(t, dir, `{"links":[{"identityId":"idn_a","name":"Ada","installationAdmin":false,"link":"https://vault.example.com/elsewhere#`+token+`","expiresAt":"x"}]}`, "", 0)
	if code, out, errText := runAdmin(t, dir, "reenroll", "--identity", "idn_a"); code == 0 || strings.Contains(out+errText, token) {
		t.Fatalf("an unrecognised link: %d %q %q", code, out, errText)
	}
	answer(t, dir, "", "", 0)
	if code, _, errText := runAdminWith(t, MapEnv{"PATH": dir, "VARLATCH_ASSISTED": "1"}, "reenroll", "--all"); code != 78 || !strings.Contains(errText, "not in assisted mode") || called(t, dir) != nil {
		t.Fatalf("assisted: %d %q", code, errText)
	}
}
