// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) Env { return func(k string) string { return vars[k] } }

func TestParseDefaults(t *testing.T) {
	c, err := Parse(strings.NewReader("# nothing but a comment\n\n"), env(map[string]string{"CREDENTIALS_DIRECTORY": "/run/credentials/varlatchd.service"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != DefaultListen || c.DataDir != DefaultDataDir || c.RootKEKFile != "/run/credentials/varlatchd.service/root-kek" ||
		c.AccessLog != "stdout" || !c.Sync || c.SyncAdapters != nil || c.PublicURL != nil || c.TrustedProxies != "" ||
		c.BackupKeyFile != "" || c.BackupInterval != 24*time.Hour || c.BackupKeep != 7 || c.BackupDestinationsFile != "" || c.BackupDestination != "offsite" {
		t.Errorf("defaults: %+v", c)
	}
	c, err = Parse(strings.NewReader(""), env(map[string]string{"CREDENTIALS_DIRECTORY": "/c", "STATE_DIRECTORY": "/var/lib/varlatch-x:/other"}))
	if err != nil || c.DataDir != "/var/lib/varlatch-x" || c.DatabasePath() != "/var/lib/varlatch-x/varlatch.db" {
		t.Errorf("STATE_DIRECTORY: %+v, %v", c, err)
	}
	if c, err := Parse(strings.NewReader("root_kek_file = /k\nbackup_interval = off\n"), env(nil)); err != nil || c.BackupInterval != 0 {
		t.Errorf("backup_interval off: %+v, %v", c, err)
	}
}

func TestParseEverySetting(t *testing.T) {
	file := "\ufeff# varlatchd.conf\n" +
		"listen = 0.0.0.0:443\n" +
		"  public_url=https://varlatch.example.com  \n" +
		"data_dir = /srv/varlatch/\n" +
		"root_kek_file = /etc/varlatch/root-kek\n" +
		"trusted_proxies = 10.0.0.0/8, caddy\n" +
		"outbound_allow = hooks.internal, 10.0.0.0/8:443, [::1/128]:*\n" +
		"access_log = /var/log/varlatch/access.log\n" +
		"sync = off\n" +
		"sync_adapters = coolify, convex\n" +
		"audit_export = off\n" +
		"backup_key_file = /etc/varlatch/bek\n" +
		"backup_interval = 12h\n" +
		"backup_keep = 30\n" +
		"backup_destinations_file = /etc/varlatch/destinations.json\n" +
		"backup_destination = b2-eu\n" +
		"   # an indented comment\n"
	c, err := Parse(strings.NewReader(file), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:443" || c.PublicURL.String() != "https://varlatch.example.com" || c.DataDir != "/srv/varlatch" ||
		c.RootKEKFile != "/etc/varlatch/root-kek" || c.TrustedProxies != "10.0.0.0/8, caddy" ||
		c.AccessLog != "/var/log/varlatch/access.log" || c.OutboundAllow != "hooks.internal, 10.0.0.0/8:443, [::1/128]:*" || c.Sync || !slices.Equal(c.SyncAdapters, []string{"coolify", "convex"}) || c.AuditExport ||
		c.BackupKeyFile != "/etc/varlatch/bek" || c.BackupInterval != 12*time.Hour || c.BackupKeep != 30 ||
		c.BackupDestinationsFile != "/etc/varlatch/destinations.json" || c.BackupDestination != "b2-eu" {
		t.Errorf("%+v", c)
	}
}

// Every one of these is a configuration error no retry can fix: *Error.
func TestParseErrors(t *testing.T) {
	kek := "root_kek_file = /k\n"
	for name, file := range map[string]string{
		"no equals sign":                   kek + "listen 127.0.0.1:1\n",
		"unknown setting":                  kek + "port = 8686\n",
		"repeated setting":                 kek + "listen = 127.0.0.1:1\nlisten = 127.0.0.1:2\n",
		"listen without a port":            kek + "listen = 127.0.0.1\n",
		"listen port too large":            kek + "listen = 127.0.0.1:65536\n",
		"listen on a host name":            kek + "listen = localhost:8686\n",
		"public_url not a URL":             kek + "public_url = varlatch.example.com\n",
		"public_url with a query":          kek + "public_url = https://x.example?a=1\n",
		"public_url plain http":            kek + "public_url = http://varlatch.example.com\n",
		"public_url http on a LAN address": kek + "public_url = http://192.168.1.20:8686\n",
		"public_url http on 127.0.0.2":     kek + "public_url = http://127.0.0.2\n",
		"relative data_dir":                kek + "data_dir = data\n",
		"relative root_kek_file":           "root_kek_file = root-kek\n",
		"no Root KEK at all":               "listen = 127.0.0.1:1\n",
		"bad trusted proxy":                kek + "trusted_proxies = under_score\n",
		"bad outbound allow entry":         kek + "outbound_allow = 10.0.0.0/33\n",
		"bad access_log":                   kek + "access_log = access.log\n",
		"bad sync":                         kek + "sync = yes\n",
		"unknown sync adapter":             kek + "sync_adapters = heroku\n",
		"audit export neither on nor off":  kek + "audit_export = maybe\n",
		"serve_cli neither on nor off":     kek + "public_url = https://varlatch.example.com\nserve_cli = yes\n",
		"serve_cli without public_url":     kek + "serve_cli = on\n",
		"serve_cli with a public_url path": kek + "public_url = https://example.com/vault\nserve_cli = on\n",
		"overlong line":                    kek + "public_url = https://" + strings.Repeat("a", 70*1024) + "\n",
		"relative backup_key_file":         kek + "backup_key_file = bek\n",
		"relative destinations file":       kek + "backup_destinations_file = d.json\n",
		"backup_interval too short":        kek + "backup_interval = 59m\n",
		"backup_interval too long":         kek + "backup_interval = 745h\n",
		"backup_interval not a duration":   kek + "backup_interval = daily\n",
		"backup_keep zero":                 kek + "backup_keep = 0\n",
		"backup_keep too many":             kek + "backup_keep = 1001\n",
		"backup_destination with a dot":    kek + "backup_destination = b2.eu\n",
		"tailnet neither on nor off":       kek + "tailnet = yes\n",
		"tailnet setting with tailnet off": kek + "tailnet_hostname = varlatch\n",
		"tailnet on without a hostname":    kek + "tailnet = on\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n",
		"tailnet hostname with a dot":      kek + "tailnet = on\ntailnet_hostname = varlatch.corp\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n",
		"tailnet on without tags":          kek + "tailnet = on\ntailnet_hostname = varlatch\ntailnet_port = 8687\n",
		"tailnet tag without tag:":         kek + "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = varlatch\ntailnet_port = 8687\n",
		"tailnet on without a port":        kek + "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\n",
		"tailnet port too large":           kek + "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 65536\n",
		"control server by host name":      kek + "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = https://hs.example.com\n",
		"relative tailnet auth key file":   kek + "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = key\n",
	} {
		_, err := Parse(strings.NewReader(file), env(nil))
		var cerr *Error
		if !errors.As(err, &cerr) {
			t.Errorf("%s: got %v, want a *config.Error", name, err)
		}
	}
	_, err := Parse(strings.NewReader("root_kek_file = /k\n\nsync = maybe\n"), env(nil))
	if err == nil || err.Error() != `configuration line 3: sync: "maybe" must be on or off` {
		t.Errorf("message: %v", err)
	}
}

// tailnet = on starts varlatchd's tailnet node (ADR-0059 Decision 5); off,
// the default, leaves every tailnet setting unset. Tailscale's control
// server, given or not, is "" for the pin; a self-hosted one (Headscale) is
// https with an IP address for its host, canonical, and never a host name
// (tsnet's bootstrap DNS fallback would send it to Tailscale).
func TestParseTailnet(t *testing.T) {
	c, err := Parse(strings.NewReader("root_kek_file = /k\n"), env(nil))
	if err != nil || c.Tailnet != nil {
		t.Fatalf("off by default: %+v, %v", c.Tailnet, err)
	}
	if c, err = Parse(strings.NewReader("root_kek_file = /k\ntailnet = off\n"), env(nil)); err != nil || c.Tailnet != nil {
		t.Fatalf("off: %+v, %v", c.Tailnet, err)
	}
	on := "root_kek_file = /k\ntailnet = on\ntailnet_hostname = varlatch-prod\ntailnet_tags = tag:varlatch, tag:prod\ntailnet_port = 8687\n"
	c, err = Parse(strings.NewReader(on), env(map[string]string{"CREDENTIALS_DIRECTORY": "/run/credentials/varlatchd.service"}))
	if err != nil {
		t.Fatal(err)
	}
	if tn := c.Tailnet; tn == nil || tn.Hostname != "varlatch-prod" || !slices.Equal(tn.Tags, []string{"tag:varlatch", "tag:prod"}) || tn.Port != 8687 ||
		tn.ControlURL != "" || tn.AuthKeyFile != "/run/credentials/varlatchd.service/tailnet-auth-key" {
		t.Errorf("on: %+v", c.Tailnet)
	}
	c, err = Parse(strings.NewReader(on+"tailnet_control_url = "+TailscaleControlURL+"\ntailnet_auth_key_file = /etc/varlatch/tailnet-auth-key\n"), env(nil))
	if err != nil || c.Tailnet.ControlURL != "" || c.Tailnet.AuthKeyFile != "/etc/varlatch/tailnet-auth-key" {
		t.Errorf("Tailscale's control URL given, and a key file: %+v, %v", c.Tailnet, err)
	}
	if c, err = Parse(strings.NewReader(on), env(nil)); err != nil || c.Tailnet.AuthKeyFile != "" {
		t.Errorf("no key file and no credentials directory: %+v, %v", c.Tailnet, err)
	}
	for given, want := range map[string]string{
		"https://192.0.2.10":               "https://192.0.2.10",
		"https://192.0.2.10/":              "https://192.0.2.10",
		"https://192.0.2.10:443":           "https://192.0.2.10",
		"https://192.0.2.10:8443":          "https://192.0.2.10:8443",
		"https://[2001:db8::10]":           "https://[2001:db8::10]",
		"https://[2001:DB8:0::10]:8443":    "https://[2001:db8::10]:8443",
		"https://[::ffff:192.0.2.10]:8443": "https://192.0.2.10:8443",
		"https://127.0.0.1:8443":           "https://127.0.0.1:8443",
	} {
		c, err := Parse(strings.NewReader(on+"tailnet_control_url = "+given+"\n"), env(nil))
		if err != nil || c.Tailnet.ControlURL != want {
			t.Errorf("%s: %+v, %v; want %s", given, c, err, want)
		}
	}
	for given, why := range map[string]string{
		"https://hs.example.com":           "an IP address is never looked up",
		"https://headscale:8443":           "an IP address is never looked up",
		"http://192.0.2.10":                "https://<its IP address>",
		"https://user@192.0.2.10":          "https://<its IP address>",
		"https://192.0.2.10/headscale":     "https://<its IP address>",
		"https://192.0.2.10?x=1":           "https://<its IP address>",
		"https://192.0.2.10#x":             "https://<its IP address>",
		"https://0.0.0.0":                  "unspecified",
		"https://[::]:8443":                "unspecified",
		"https://224.0.0.1":                "multicast",
		"https://[fe80::1%25eth0]":         "zoned",
		"https://[::ffff:0.0.0.0]":         "unspecified",
		"https://[::ffff:224.0.0.1]":       "multicast",
		"https://[fe80::1]":                "link-local",
		"https://169.254.10.1":             "link-local",
		"https://[::ffff:169.254.10.1]":    "link-local",
		"https://255.255.255.255":          "broadcast",
		"https://[::ffff:255.255.255.255]": "broadcast",
		"https://192.0.2.10:0":             "port is not 1 to 65535",
		"https://010.0.2.10":               "an IP address is never looked up",
		"https://192.0.2.10:99999":         "https://<its IP address>",
	} {
		_, err := Parse(strings.NewReader(on+"tailnet_control_url = "+given+"\n"), env(nil))
		var cerr *Error
		if !errors.As(err, &cerr) || !strings.Contains(err.Error(), why) || !strings.Contains(err.Error(), "Leave tailnet_control_url unset for Tailscale's") {
			t.Errorf("%s: %v, want a configuration error naming %q", given, err, why)
		}
	}
	// A self-hosted control server issues no Tailscale certificate: no
	// browser endpoint with it.
	_, err = Parse(strings.NewReader(on+"tailnet_control_url = https://192.0.2.10\ntailnet_https_port = 8688\npublic_url = https://varlatch.example.test\n"), env(nil))
	if err == nil || !strings.Contains(err.Error(), "does not issue") {
		t.Errorf("the browser endpoint with a self-hosted control server: %v", err)
	}
}

// tailnet_https_port turns the browser endpoint on (config.ts's
// tailnetBrowser): a port of its own, and the origins it may serve, an
// https (or loopback http) public_url's by default and exact ones listed.
func TestParseBrowserEndpoint(t *testing.T) {
	on := "root_kek_file = /k\ntailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n"
	parse := func(extra string) (*Tailnet, error) {
		c, err := Parse(strings.NewReader(on+extra), env(nil))
		if err != nil {
			return nil, err
		}
		return c.Tailnet, nil
	}
	if tn, err := parse(""); err != nil || tn.HTTPSPort != 0 || tn.BrowserOrigins != nil {
		t.Fatalf("off by default: %+v %v", tn, err)
	}
	tn, err := parse("public_url = https://varlatch.example.com:443\ntailnet_https_port = 8443\ntailnet_browser_origins = https://dash.example.com, http://localhost:5173 , https://varlatch.example.com\n")
	if err != nil || tn.HTTPSPort != 8443 || !slices.Equal(tn.BrowserOrigins, []string{"https://varlatch.example.com", "https://dash.example.com", "http://localhost:5173"}) {
		t.Fatalf("on: %+v %v", tn, err)
	}
	if tn, err := parse("public_url = http://127.0.0.1:8686\ntailnet_https_port = 8443\n"); err != nil || !slices.Equal(tn.BrowserOrigins, []string{"http://127.0.0.1:8686"}) {
		t.Errorf("a loopback public_url: %+v %v", tn, err)
	}
	if tn, err := parse("tailnet_https_port = 8443\ntailnet_browser_origins = http://[::1]:3000\n"); err != nil || !slices.Equal(tn.BrowserOrigins, []string{"http://[::1]:3000"}) {
		t.Errorf("IPv6 loopback: %+v %v", tn, err)
	}
	for name, c := range map[string]struct{ extra, want string }{
		"origins without the port": {"tailnet_browser_origins = https://dash.example.com\n", "is set, but the browser endpoint is off"},
		"no origin":                {"tailnet_https_port = 8443\n", "needs a dashboard origin it may serve"},
		"not a port":               {"tailnet_https_port = 70000\n", "is not a port"},
		"the listener's port":      {"tailnet_https_port = 8687\n", "must differ from tailnet_port"},
		"a wildcard":               {"tailnet_https_port = 8443\ntailnet_browser_origins = *\n", "is never allowed; list exact origins"},
		"null":                     {"tailnet_https_port = 8443\ntailnet_browser_origins = null\n", "is never allowed; list exact origins"},
		"not a URL":                {"tailnet_https_port = 8443\ntailnet_browser_origins = dash.example.com\n", "is not an origin such as"},
		"plain http":               {"tailnet_https_port = 8443\ntailnet_browser_origins = http://dash.example.com\n", "must use https"},
		"a path":                   {"tailnet_https_port = 8443\ntailnet_browser_origins = https://dash.example.com/\n", "must be exactly an origin, written https://dash.example.com"},
		"the default port":         {"tailnet_https_port = 8443\ntailnet_browser_origins = https://dash.example.com:443\n", "must be exactly an origin, written https://dash.example.com"},
		"upper case":               {"tailnet_https_port = 8443\ntailnet_browser_origins = https://Dash.example.com\n", "must be exactly an origin, written https://dash.example.com"},
		"a wildcard host":          {"tailnet_https_port = 8443\ntailnet_browser_origins = https://*.example.com\n", "must name one host; wildcards are never allowed"},
		"http public_url only":     {"public_url = http://localhost:8686\ntailnet_https_port = 8443\ntailnet_browser_origins = https://a.example.com,ftp://x\n", "must use https"},
	} {
		_, err := parse(c.extra)
		var cerr *Error
		if !errors.As(err, &cerr) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, err := Parse(strings.NewReader("root_kek_file = /k\ntailnet_https_port = 8443\n"), env(nil)); err == nil || !strings.Contains(err.Error(), "tailnet is off") {
		t.Errorf("with tailnet off: %v", err)
	}
}

func TestLoadReadError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.conf"))
	var cerr *Error
	if err == nil || errors.As(err, &cerr) || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file must be a read error, not a configuration error: %v", err)
	}
}

// The example the installer and setup follow parses.
func TestExampleParses(t *testing.T) {
	f, err := os.Open("../../install/varlatchd.conf.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Parse(f, env(map[string]string{"CREDENTIALS_DIRECTORY": "/c"})); err != nil {
		t.Fatal(err)
	}
}

// Plain http is accepted only on this machine: localhost, 127.0.0.1 and
// [::1] (ADR-0059 Decision 6); https anywhere.
func TestPublicURLPlainHTTPOnlyOnLoopback(t *testing.T) {
	for _, v := range []string{"http://localhost:8686", "http://LOCALHOST", "http://127.0.0.1:8686", "http://[::1]:8686", "https://varlatch.example.com", "https://192.168.1.20"} {
		c, err := Parse(strings.NewReader("root_kek_file = /k\npublic_url = "+v+"\n"), env(nil))
		if err != nil || c.PublicURL == nil {
			t.Errorf("%s: %v", v, err)
		}
	}
}

// TestParsePublicHTTPS: listen_https turns public HTTPS on, for an https
// public_url naming a DNS name; the plain HTTP listener defaults to port
// 80 on the same address and may be off; the ACME settings apply only
// with it. Without listen_https, nothing is set and the other listeners
// are as before.
func TestParsePublicHTTPS(t *testing.T) {
	parse := func(conf string) (*Config, error) {
		return Parse(strings.NewReader("root_kek_file = /k\n"+conf), env(nil))
	}
	c, err := parse("public_url = https://Vault.Example.com\nlisten_https = :443\n")
	if err != nil {
		t.Fatal(err)
	}
	want := PublicHTTPS{Host: "vault.example.com", Listen: ":443", RedirectListen: ":80", CA: LetsEncryptDirectory}
	if c.PublicHTTPS == nil || *c.PublicHTTPS != want || c.Listen != DefaultListen {
		t.Errorf("defaults: %+v", c.PublicHTTPS)
	}
	c, err = parse("public_url = https://vault.example.com:8443\nlisten_https = 203.0.113.5:8443\nlisten_http_redirect = off\nacme_email = ops@example.com\n" +
		"acme_ca = https://acme-staging-v02.api.letsencrypt.org/directory\nacme_ca_root = /etc/varlatch/ca.pem\n")
	if err != nil {
		t.Fatal(err)
	}
	want = PublicHTTPS{Host: "vault.example.com", Listen: "203.0.113.5:8443", Email: "ops@example.com",
		CA: "https://acme-staging-v02.api.letsencrypt.org/directory", CARootFile: "/etc/varlatch/ca.pem"}
	if *c.PublicHTTPS != want {
		t.Errorf("every setting: %+v", c.PublicHTTPS)
	}
	if c, err := parse("public_url = https://vault.example.com\nlisten_https = 10.0.0.1:443\n"); err != nil || c.PublicHTTPS.RedirectListen != "10.0.0.1:80" {
		t.Errorf("the redirect's default address: %+v %v", c, err)
	}
	for _, listen := range []string{"127.0.0.1:8686", "127.0.0.2:8686", "[::1]:8686"} {
		if _, err := parse("listen = " + listen + "\npublic_url = https://vault.example.com\nlisten_https = :443\n"); err != nil {
			t.Errorf("loopback listen %s with listen_https: %v", listen, err)
		}
	}
	if c, err := parse("listen = 0.0.0.0:8686\npublic_url = https://vault.example.com\n"); err != nil || c.PublicHTTPS != nil {
		t.Errorf("a non-loopback plain listener without public HTTPS, as before: %+v %v", c, err)
	}
	if c, err := parse("public_url = https://vault.example.com\n"); err != nil || c.PublicHTTPS != nil {
		t.Errorf("off: %+v %v", c, err)
	}
	for _, c := range []struct{ conf, has string }{
		{"listen_https = :443\n", "needs an https public_url"},
		{"public_url = http://localhost:8686\nlisten_https = :443\n", "needs an https public_url"},
		{"public_url = https://192.0.2.7\nlisten_https = :443\n", "a DNS name a public certificate can hold"},
		{"public_url = https://vault\nlisten_https = :443\n", "a DNS name a public certificate can hold"},
		{"public_url = https://localhost\nlisten_https = :443\n", "a DNS name a public certificate can hold"},
		{"public_url = https://vault.example.com\nlisten_https = 443\n", "is not host:port"},
		{"public_url = https://vault.example.com\nlisten_https = :0\n", "the port must be 1 to 65535"},
		{"public_url = https://vault.example.com\nlisten_https = :443\nlisten_http_redirect = 127.0.0.1:0\n", "the port must be 1 to 65535"},
		{"public_url = https://vault.example.com\nlisten_https = vault.example.com:443\n", "the host must be an IP address"},
		{"public_url = https://vault.example.com\nlisten_https = :443\nlisten_http_redirect = :443\n", "must differ from listen_https"},
		{"public_url = https://vault.example.com\nlisten = 127.0.0.1:443\nlisten_https = 127.0.0.1:443\n", "must differ from listen"},
		{"public_url = https://vault.example.com\nlisten_https = :443\nacme_email = not-an-address\n", "is not an email address"},
		{"public_url = https://vault.example.com\nlisten_https = :443\nacme_ca = http://ca.example/directory\n", "is not an https ACME directory URL"},
		{"public_url = https://vault.example.com\nlisten_https = :443\nacme_ca = https://u:p@ca.example/directory\n", "is not an https ACME directory URL"},
		{"public_url = https://vault.example.com\nlisten_https = :443\nacme_ca_root = ca.pem\n", "is not an absolute path"},
		{"listen = 0.0.0.0:8686\npublic_url = https://vault.example.com\nlisten_https = :443\n", "the plain listener must be on a loopback address"},
		{"listen = 192.0.2.5:8686\npublic_url = https://vault.example.com\nlisten_https = :443\n", "the plain listener must be on a loopback address"},
		{"listen = :8686\npublic_url = https://vault.example.com\nlisten_https = :443\n", "the plain listener must be on a loopback address"},
		{"acme_email = ops@example.com\n", "listen_https is not"},
		{"listen_http_redirect = :80\n", "listen_https is not"},
		{"acme_ca = https://ca.example/d\n", "listen_https is not"},
		{"acme_ca_root = /ca.pem\n", "listen_https is not"},
	} {
		_, err := parse(c.conf)
		var cerr *Error
		if !errors.As(err, &cerr) || !strings.Contains(err.Error(), c.has) {
			t.Errorf("%q: %v, want %q", c.conf, err, c.has)
		}
		if err != nil && strings.Contains(err.Error(), "u:p") {
			t.Errorf("%q: the error shows the URL's password", c.conf)
		}
	}
}

// TestBackupKeyCredential: without backup_key_file, the unit's backup-key
// credential is the backup key when it exists, as the root-kek
// credential is the Root KEK; without one, no scheduled backup.
func TestBackupKeyCredential(t *testing.T) {
	dir := t.TempDir()
	c, err := Parse(strings.NewReader(""), env(map[string]string{"CREDENTIALS_DIRECTORY": dir}))
	if err != nil || c.BackupKeyFile != "" || c.RootKEKFile != filepath.Join(dir, "root-kek") {
		t.Fatalf("no backup-key credential: %+v %v", c, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup-key"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = Parse(strings.NewReader(""), env(map[string]string{"CREDENTIALS_DIRECTORY": dir})); err != nil || c.BackupKeyFile != filepath.Join(dir, "backup-key") {
		t.Errorf("the backup-key credential: %+v %v", c, err)
	}
	if c, err = Parse(strings.NewReader("backup_key_file = /etc/bek\n"), env(map[string]string{"CREDENTIALS_DIRECTORY": dir})); err != nil || c.BackupKeyFile != "/etc/bek" {
		t.Errorf("backup_key_file wins: %+v %v", c, err)
	}
}

func TestServeCLI(t *testing.T) {
	for file, want := range map[string]bool{
		"root_kek_file = /k\n":                  false,
		"root_kek_file = /k\nserve_cli = off\n": false,
		"root_kek_file = /k\npublic_url = https://varlatch.example.com\nserve_cli = on\n":        true,
		"root_kek_file = /k\npublic_url = http://127.0.0.1:8686\nserve_cli = on\n":               true,
		"root_kek_file = /k\npublic_url = https://varlatch.example.com/\nserve_cli = on\n":       true,
		"root_kek_file = /k\npublic_url = https://varlatch.example.com/vault\nserve_cli = off\n": false,
	} {
		c, err := Parse(strings.NewReader(file), env(nil))
		if err != nil || c.ServeCLI != want {
			t.Errorf("%q: %+v %v", file, c, err)
		}
	}
}
