// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func env(vars map[string]string) Env { return func(k string) string { return vars[k] } }

func TestParseDefaults(t *testing.T) {
	c, err := Parse(strings.NewReader("# nothing but a comment\n\n"), env(map[string]string{"CREDENTIALS_DIRECTORY": "/run/credentials/varlatchd.service"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != DefaultListen || c.DataDir != DefaultDataDir || c.RootKEKFile != "/run/credentials/varlatchd.service/root-kek" ||
		c.AccessLog != "stdout" || !c.Sync || c.SyncAdapters != nil || c.PublicURL != nil || c.TrustedProxies != "" {
		t.Errorf("defaults: %+v", c)
	}
	c, err = Parse(strings.NewReader(""), env(map[string]string{"CREDENTIALS_DIRECTORY": "/c", "STATE_DIRECTORY": "/var/lib/varlatch-x:/other"}))
	if err != nil || c.DataDir != "/var/lib/varlatch-x" || c.DatabasePath() != "/var/lib/varlatch-x/varlatch.db" {
		t.Errorf("STATE_DIRECTORY: %+v, %v", c, err)
	}
}

func TestParseEverySetting(t *testing.T) {
	file := "\ufeff# varlatchd.conf\n" +
		"listen = 0.0.0.0:443\n" +
		"  public_url=https://varlatch.example.com  \n" +
		"data_dir = /srv/varlatch/\n" +
		"root_kek_file = /etc/varlatch/root-kek\n" +
		"trusted_proxies = 10.0.0.0/8, caddy\n" +
		"access_log = /var/log/varlatch/access.log\n" +
		"sync = off\n" +
		"sync_adapters = coolify, convex\n" +
		"   # an indented comment\n"
	c, err := Parse(strings.NewReader(file), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:443" || c.PublicURL.String() != "https://varlatch.example.com" || c.DataDir != "/srv/varlatch" ||
		c.RootKEKFile != "/etc/varlatch/root-kek" || c.TrustedProxies != "10.0.0.0/8, caddy" ||
		c.AccessLog != "/var/log/varlatch/access.log" || c.Sync || !slices.Equal(c.SyncAdapters, []string{"coolify", "convex"}) {
		t.Errorf("%+v", c)
	}
}

// Every one of these is a configuration error no retry can fix: *Error.
func TestParseErrors(t *testing.T) {
	kek := "root_kek_file = /k\n"
	for name, file := range map[string]string{
		"no equals sign":          kek + "listen 127.0.0.1:1\n",
		"unknown setting":         kek + "port = 8686\n",
		"repeated setting":        kek + "listen = 127.0.0.1:1\nlisten = 127.0.0.1:2\n",
		"listen without a port":   kek + "listen = 127.0.0.1\n",
		"listen port too large":   kek + "listen = 127.0.0.1:65536\n",
		"listen on a host name":   kek + "listen = localhost:8686\n",
		"public_url not a URL":    kek + "public_url = varlatch.example.com\n",
		"public_url with a query": kek + "public_url = https://x.example?a=1\n",
		"relative data_dir":       kek + "data_dir = data\n",
		"relative root_kek_file":  "root_kek_file = root-kek\n",
		"no Root KEK at all":      "listen = 127.0.0.1:1\n",
		"bad trusted proxy":       kek + "trusted_proxies = under_score\n",
		"bad access_log":          kek + "access_log = access.log\n",
		"bad sync":                kek + "sync = yes\n",
		"unknown sync adapter":    kek + "sync_adapters = heroku\n",
		"overlong line":           kek + "public_url = https://" + strings.Repeat("a", 70*1024) + "\n",
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
