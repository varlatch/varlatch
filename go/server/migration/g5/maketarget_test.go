// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// G5's host shape from a missing target (go-step7 decision 20, slice
// 7.4e): `varlatch migrate --config /etc/varlatch/varlatchd.conf` with no
// target there makes it with setup's steps, then migrates into it; undone
// before the switch, exactly what it made goes; killed while making it,
// --resume goes on, --abort removes it.
//
// What stands in, beyond interrupt_test.go's: the CLI's crashpoint seam
// (VARLATCH_MIGRATE_TARGET_ROOT) makes the target under a test root, its
// varlatch user a record in a file there (no useradd, no chown: a test
// changes no account of this host); systemctl's enable, disable,
// is-enabled and is-active answer from the stand-in's state. Real setup on
// a real host's systemd is go.yml's runner-only step
// (TestPrepareTargetOnThisHost).

// madeWorld is a world whose host target is not there: --config at setup's
// place under a test root, the unit file installed (install.sh --server's
// part), nothing else.
func madeWorld(t *testing.T) (*world, string) {
	t.Helper()
	w := newWorld(t, false)
	// Short: the data directory holds varlatchd's Unix socket (107 bytes).
	root, err := os.MkdirTemp("", "g5mt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, d := range []string{"etc/systemd/system", "var/lib"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/systemd/system/varlatchd.service"), []byte("[Unit]\nDescription=varlatchd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.conf = filepath.Join(root, "etc/varlatch/varlatchd.conf")
	w.data = filepath.Join(root, "var/lib/varlatch")
	w.keys = filepath.Join(root, "etc/varlatch")
	_ = os.Remove(filepath.Join(w.stateDir, "service.conf"))
	if err := os.Symlink(w.conf, filepath.Join(w.stateDir, "service.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.stateDir, "credentials-dir"), []byte(w.keys), 0o600); err != nil {
		t.Fatal(err)
	}
	w.extraEnv = []string{"VARLATCH_MIGRATE_TARGET_ROOT=" + root}
	// The public URL over https, as setup requires behind a proxy: the
	// same origin's stand-in, served with a test certificate the CLI
	// trusts (SSL_CERT_FILE) and the test's probes too.
	var env []byte
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(w.serveOrigin))
	t.Cleanup(tlsOrigin.Close)
	ca := filepath.Join(w.stateDir, "origin-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsOrigin.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	env, err = os.ReadFile(filepath.Join(w.compose, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	env = []byte(strings.Replace(string(env), "VARLATCH_PUBLIC_URL="+w.origin, "VARLATCH_PUBLIC_URL="+tlsOrigin.URL, 1))
	if err := os.WriteFile(filepath.Join(w.compose, ".env"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	w.origin, w.client = tlsOrigin.URL, tlsOrigin.Client()
	w.extraEnv = append(w.extraEnv, "SSL_CERT_FILE="+ca)
	return w, root
}

// gone holds that nothing migrate made is left under root but the unit
// file it found, and that the unit is not enabled.
func (w *world) gone(when, root string) {
	t := w.t
	t.Helper()
	for _, p := range []string{"etc/varlatch", "var/lib/varlatch"} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Errorf("%s: %s is left: %v", when, p, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(root, "users")); strings.Contains(string(b), "varlatch\n") {
		t.Errorf("%s: the varlatch user is left", when)
	}
	if _, err := os.Stat(filepath.Join(w.stateDir, "unit-enabled")); !os.IsNotExist(err) {
		t.Errorf("%s: the unit is left enabled", when)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/varlatchd.service")); err != nil {
		t.Errorf("%s: the unit file, not migrate's, was removed: %v", when, err)
	}
}

func TestG5MakesTheHostTarget(t *testing.T) {
	t.Run("made, migrated into", func(t *testing.T) {
		w, root := madeWorld(t)
		w.useState()
		// The source's outbound allow list, which the target made carries.
		envFile := filepath.Join(w.compose, ".env")
		env, err := os.ReadFile(envFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(envFile, append(env, "VARLATCH_OUTBOUND_ALLOW=coolify.lan,10.0.0.0/8:8000\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
		before := w.sourceHash()
		if code := w.run(""); code != 0 {
			t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("migrated", "open", "open", "target-open", "migrated-out")
		j, _ := os.ReadFile(filepath.Join(w.compose, "migration.json"))
		for _, item := range []string{"user", "etc-dir", "data-dir", "config", "unit-enabled", "root-kek", "backup-key"} {
			if !strings.Contains(string(j), `"`+item+`"`) {
				t.Errorf("the journal does not record %s as made:\n%s", item, j)
			}
		}
		conf, err := os.ReadFile(w.conf)
		if err != nil || !strings.Contains(string(conf), "public_url = "+w.origin) || !strings.Contains(string(conf), "listen = "+w.listen) || strings.Contains(string(conf), "root_kek_file") ||
			!strings.Contains(string(conf), "\noutbound_allow = coolify.lan,10.0.0.0/8:8000\n") {
			t.Errorf("the configuration made: %s %v", conf, err)
		}
		for _, k := range []string{"root-kek", "backup-key"} {
			if st, err := os.Stat(filepath.Join(root, "etc/varlatch", k)); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v", k, st, err)
			}
		}
		if b, _ := os.ReadFile(filepath.Join(root, "etc/varlatch/root-kek")); string(b) != hexKEK() {
			t.Error("the target's Root KEK is not the source's")
		}
		if w.sourceHash() != before {
			t.Error("the source's data changed")
		}
		w.noSecrets()
	})
	t.Run("made, then aborted before the switch", func(t *testing.T) {
		w, root := madeWorld(t)
		w.useState()
		if code := w.run("entered barrier"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if code := w.run("", "--abort"); code != 0 {
			t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("undone", "released", "", "source", "")
		w.gone("undone", root)
		// --resume after changes nothing; a new migration makes it again.
		if code := w.run("", "--resume"); code != 0 {
			t.Errorf("--resume after: %d", code)
		}
		if code := w.run(""); code != 0 {
			log, _ := os.ReadFile(filepath.Join(w.stateDir, "service.log"))
			t.Fatalf("a new migration: %d\n%s\nservice.log:\n%s", code, w.outputs[len(w.outputs)-1], log)
		}
		w.expect("migrated again", "open", "open", "target-open", "migrated-out")
		w.noSecrets()
	})
	for _, point := range []string{"target data-dir", "target config", "target unit-enabled"} {
		t.Run("killed at "+point, func(t *testing.T) {
			w, root := madeWorld(t)
			w.useState()
			if code := w.run(point); code != -1 {
				t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			if s, _ := w.phases(); s != "started" {
				t.Fatalf("the source's journal: %q", s)
			}
			if code := w.run("", "--abort"); code != 0 {
				t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.gone("aborted", root)
			if s, _ := w.phases(); s != "released" {
				t.Errorf("the source's journal: %q", s)
			}
			// Killed again, then resumed: it goes on to open.
			if code := w.run(point); code != -1 {
				t.Fatalf("not killed: %d", code)
			}
			if code := w.run("", "--resume"); code != 0 {
				t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.expect("resumed", "open", "open", "target-open", "migrated-out")
			// Every step of the target's made, the unit enabled included
			// (it starts again after a reboot).
			if _, err := os.Stat(filepath.Join(w.stateDir, "unit-enabled")); err != nil {
				t.Errorf("resumed: the unit is not enabled: %v", err)
			}
			w.noSecrets()
		})
	}
	// A dry run killed while it made the target is a dry run still: resumed,
	// it stops after the dry run, nothing switched; --abort then removes
	// what it made.
	t.Run("a dry run killed at target config, resumed", func(t *testing.T) {
		w, root := madeWorld(t)
		w.useState()
		if code := w.run("target config", "--dry-run"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if code := w.run("", "--resume"); code != 0 {
			t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("resumed dry run", "dry-run", "dry-run", "source", "")
		if code := w.run("", "--abort"); code != 0 {
			t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.gone("aborted", root)
		w.noSecrets()
	})
}

// hexKEK is the seed's Root KEK as its file holds it.
func hexKEK() string { return hex.EncodeToString(shared.source.RootKEK) + "\n" }
