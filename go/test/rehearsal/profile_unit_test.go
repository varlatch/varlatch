// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProfileRefusals: the profile's checks, without a container. The box
// runs as root; the Coolify case needs its release variables and the
// candidate checkout's Coolify files before anything starts; B6 needs an
// archive and its keys on this host, by path.
func TestProfileRefusals(t *testing.T) {
	dir := t.TempDir()
	defer func(r, ts string) { releaseDir, tsCheckout = r, ts }(releaseDir, tsCheckout)
	releaseDir, tsCheckout = filepath.Join(dir, "release"), filepath.Join(dir, "ts")
	coolify := func(t *testing.T) {
		for k, v := range map[string]string{
			"VL_RH_PROFILE": "box", "VL_RH_INGRESS": "coolify", "VL_RH_TARGET": "image", "VL_RH_PUBLIC_NAME": "rh.example",
			"VL_RH_GO_IMAGE": "registry.example/varlatchd@sha256:" + strings.Repeat("a", 64), "VL_RH_COOLIFY_SOURCE_DIR": filepath.Join(dir, "app"),
		} {
			t.Setenv(k, v)
		}
	}
	t.Run("the workstation profile", func(t *testing.T) {
		t.Setenv("VL_RH_PROFILE", "")
		t.Setenv("VL_RH_INGRESS", "")
		if p, err := readProfile(1000); err != nil || p.box || p.ingress != "proxy" {
			t.Fatalf("%+v, %v", p, err)
		}
	})
	t.Run("VL_RH_ONLY", func(t *testing.T) {
		t.Setenv("VL_RH_PROFILE", "")
		t.Setenv("VL_RH_INGRESS", "")
		for _, c := range []struct{ only, kill, sync, want string }{
			{"kill", "", "", "VL_RH_ONLY=kill needs VL_RH_KILL"},
			{"everything", "", "", "VL_RH_ONLY is setup, kill, sync or bundle"},
			{"bundle", "", "", "VL_RH_BUNDLE_OUT, an absolute path"},
			{"kill", "transfer", "", ""},
			{"setup", "", "", ""},
			{"sync", "", "", "VL_RH_ONLY=sync needs VL_RH_SYNC=fakes or real"},
			{"sync", "", "fakes", ""},
		} {
			t.Setenv("VL_RH_ONLY", c.only)
			t.Setenv("VL_RH_KILL", c.kill)
			t.Setenv("VL_RH_SYNC", c.sync)
			_, err := readProfile(1000)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("VL_RH_ONLY=%s VL_RH_KILL=%s VL_RH_SYNC=%s: %v, want %q", c.only, c.kill, c.sync, err, c.want)
			}
		}
	})
	t.Run("VL_RH_SYNC", func(t *testing.T) {
		t.Setenv("VL_RH_ONLY", "")
		for _, c := range []struct{ profile, ingress, sync, want string }{
			{"", "", "fakes", ""},
			{"", "", "coolify", "VL_RH_SYNC is fakes"},
			{"", "", "real", "owner's session on the box"},
			{"box", "public", "fakes", "workstation only"},
		} {
			t.Setenv("VL_RH_PROFILE", c.profile)
			t.Setenv("VL_RH_INGRESS", c.ingress)
			t.Setenv("VL_RH_SYNC", c.sync)
			t.Setenv("VL_RH_PUBLIC_NAME", "rh.example")
			t.Setenv("VL_RH_PUBLIC_BIND", "127.0.0.1")
			p, err := readProfile(0)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("VL_RH_PROFILE=%s VL_RH_SYNC=%s: %v, want %q", c.profile, c.sync, err, c.want)
			}
			if c.want == "" && p.sync != c.sync {
				t.Errorf("VL_RH_SYNC=%s read as %q", c.sync, p.sync)
			}
		}
	})
	t.Run("B6: the restored archive and its keys", func(t *testing.T) {
		t.Setenv("VL_RH_PROFILE", "")
		t.Setenv("VL_RH_INGRESS", "")
		t.Setenv("VL_RH_ONLY", "")
		t.Setenv("VL_RH_KILL", "")
		archive, bek, kek := filepath.Join(dir, "b6", "archive.vltbak"), filepath.Join(dir, "b6", "backup-key"), filepath.Join(dir, "b6", "root-kek")
		if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{archive, bek, kek} {
			if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range []struct{ source, bek, kek, ingress, want string }{
			{"restore:https://backups.example/a.vltbak", bek, kek, "", "the harness fetches nothing"},
			{"restore:a.vltbak", bek, kek, "", "absolute path"},
			{"restore:" + archive, "", kek, "", "VL_RH_RESTORE_BEK"},
			{"restore:" + archive, bek, "", "", "VL_RH_RESTORE_KEK"},
			{"restore:" + filepath.Join(dir, "b6", "none"), bek, kek, "", "no such file"},
			{"restore:" + filepath.Dir(archive), bek, kek, "", "not a regular file"},
			{"restore:" + archive, bek, kek, "", ""},
		} {
			t.Setenv("VL_RH_SOURCE", c.source)
			t.Setenv("VL_RH_RESTORE_BEK", c.bek)
			t.Setenv("VL_RH_RESTORE_KEK", c.kek)
			p, err := readProfile(1000)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", c.source, err, c.want)
			}
			if c.want == "" && (p.restore != archive || p.restoreBEK != bek || p.restoreKEK != kek) {
				t.Errorf("%+v", p)
			}
		}
		t.Setenv("VL_RH_SOURCE", "restore:"+archive)
		t.Setenv("VL_RH_RESTORE_BEK", bek)
		t.Setenv("VL_RH_RESTORE_KEK", kek)
		if err := os.Chmod(kek, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readProfile(1000); err == nil || !strings.Contains(err.Error(), "readable by others") {
			t.Errorf("a key readable by others: %v", err)
		}
		t.Setenv("VL_RH_SOURCE", "")
		t.Setenv("VL_RH_ONLY", "bundle")
		t.Setenv("VL_RH_BUNDLE_OUT", filepath.Dir(archive))
		if _, err := readProfile(1000); err == nil || !strings.Contains(err.Error(), "is not empty") {
			t.Errorf("VL_RH_ONLY=bundle into a directory with files: %v", err)
		}
		t.Setenv("VL_RH_BUNDLE_OUT", filepath.Join(dir, "out"))
		if p, err := readProfile(1000); err != nil || p.bundleOut != filepath.Join(dir, "out") {
			t.Errorf("VL_RH_ONLY=bundle: %+v, %v", p, err)
		}
	})
	t.Run("the box not as root", func(t *testing.T) {
		coolify(t)
		if _, err := readProfile(1000); err == nil || !strings.Contains(err.Error(), "runs as root") {
			t.Fatal(err)
		}
	})
	t.Run("coolify without the release's variables", func(t *testing.T) {
		coolify(t)
		_, err := readProfile(0)
		if err == nil || !strings.Contains(err.Error(), "coolify-image-digests.env") || !strings.Contains(err.Error(), "images.sh") {
			t.Fatal(err)
		}
	})
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("coolify without the checkout's Coolify files", func(t *testing.T) {
		coolify(t)
		write(t, filepath.Join(releaseDir, "coolify-image-digests.env"))
		_, err := readProfile(0)
		if err == nil || !strings.Contains(err.Error(), "docker-compose.coolify.yml") || !strings.Contains(err.Error(), "0.23.0 candidate") {
			t.Fatal(err)
		}
	})
	t.Run("coolify with everything", func(t *testing.T) {
		coolify(t)
		write(t, filepath.Join(tsCheckout, "infra", "compose", "docker-compose.coolify.yml"))
		write(t, filepath.Join(tsCheckout, "infra", "coolify", "README.md"))
		if p, err := readProfile(0); err != nil || !p.box || p.ingress != "coolify" {
			t.Fatalf("%+v, %v", p, err)
		}
	})
}
