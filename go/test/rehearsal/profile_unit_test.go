// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProfileRefusals: the profile's checks, without a container. The box
// runs as root; the Coolify case needs its release variables and the
// candidate checkout's Coolify files before anything starts; B6 needs an
// archive and its keys on this host, by path.
func TestProfileRefusals(t *testing.T) {
	dir := t.TempDir()
	defer func(r, ts string) { releaseDir, tsCheckout = r, ts }(releaseDir, tsCheckout)
	releaseDir, tsCheckout = filepath.Join(dir, "release"), filepath.Join(dir, "ts")
	defer func(r func() (string, error)) { imageUserRelease = r }(imageUserRelease)
	release, releaseErr := "0.50.0-dev", error(nil)
	imageUserRelease = func() (string, error) { return release, releaseErr }
	defer func(r func(string) ([]string, error)) { resolveHost = r }(resolveHost)
	resolveHost = func(string) ([]string, error) { return []string{os.Getenv("VL_RH_PUBLIC_BIND")}, nil }
	coolify := func(t *testing.T) {
		for k, v := range map[string]string{
			"VL_RH_PROFILE": "box", "VL_RH_INGRESS": "coolify", "VL_RH_TARGET": "image", "VL_RH_PUBLIC_NAME": "rh.example",
			"VL_RH_GO_IMAGE": "127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev@sha256:" + strings.Repeat("a", 64), "VL_RH_COOLIFY_SOURCE_DIR": filepath.Join(dir, "app"),
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
	// B2: migrate checks the public URL by its name, so it must lead to
	// the run's address on this host.
	t.Run("public: the name leads elsewhere", func(t *testing.T) {
		for k, v := range map[string]string{"VL_RH_PROFILE": "box", "VL_RH_INGRESS": "public", "VL_RH_TARGET": "host", "VL_RH_SYNC": "", "VL_RH_ONLY": "",
			"VL_RH_PUBLIC_NAME": "rh.example", "VL_RH_PUBLIC_BIND": "192.0.2.7"} {
			t.Setenv(k, v)
		}
		defer func(r func(string) ([]string, error)) { resolveHost = r }(resolveHost)
		resolveHost = func(string) ([]string, error) { return []string{"198.51.100.9"}, nil }
		if _, err := readProfile(0); err == nil || !strings.Contains(err.Error(), "resolves, on this host, to [198.51.100.9]") {
			t.Fatal(err)
		}
	})
	// The image target's preconditions, refused before the owner's first
	// step (B3's first two runs got as far as migrate).
	t.Run("coolify: the image target", func(t *testing.T) {
		digest := "@sha256:" + strings.Repeat("a", 64)
		for _, c := range []struct {
			image   string
			release string
			err     error
			want    string
		}{
			{"127.0.0.1:5000/vl-rh/varlatchd" + digest, "0.50.0-dev", nil, "is not migrate's --to-image form"},
			{"127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev@sha256:abc", "0.50.0-dev", nil, "is not migrate's --to-image form"},
			{"127.0.0.1:5000/vl-rh/varlatchd:0.50.0-rc.2" + digest, "0.50.0-dev", nil, "tag is not the run's varlatchd release, 0.50.0-dev"},
			{"127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev" + digest, "", errors.New("fork/exec /home/owner/runs/b3/bin/varlatchd: permission denied"), "cannot: fork/exec /home/owner/runs/b3/bin/varlatchd: permission denied. Set VL_RH_ROOT"},
			{"127.0.0.1:5000/vl-rh/varlatchd:v0.50.0-dev" + digest, "0.50.0-dev", nil, ""},
			{"127.0.0.1:5000/vl-rh/varlatchd:V0.50.0-dev" + digest, "0.50.0-dev", nil, ""},
		} {
			coolify(t)
			t.Setenv("VL_RH_GO_IMAGE", c.image)
			release, releaseErr = c.release, c.err
			_, err := readProfile(0)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", c.image, err, c.want)
			}
		}
		release, releaseErr = "0.50.0-dev", nil
	})
	// A refused value is not repeated (it may be a registry URL with
	// credentials, and the refusal reaches the run's log).
	t.Run("coolify: the refused image is not shown", func(t *testing.T) {
		coolify(t)
		t.Setenv("VL_RH_GO_IMAGE", "https://user:s3cret@registry.example/varlatchd:0.50.0-dev@sha256:"+strings.Repeat("a", 64))
		if _, err := readProfile(0); err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "registry.example") {
			t.Fatal(err)
		}
	})
}

// TestVersionRelease: only varlatchd's own version line gives a release.
func TestVersionRelease(t *testing.T) {
	for in, want := range map[string]string{
		"varlatchd 0.50.0-dev\n":    "0.50.0-dev",
		"varlatchd V0.50.0-rc.2\n":  "0.50.0-rc.2",
		"varlatchd v0.50.0+abc\n":   "0.50.0+abc",
		"":                          "",
		"varlatchd\n":               "",
		"varlatchd 0.50.0":          "",
		"varlatchd 0.50.0 extra\n":  "",
		"varlatchd 0.50.0\nmore\n":  "",
		"varlatch 0.50.0\n":         "",
		"sh: 1: varlatchd 0.50.0\n": "",
		" varlatchd 0.50.0\n":       "",
	} {
		got, err := versionRelease([]byte(in))
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestCappedOutput: the probe's output is kept up to its limit, never
// blocking the writer, and the excess noted.
func TestCappedOutput(t *testing.T) {
	c := &cappedOutput{max: 8}
	for _, p := range []string{"varl", "atchd", " 0.50.0\n"} {
		if n, err := c.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("write %q: %d, %v", p, n, err)
		}
	}
	if string(c.b) != "varlatch" || !c.over {
		t.Fatalf("%q over %v", c.b, c.over)
	}
}

// TestImageUserRelease: the run's varlatchd run as the image's user, as
// migrate runs it: a directory that user cannot pass refuses, the kernel
// deciding (root only: it changes the user).
func TestImageUserRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runs a program as uid 65532: root only")
	}
	defer func(b string) { binDir = b }(binDir)
	root := t.TempDir()
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o755, true}, {0o711, true}, {0o750, false}, {0o700, false}} {
		dir := filepath.Join(root, c.mode.String())
		binDir = filepath.Join(dir, "bin")
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir, "varlatchd"), []byte("#!/bin/sh\necho varlatchd V0.50.0-dev\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{filepath.Dir(root), root} {
			if err := os.Chmod(d, 0o711); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(dir, c.mode); err != nil {
			t.Fatal(err)
		}
		rel, err := imageUserRelease()
		if c.ok != (err == nil) || c.ok && rel != "0.50.0-dev" {
			t.Errorf("a directory of mode %v: %q, %v", c.mode, rel, err)
		}
	}
	// A program that never answers, one that prints without end, and one
	// that prints another line: each refused.
	defer func(d time.Duration) { versionProbeTimeout = d }(versionProbeTimeout)
	versionProbeTimeout = 2 * time.Second
	binDir = filepath.Join(root, "odd")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for script, want := range map[string]string{
		"exec sleep 60":               "no answer within 2s",
		"yes varlatchd":               "printed more than 4096 bytes",
		"echo varlatchd 0.50.0 extra": "not varlatchd's version line",
	} {
		if err := os.WriteFile(filepath.Join(binDir, "varlatchd"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		began := time.Now()
		_, err := imageUserRelease()
		if err == nil || !strings.Contains(err.Error(), want) || time.Since(began) > 10*time.Second {
			t.Errorf("%s: %v after %s, want %q", script, err, time.Since(began), want)
		}
	}
}
