// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	defer func(r func() (string, error), b func() (string, error)) { hostRelease, runBinaryBlocked = r, b }(hostRelease, runBinaryBlocked)
	hostRelease = func() (string, error) { return "0.50.0-dev", nil }
	blocked := ""
	runBinaryBlocked = func() (string, error) { return blocked, nil }
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
	// The image target's preconditions, refused before the owner's first
	// step (B3's first two runs got as far as migrate).
	t.Run("coolify: the image target", func(t *testing.T) {
		digest := "@sha256:" + strings.Repeat("a", 64)
		for _, c := range []struct{ image, blocked, want string }{
			{"127.0.0.1:5000/vl-rh/varlatchd" + digest, "", "not migrate's --to-image form"},
			{"127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev@sha256:abc", "", "not migrate's --to-image form"},
			{"127.0.0.1:5000/vl-rh/varlatchd:0.50.0-rc.2" + digest, "", "tagged 0.50.0-rc.2; the run's varlatchd is 0.50.0-dev"},
			{"127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev" + digest, "/home/owner", "cannot pass /home/owner: set VL_RH_ROOT outside"},
			{"127.0.0.1:5000/vl-rh/varlatchd:v0.50.0-dev" + digest, "", ""},
		} {
			coolify(t)
			t.Setenv("VL_RH_GO_IMAGE", c.image)
			blocked = c.blocked
			_, err := readProfile(0)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s, blocked %q: %v, want %q", c.image, c.blocked, err, c.want)
			}
		}
		blocked = ""
	})
}

// fakeInfo is a stat answer: a mode and an owner.
type fakeInfo struct {
	mode     fs.FileMode
	uid, gid uint32
}

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid, Gid: f.gid} }

// TestFirstBlocked: the way to the run's varlatchd as the image's user
// (65532) sees it: owner, group and other bits each for their class.
func TestFirstBlocked(t *testing.T) {
	const bin = "/srv/vl-rh-runs/b3/bin/varlatchd"
	base := map[string]fakeInfo{
		"/": {fs.ModeDir | 0o755, 0, 0}, "/srv": {fs.ModeDir | 0o755, 0, 0}, "/srv/vl-rh-runs": {fs.ModeDir | 0o755, 0, 0},
		"/srv/vl-rh-runs/b3": {fs.ModeDir | 0o755, 1001, 1001}, "/srv/vl-rh-runs/b3/bin": {fs.ModeDir | 0o755, 1001, 1001},
		bin: {0o755, 1001, 1001},
	}
	for _, c := range []struct {
		name string
		edit map[string]fakeInfo
		want string
	}{
		{"open all the way", nil, ""},
		{"a home of mode 0750", map[string]fakeInfo{"/srv/vl-rh-runs/b3": {fs.ModeDir | 0o750, 1001, 1001}}, "/srv/vl-rh-runs/b3"},
		{"0711 passes", map[string]fakeInfo{"/srv/vl-rh-runs": {fs.ModeDir | 0o711, 0, 0}}, ""},
		{"the image's own directory, owner bits", map[string]fakeInfo{"/srv/vl-rh-runs/b3": {fs.ModeDir | 0o700, 65532, 0}}, ""},
		{"its group's, group bits", map[string]fakeInfo{"/srv/vl-rh-runs/b3": {fs.ModeDir | 0o750, 0, 65532}}, ""},
		{"the binary not executable for others", map[string]fakeInfo{bin: {0o750, 1001, 1001}}, bin},
	} {
		infos := map[string]fakeInfo{}
		for k, v := range base {
			infos[k] = v
		}
		for k, v := range c.edit {
			infos[k] = v
		}
		got, err := firstBlocked(bin, 65532, 65532, func(p string) (fs.FileInfo, error) {
			if fi, ok := infos[p]; ok {
				return fi, nil
			}
			return nil, fs.ErrNotExist
		})
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}
