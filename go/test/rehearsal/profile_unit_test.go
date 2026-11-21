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
// candidate checkout's Coolify files before anything starts.
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
