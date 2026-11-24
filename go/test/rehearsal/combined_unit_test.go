// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The combined case's inputs, each missing one refused before anything
// starts.
func TestCombinedInputs(t *testing.T) {
	dir := t.TempDir()
	defer func(r, ts string) { releaseDir, tsCheckout = r, ts }(releaseDir, tsCheckout)
	releaseDir, tsCheckout = filepath.Join(dir, "release"), filepath.Join(dir, "ts")
	defer func(r func() (string, error)) { imageUserRelease = r }(imageUserRelease)
	imageUserRelease = func() (string, error) { return "0.50.0-dev", nil }
	const source, target = "abcdefghijklmnopqrstuvwx", "bcdefghijklmnopqrstuvwxy"
	good := map[string]string{"VL_RH_PROFILE": "box", "VL_RH_INGRESS": "combined", "VL_RH_TARGET": "image", "VL_RH_PUBLIC_NAME": "rh.example", "VL_RH_GIT_NAME": "git.rh.example",
		"VL_RH_GO_IMAGE": "127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev@sha256:" + strings.Repeat("a", 64), "VL_RH_COOLIFY_SOURCE_DIR": "/data/coolify/applications/" + source, "VL_RH_COOLIFY_TARGET": target,
		"VL_RH_SOURCE": "", "VL_RH_KILL": "", "VL_RH_SYNC": "", "VL_RH_ONLY": "", "VL_RH_TAILSCALE_OAUTH_FILE": "", "VL_RH_TAILSCALE_AUTH_KEY_FILE": "", "VL_RH_TAILSCALE_TAILNET": ""}
	files := []string{filepath.Join(releaseDir, "coolify-image-digests.env"), filepath.Join(tsCheckout, tailscaleCompose), filepath.Join(tsCheckout, "infra", "compose", "docker-compose.yml"), filepath.Join(tsCheckout, "infra", "coolify", "README.md")}
	try := func(t *testing.T, change map[string]string, euid int) error {
		t.Helper()
		for k, v := range good {
			if c, ok := change[k]; ok {
				v = c
			}
			t.Setenv(k, v)
		}
		_, err := readProfile(euid)
		return err
	}
	for _, f := range files {
		if err := try(t, nil, 0); err == nil || !strings.Contains(err.Error(), f) {
			t.Errorf("without %s: %v", f, err)
		}
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := try(t, nil, 0); err != nil {
		t.Errorf("with everything: %v", err)
	}
	for _, c := range []struct{ name, value, want string }{
		{"VL_RH_PROFILE", "", "runs on the box only"},
		{"VL_RH_TARGET", "host", "VL_RH_TARGET=image"},
		{"VL_RH_GO_IMAGE", "", "VL_RH_GO_IMAGE"},
		{"VL_RH_GO_IMAGE", "nginx", "VL_RH_GO_IMAGE"},
		{"VL_RH_COOLIFY_SOURCE_DIR", "", "VL_RH_COOLIFY_SOURCE_DIR"},
		{"VL_RH_COOLIFY_SOURCE_DIR", "/data/coolify/applications/UPPER", "ends in the source app's UUID"},
		{"VL_RH_COOLIFY_SOURCE_DIR", "/data/coolify/applications/" + target, "another"},
		{"VL_RH_COOLIFY_TARGET", "", "VL_RH_COOLIFY_TARGET"},
		{"VL_RH_COOLIFY_TARGET", "../x", "VL_RH_COOLIFY_TARGET"},
		{"VL_RH_PUBLIC_NAME", "", "VL_RH_PUBLIC_NAME"},
		{"VL_RH_GIT_NAME", "", "VL_RH_GIT_NAME"},
		{"VL_RH_GIT_NAME", "rh.example", "two names"},
		{"VL_RH_KILL", "barrier", "leave VL_RH_KILL"},
		{"VL_RH_ONLY", "setup", "leave VL_RH_ONLY unset"},
		{"VL_RH_SYNC", "fakes", "VL_RH_SYNC"},
	} {
		if err := try(t, map[string]string{c.name: c.value}, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s=%s: %v, want %q", c.name, c.value, err, c.want)
		}
	}
	if err := try(t, nil, 1000); err == nil || !strings.Contains(err.Error(), "runs as root") {
		t.Errorf("not as root: %v", err)
	}
}

// The sidecar's settings in the release's file: added once each, nothing
// else changed; a file they do not fit is refused.
func TestSidecarEdit(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", tailscaleCompose))
	if err != nil {
		t.Skipf("no Compose file in this checkout: %v", err)
	}
	got, err := sidecarEdit(string(b), "https://10.0.0.1:18443", "/srv/vl-rh/x/tailnet/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	added := []string{"      TS_EXTRA_ARGS: --login-server=https://10.0.0.1:18443\n", "      SSL_CERT_FILE: /vl-rh-tailnet/ca.pem\n", "      - /srv/vl-rh/x/tailnet/ca.pem:/vl-rh-tailnet/ca.pem:ro\n"}
	back := got
	for _, a := range added {
		if strings.Count(got, a) != 1 {
			t.Errorf("%q is there %d times", a, strings.Count(got, a))
		}
		back = strings.Replace(back, a, "", 1)
	}
	if back != string(b) {
		t.Error("something else changed")
	}
	if i, k := strings.Index(got, "\n  tailscale:\n"), strings.Index(got, added[0]); i < 0 || k < i {
		t.Error("the settings are not the sidecar's")
	}
	for _, bad := range []string{"", string(b) + string(b)} {
		if _, err := sidecarEdit(bad, "u", "c"); err == nil || !strings.Contains(err.Error(), "not once") {
			t.Errorf("a file they do not fit: %v", err)
		}
	}
}

// migrate's route, taken from what it says word for word.
func TestRouteText(t *testing.T) {
	const file = "http:\n  routers:\n    varlatch-rollback:\n      rule: \"Host(`rh.example`)\"\n      middlewares: [varlatch-rollback]\n  services:\n    x: {}\n"
	said := "Address back, by hand, before the reverse begins (why): do not Deploy. Put this in the proxy, as /data/coolify/proxy/dynamic/varlatch-rollback.yaml on the host (or in Coolify: x). It routes the name; the address does not answer from Go from then on:\n" +
		file + "Then run varlatch migrate --rollback again: it starts the dashboard.\n"
	if path, text, err := routeText("before\n" + said + "after"); err != nil || path != routePath || text != file {
		t.Errorf("%s %q %v", path, text, err)
	}
	if _, _, err := routeText("Rolled back."); err == nil {
		t.Error("no route was found")
	}
}
