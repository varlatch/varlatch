// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The run's unit starts and stops as the shipped one does.
func TestTheUnitStopsAsTheShippedOne(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "install", "varlatchd.service"))
	if err != nil {
		t.Skipf("no shipped unit in this checkout: %v", err)
	}
	unit := unitFile("x, y", "/s/service.env", "/b/varlatchd", "/c/varlatchd.conf")
	for _, key := range []string{"Type", "TimeoutStopSec"} {
		re := regexp.MustCompile(`(?m)^` + key + `=.*$`)
		shipped := re.FindAllString(string(b), -1)
		if len(shipped) != 1 || !slices.Equal(re.FindAllString(unit, -1), shipped) {
			t.Errorf("%s: the shipped unit has %q, the run's %q", key, shipped, re.FindAllString(unit, -1))
		}
	}
	service := unit[strings.Index(unit, "[Service]"):strings.Index(unit, "[Install]")]
	for _, l := range []string{"EnvironmentFile=-/s/service.env\n", "ExecStart=/b/varlatchd serve --config /c/varlatchd.conf\n", "Restart=no\n", "TimeoutStopSec="} {
		if strings.Count(service, l) != 1 {
			t.Errorf("[Service] has %q %d times:\n%s", l, strings.Count(service, l), unit)
		}
	}
}

func TestStopsIn(t *testing.T) {
	line := func(id, result string, at int64) string {
		return fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":"s=1;i=2","MESSAGE_ID":"%s","UNIT_RESULT":"%s"}`, at, id, result)
	}
	const started = "39f53479d3a045ac8e11786248231fbf"
	s := int64(time.Second / time.Microsecond)
	lines := []string{
		`{"__REALTIME_TIMESTAMP":"1","__CURSOR":"a line of varlatchd's own"}`,
		line(started, "", 10*s),
		line(msgStopping, "", 20*s), line(msgStopped, "", 20*s+21000),
		line(started, "", 30*s),
		line(msgStopping, "", 40*s), line(msgFailed, "timeout", 70*s), line(msgStopped, "", 70*s+500),
		// Failed, but not by the limit.
		line(msgStopping, "", 80*s), line(msgFailed, "exit-code", 81*s), line(msgStopped, "", 81*s),
		// Still going.
		line(msgStopping, "", 90*s), "",
	}
	got, err := stopsIn(strings.Join(lines, "\n"))
	want := []stopped{{took: 21 * time.Millisecond}, {took: 30*time.Second + 500*time.Microsecond, killed: true}, {took: time.Second}}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("%+v, %v; want %+v", got, err, want)
	}
	if got, err := stopsIn(""); err != nil || len(got) != 0 {
		t.Errorf("nothing: %+v, %v", got, err)
	}
	if _, err := stopsIn("-- No entries --"); err == nil {
		t.Error("what is no JSON is taken")
	}
}

func TestFakeStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stops.log")
	if got, err := fakeStops(path); err != nil || len(got) != 0 {
		t.Errorf("none: %+v, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("21ms\n30.05s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := fakeStops(path); err != nil || !slices.Equal(got, []stopped{{took: 21 * time.Millisecond}, {took: 30*time.Second + 50*time.Millisecond, killed: true}}) {
		t.Errorf("%+v, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("soon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fakeStops(path); err == nil {
		t.Error("what is no duration is taken")
	}
}

// VL_RH_ONLY and VL_RH_KILL are refused where the ingress's case does not
// honour them.
func TestOnlyAndKillByIngress(t *testing.T) {
	dir := t.TempDir()
	defer func(r, ts string) { releaseDir, tsCheckout = r, ts }(releaseDir, tsCheckout)
	releaseDir, tsCheckout = filepath.Join(dir, "release"), filepath.Join(dir, "ts")
	defer func(r func() (string, error)) { imageUserRelease = r }(imageUserRelease)
	imageUserRelease = func() (string, error) { return "0.50.0-dev", nil }
	for _, f := range []string{filepath.Join(releaseDir, "coolify-image-digests.env"), filepath.Join(tsCheckout, "infra", "compose", "docker-compose.coolify.yml"), filepath.Join(tsCheckout, "infra", "coolify", "README.md")} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ profile, ingress, target, only, kill, want string }{
		{"box", "coolify", "image", "", "", ""},
		{"box", "coolify", "image", "", "barrier", "leave VL_RH_KILL unset"},
		{"box", "coolify", "image", "setup", "", "leave VL_RH_ONLY unset"},
		{"box", "coolify", "image", "kill", "barrier", "leave VL_RH_ONLY unset"},
		{"", "tailnet", "host", "", "", ""},
		{"", "tailnet", "host", "setup", "", "leave VL_RH_ONLY unset"},
		{"", "tailnet", "host", "kill", "barrier", "leave VL_RH_KILL and VL_RH_SYNC unset"},
		{"", "proxy", "host", "kill", "barrier", ""},
		{"box", "proxy", "host", "kill", "transfer", ""},
		{"", "proxy", "host", "", "transfer", ""},
	} {
		for k, v := range map[string]string{"VL_RH_PROFILE": c.profile, "VL_RH_INGRESS": c.ingress, "VL_RH_TARGET": c.target, "VL_RH_ONLY": c.only, "VL_RH_KILL": c.kill,
			"VL_RH_SOURCE": "", "VL_RH_SYNC": "", "VL_RH_PUBLIC_NAME": "rh.example", "VL_RH_PUBLIC_BIND": "", "VL_RH_COOLIFY_SOURCE_DIR": filepath.Join(dir, "app"),
			"VL_RH_GO_IMAGE":             "127.0.0.1:5000/vl-rh/varlatchd:0.50.0-dev@sha256:" + strings.Repeat("a", 64),
			"VL_RH_TAILSCALE_OAUTH_FILE": "", "VL_RH_TAILSCALE_AUTH_KEY_FILE": "", "VL_RH_TAILSCALE_TAILNET": ""} {
			t.Setenv(k, v)
		}
		_, err := readProfile(0)
		if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
