// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// .env as the reverse writes it (#370 review): a line longer than a
// scanner's 64 KiB token is read whole and kept byte for byte, never a
// truncated .env written over the operator's; the one line changed or
// added, every other byte as it was (comments, quoting, a missing last
// newline); COMPOSE_FILE removed again restores the file exactly; a .env
// that is a symbolic link is written at its target, the link kept.
func TestTheReverseWritesEnvWhole(t *testing.T) {
	dir := t.TempDir()
	c := &Compose{Directory: dir}
	long := strings.Repeat("x", 200<<10)
	orig := "# the operator's\nVARLATCH_PUBLIC_URL=\"https://vault.example.test\"\nLONG=" + long + "\nBIND_ADDRESS=127.0.0.1"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	env, err := c.envFile()
	if err != nil || env["LONG"] != long || env["BIND_ADDRESS"] != "127.0.0.1" || env["VARLATCH_PUBLIC_URL"] != "https://vault.example.test" {
		t.Fatalf("read: %d values, %v", len(env), err)
	}
	files := "docker-compose.yml:" + OverrideFile
	if err := c.setEnv("COMPOSE_FILE", &files); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if want := orig + "\nCOMPOSE_FILE=" + files + "\n"; string(b) != want {
		t.Fatalf("written: %d bytes, want %d", len(b), len(want))
	}
	if st, _ := os.Stat(filepath.Join(dir, ".env")); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	if err := c.setEnv("COMPOSE_FILE", nil); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, ".env"))
	if string(b) != orig+"\n" || !bytes.Contains(b, []byte(long)) {
		t.Errorf("restored: %d bytes, want %d", len(b), len(orig)+1)
	}
	// A line replaced in place.
	other := "docker-compose.yml:docker-compose.caddy.yml"
	if err := c.setEnv("BIND_ADDRESS", &other); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".env")); !strings.HasSuffix(string(b), "LONG="+long+"\nBIND_ADDRESS="+other+"\n") {
		t.Error("the line was not replaced in place")
	}
	// A symbolic link: its target written, the link kept.
	real := filepath.Join(t.TempDir(), "env.real")
	if err := os.WriteFile(real, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.Symlink(real, filepath.Join(linked, ".env")); err != nil {
		t.Fatal(err)
	}
	lc := &Compose{Directory: linked}
	if err := lc.setEnv("COMPOSE_FILE", &files); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(linked, ".env")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != "A=1\nCOMPOSE_FILE="+files+"\n" {
		t.Errorf("the target: %q", b)
	}
	// A link whose target is not there: refused, the link left as it is.
	dangling := t.TempDir()
	if err := os.Symlink(filepath.Join(dangling, "gone"), filepath.Join(dangling, ".env")); err != nil {
		t.Fatal(err)
	}
	dc := &Compose{Directory: dangling}
	if err := dc.setEnv("COMPOSE_FILE", &files); err == nil || !strings.Contains(err.Error(), "which is not there") {
		t.Errorf("a dangling link: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(dangling, ".env")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the dangling link after the refusal: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dangling, "gone")); !os.IsNotExist(err) {
		t.Errorf("a target made: %v", err)
	}
}

// The project is Compose's own (#371 review P2-2): its files' top-level
// name:, read uninterpolated (the interpolated configuration would carry
// .env's secrets), never the directory's name; the fresh volumes are named
// by it; an answer without a name, or a failed config, refuses.
func TestTheProjectIsCompose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "varlatch-0.23.0")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"varlatch","services":{}}`)}}}
	c := &Compose{Directory: dir, Run: run}
	j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}
	plan, err := c.RebuildPlan(t.Context(), j)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Volumes[0] != "varlatch_postgres-data-abcdefgh" || plan.Volumes[1] != "varlatch_convex-data-abcdefgh" {
		t.Errorf("the fresh volumes: %v", plan.Volumes)
	}
	for _, bad := range []Ran{{Answer: []byte(`{"services":{}}`)}, {Answer: []byte("not json")}, {Code: 1, Said: []byte("no configuration file provided")},
		{Answer: []byte(`{"name":"a b"}`)}} {
		run.answers["docker compose config --no-interpolate --format json"] = bad
		if _, err := c.RebuildPlan(t.Context(), j); err == nil {
			t.Errorf("%q: no refusal", bad.Answer)
		}
	}
}

// The reverse undone starts the TypeScript varlatchd without its one-off
// dependency (varlatch-migrate, which refuses behind the migrated-out
// marker). Where varlatchd runs in the Tailscale sidecar's network and the
// sidecar is not running, nothing of varlatchd's is started: the step to
// take is said, the sidecar never started by migrate.
func TestTheReverseUndoneStartsVarlatchdWithoutItsDependency(t *testing.T) {
	for _, c := range []struct {
		name, config, running, why string
	}{
		{"its own network", `{"name":"varlatch","services":{"varlatchd":{}}}`, "postgres\nconvex-backend\n", ""},
		{"the sidecar's, running", `{"name":"varlatch","services":{"varlatchd":{"network_mode":"service:tailscale"}}}`, "postgres\ntailscale\n", ""},
		{"the sidecar's, stopped", `{"name":"varlatch","services":{"varlatchd":{"network_mode":"service:tailscale"}}}`, "postgres\n",
			"start it by hand (docker compose up -d --no-deps tailscale"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("VARLATCH_PUBLIC_URL=https://vault.example.test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			run := &scripted{t: t, answers: map[string]Ran{
				"docker compose stop ":                                                  {},
				"docker compose up -d postgres convex-backend":                          {},
				"docker ps -a --filter volume=":                                         {},
				"docker volume rm -f ":                                                  {},
				"docker compose config --no-interpolate --format json":                  {Answer: []byte(c.config)},
				"docker compose ps --status running --services":                         {Answer: []byte(c.running)},
				"docker compose run --rm -T --no-deps varlatchd admin migration status": {Answer: []byte(`{"daemon":false,"gate":{"kind":"migrated-out","id":"gate-1"}}`)},
				"docker compose up -d --no-deps varlatchd":                              {},
			}}
			cmp := &Compose{Directory: dir, Run: run}
			err := cmp.UndoRebuild(t.Context(), RebuildRecord{Override: OverrideFile, Volumes: []string{"varlatch_postgres-data-abcdefgh"}})
			started := slices.Contains(run.ran, "docker compose up -d --no-deps varlatchd")
			for _, r := range run.ran {
				if r == "docker compose up -d varlatchd" || strings.HasPrefix(r, "docker compose up -d --no-deps tailscale") || strings.HasPrefix(r, "docker compose start") {
					t.Errorf("ran %q", r)
				}
			}
			if c.why == "" {
				if err != nil || !started {
					t.Fatalf("%v, started %v: %v", err, started, run.ran)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.why) || !strings.Contains(err.Error(), "varlatch migrate --resume") || started ||
				slices.ContainsFunc(run.ran, func(r string) bool { return strings.Contains(r, "admin migration") }) {
				t.Fatalf("%v, started %v: %v", err, started, run.ran)
			}
		})
	}
}

// StartNetworkOwner starts only the service varlatchd shares its network
// with, and only when it is not running: never varlatchd, never a service
// of its own network.
func TestStartNetworkOwner(t *testing.T) {
	for _, c := range []struct {
		name, config, running string
		started               bool
	}{
		{"its own network", `{"name":"varlatch","services":{"varlatchd":{}}}`, "postgres\n", false},
		{"the sidecar's, running", `{"name":"varlatch","services":{"varlatchd":{"network_mode":"service:tailscale"}}}`, "postgres\ntailscale\n", false},
		{"the sidecar's, stopped", `{"name":"varlatch","services":{"varlatchd":{"network_mode":"service:tailscale"}}}`, "postgres\n", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := &scripted{t: t, answers: map[string]Ran{
				"docker compose config --no-interpolate --format json": {Answer: []byte(c.config)},
				"docker compose ps --status running --services":        {Answer: []byte(c.running)},
				"docker compose start tailscale":                       {},
			}}
			cmp := &Compose{Directory: t.TempDir(), Run: run}
			if err := cmp.StartNetworkOwner(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(run.ran, "docker compose start tailscale"); got != c.started {
				t.Fatalf("started %v, want %v: %v", got, c.started, run.ran)
			}
			for _, r := range run.ran {
				if strings.Contains(r, "varlatchd") && strings.HasPrefix(r, "docker compose up") || strings.HasPrefix(r, "docker compose restart") {
					t.Errorf("ran %q", r)
				}
			}
		})
	}
}

// The sidecar is migrate's own to start for a reverse only after a
// tailnet handoff that moved the name; otherwise a stopped sidecar is the
// operator's (ReverseReady refuses it).
func TestSidecarOwned(t *testing.T) {
	for _, c := range []struct {
		name string
		j    *Journal
		want bool
	}{
		{"no tailnet", &Journal{}, false},
		{"a handoff prepared, nothing moved", &Journal{Tailnet: &TailnetRecord{Handoff: &tailhandoff.State{Phase: tailhandoff.Prepared}}}, false},
		{"a handoff undone", &Journal{Tailnet: &TailnetRecord{Handoff: &tailhandoff.State{Phase: tailhandoff.Undone}}}, false},
		{"the name moved", &Journal{Tailnet: &TailnetRecord{Handoff: &tailhandoff.State{Phase: tailhandoff.Done}}}, true},
	} {
		if got := sidecarOwned(c.j); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// A service's environment as `docker compose config --format json`
// prints it, in both forms: testdata/compose-config holds Compose 5.6.1's
// own output (docker compose -f docker-compose.yml [-f override.yml]
// config --no-interpolate --format json) for a list (- A=1), a map, and a
// map an overlay merged a list into (printed as a list). A name without a
// value is not set.
func TestComposeEnvironmentForms(t *testing.T) {
	str := func(v string) *string { return &v }
	for file, want := range map[string]map[string]composeEnv{
		// The map's unquoted number and boolean are JSON ones there.
		"map-and-list.json": {
			"a": {"A": str("1"), "B": nil, "C": str(""), "D": str("b=c")},
			"b": {"X": str("1"), "Y": nil, "PORT": str("8080"), "FLAG": str("false"), "RATIO": str("1.5")},
		},
		"overlay-list.json": {
			"a": {"A": str("1"), "B": nil, "C": str(""), "D": str("b=c")},
			"b": {"X": str("1"), "Y": nil, "Z": str("2"), "PORT": str("8080"), "FLAG": str("false"), "RATIO": str("1.5")},
		},
	} {
		b, err := os.ReadFile(filepath.Join("testdata", "compose-config", file))
		if err != nil {
			t.Fatal(err)
		}
		run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: b}}}
		cfg, err := (&Compose{Directory: t.TempDir(), Run: run}).config(t.Context())
		if err != nil || cfg.Name != "envprobe" {
			t.Fatalf("%s: %+v %v", file, cfg, err)
		}
		for svc, env := range want {
			got := cfg.Services[svc].Environment
			if len(got) != len(env) {
				t.Errorf("%s %s: %v", file, svc, got)
			}
			for k, v := range env {
				g, ok := got[k]
				if !ok || (v == nil) != (g == nil) || v != nil && *v != *g {
					t.Errorf("%s %s %s: %v, want %v", file, svc, k, g, v)
				}
			}
		}
	}
	// A name a list repeats: the last one holds, as in a container's
	// environment.
	run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"p","services":{"a":{"environment":["A=1","A=2","B=x","B"]}}}`)}}}
	cfg, err := (&Compose{Directory: t.TempDir(), Run: run}).config(t.Context())
	if env := cfg.Services["a"].Environment; err != nil || env["A"] == nil || *env["A"] != "2" || env["B"] != nil || len(env) != 2 {
		t.Fatalf("a repeated name: %v %v", env, err)
	}
	// What Compose cannot have printed is said as such, not as a project
	// without a name.
	for _, bad := range []string{`42`, `{"A":{"x":1}}`, `{"A":["x"]}`, `[1]`} {
		run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"p","services":{"a":{"environment":` + bad + `}}}`)}}}
		if _, err := (&Compose{Directory: t.TempDir(), Run: run}).config(t.Context()); err == nil || !strings.Contains(err.Error(), "a configuration migrate cannot read") {
			t.Errorf("the environment %s: %v", bad, err)
		}
	}
}
