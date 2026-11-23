// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// labelled is a host with Compose containers.
type labelled struct {
	containers []composeLabels
}

func (h *labelled) answer(args []string) (Ran, bool) {
	switch {
	case len(args) > 2 && args[0] == "ps" && args[1] == "-a" && args[2] == "-q" && slices.Contains(args, "label="+labelProject):
		var ids []string
		for i := range h.containers {
			ids = append(ids, "c"+string(rune('a'+i)))
		}
		return Ran{Answer: []byte(strings.Join(ids, "\n"))}, true
	case len(args) > 4 && args[0] == "inspect" && slices.Contains(args, labelsFormat):
		var b strings.Builder
		for _, l := range h.containers {
			for _, v := range []string{l.project, l.service, l.files, l.dir, l.oneOff} {
				q, _ := json.Marshal(v)
				b.Write(q)
				b.WriteByte(' ')
			}
			b.WriteByte('\n')
		}
		return Ran{Answer: []byte(b.String())}, true
	}
	return Ran{}, false
}

// installationDir is a directory with files of those names.
func installationDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// coolifyDir is Coolify's directory of the TypeScript application, as
// production's and the lab's are: the repository's Compose files (its
// docker-compose.yml names the project varlatch), Coolify's own
// docker-compose.yaml, and the file the containers run from.
func coolifyDir(t *testing.T) string {
	return installationDir(t, map[string]string{
		"docker-compose.yml":                   "name: varlatch\nservices: {}\n",
		"docker-compose.yaml":                  "services: {}\n",
		"docker-compose.coolify-tailscale.yml": "services: {}\n",
		"docker-compose.caddy.yml":             "services: {}\n",
		".env":                                 "VARLATCH_PUBLIC_URL=https://vault.example.test\nVARLATCH_VARLATCHD_DIGEST=sha256:" + strings.Repeat("a", 64) + "\n",
	})
}

const appID = "abcdefghijklmnopqrstuvwx"

func TestComposeProject(t *testing.T) {
	const stock = "docker-compose.yml"
	one := map[string]string{stock: "services: {}\n"}
	at := func(project, service, dir string, files ...string) composeLabels {
		var abs []string
		for _, f := range files {
			if !filepath.IsAbs(f) {
				f = filepath.Join(dir, f)
			}
			abs = append(abs, f)
		}
		return composeLabels{project, service, strings.Join(abs, ","), dir, "False"}
	}
	for _, c := range []struct {
		name       string
		dir        func(t *testing.T) string
		containers func(dir string) []composeLabels
		env        func(dir string) []string
		project    string
		files      []string
		refused    []string
	}{
		{"Coolify's directory: the labels, not the files there", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at(appID, "postgres", d, "docker-compose.coolify-tailscale.yml"),
					at("another", "varlatchd", "/data/coolify/applications/another", "docker-compose.coolify.yml")}
			}, nil, appID, []string{"docker-compose.coolify-tailscale.yml"}, nil},
		{"the shell agrees, as the backup job's configuration does", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml")}
			},
			func(d string) []string {
				return []string{"COMPOSE_FILE=docker-compose.coolify-tailscale.yml", "COMPOSE_PROJECT_NAME=" + appID}
			}, appID, []string{"docker-compose.coolify-tailscale.yml"}, nil},
		{"the shell's files differ", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml")}
			},
			func(d string) []string { return []string{"COMPOSE_FILE=docker-compose.yml"} }, "", nil,
			[]string{"COMPOSE_FILE in the environment names", "docker-compose.yml", "docker-compose.coolify-tailscale.yml"}},
		{"the shell's project differs", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml")}
			},
			func(d string) []string { return []string{"COMPOSE_PROJECT_NAME=varlatch"} }, "", nil,
			[]string{"COMPOSE_PROJECT_NAME in the environment is varlatch", appID}},
		{".env's project differs", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", ".env": "COMPOSE_PROJECT_NAME=other\n"})
		}, func(d string) []composeLabels { return []composeLabels{at("varlatch", "varlatchd", d, stock)} }, nil, "", nil,
			[]string{"COMPOSE_PROJECT_NAME in", "is other", "varlatch"}},
		{"Coolify's directory without containers", coolifyDir, nil, nil, "", nil,
			[]string{"several Compose files", "docker-compose.yml, docker-compose.yaml", "COMPOSE_FILE"}},
		{"Coolify's directory without containers, COMPOSE_FILE given", coolifyDir, nil,
			func(d string) []string { return []string{"COMPOSE_FILE=docker-compose.coolify-tailscale.yml"} }, "asked", []string{"docker-compose.coolify-tailscale.yml"}, nil},
		{"one docker-compose.yaml", func(t *testing.T) string {
			return installationDir(t, map[string]string{"docker-compose.yaml": "services: {}\n"})
		}, func(d string) []composeLabels {
			return []composeLabels{at(appID, "varlatchd", d, "docker-compose.yaml")}
		}, nil, appID, []string{"docker-compose.yaml"}, nil},
		{"one docker-compose.yaml, no containers", func(t *testing.T) string {
			return installationDir(t, map[string]string{"docker-compose.yaml": "services: {}\n"})
		}, nil, nil, "asked", []string{"docker-compose.yaml"}, nil},
		{"the stock file", func(t *testing.T) string { return installationDir(t, one) },
			func(d string) []composeLabels {
				return []composeLabels{at("varlatch", "varlatchd", d, stock), {"varlatch", "varlatchd", "/elsewhere/x.yml", "/elsewhere", "True"}}
			}, nil, "varlatch", []string{stock}, nil},
		{"the stock file and its override, no containers", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.override.yml": "services: {}\n"})
		}, nil, nil, "asked", []string{stock, "docker-compose.override.yml"}, nil},
		{"two overrides, no containers", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.override.yml": "services: {}\n", "compose.override.yml": "services: {}\n"})
		}, nil, nil, "", nil, []string{"several Compose files", "docker-compose.override.yml"}},
		{"a file added to .env since: varlatchd's label is the old list", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.caddy.yml": "services: {}\n", ".env": "COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\n"})
		}, func(d string) []composeLabels {
			return []composeLabels{at("varlatch", "varlatchd", d, stock), at("varlatch", "caddy", d, stock, "docker-compose.caddy.yml")}
		}, nil, "varlatch", []string{stock, "docker-compose.caddy.yml"}, nil},
		{"containers of different files, the directory names neither", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at(appID, "postgres", d, "docker-compose.yaml")}
			}, nil, "", nil, []string{"made from different files", "docker-compose.coolify-tailscale.yml", "docker-compose.yaml"}},
		{".env names other files than any container's", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.caddy.yml": "services: {}\n", ".env": "COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\n"})
		}, func(d string) []composeLabels { return []composeLabels{at("varlatch", "varlatchd", d, stock)} }, nil, "", nil,
			[]string{"COMPOSE_FILE names the Compose files", "docker-compose.caddy.yml", "were made from"}},
		{"two projects", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at("varlatch", "varlatchd", d, stock)}
			}, nil, "", nil, []string{"2 Compose projects", appID, "varlatch"}},
		{"one project from two directories", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at(appID, "postgres", "/elsewhere", "docker-compose.yml")}
			}, nil, "", nil, []string{"runs from", "/elsewhere"}},
		{"this directory's files, another project directory", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{{appID, "varlatchd", filepath.Join(d, stock), "/elsewhere", "False"}}
			}, nil, "", nil, []string{"its project directory is /elsewhere"}},
		{"a label's file that is gone", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "docker-compose.coolify.yml")}
			}, nil, "", nil, []string{"docker-compose.coolify.yml", "which is not there"}},
		{"a file of another directory first", coolifyDir,
			func(d string) []composeLabels {
				return []composeLabels{at(appID, "varlatchd", d, "/artifacts/x/docker-compose.yml")}
			}, nil, "", nil, []string{"/artifacts/x/docker-compose.yml"}},
		{"a label without files", coolifyDir,
			func(d string) []composeLabels { return []composeLabels{{appID, "varlatchd", "", d, "False"}} }, nil, "", nil,
			[]string{"names no Compose file it was made from"}},
		{"migrate's own file is not the installation's", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", OverrideFile: "services: {}\n", ".env": "COMPOSE_FILE=docker-compose.yml:" + OverrideFile + "\n"})
		}, func(d string) []composeLabels {
			return []composeLabels{at("varlatch", "varlatchd", d, stock), at("varlatch", "postgres", d, stock, OverrideFile)}
		}, nil, "varlatch", []string{stock}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := c.dir(t)
			host := &labelled{}
			if c.containers != nil {
				host.containers = c.containers(dir)
			}
			run := &scripted{t: t, host: host, nameless: true, answers: map[string]Ran{
				"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"asked","services":{}}`)}}}
			cmp := &Compose{Directory: dir, Run: run}
			if c.env != nil {
				cmp.Env = c.env(dir)
			}
			p, err := cmp.project(context.Background())
			if len(c.refused) > 0 {
				for _, w := range c.refused {
					if err == nil || !strings.Contains(err.Error(), w) {
						t.Errorf("%v (%v), want %q", p, err, w)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, f := range c.files {
				want = append(want, filepath.Join(dir, f))
			}
			if p.Name != c.project || p.Dir != dir || !slices.Equal(p.Files, want) {
				t.Errorf("%v, want %s of %v", p, c.project, want)
			}
		})
	}
}

// A comma in a path, where Compose joins paths with commas.
func TestLabelPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a,b")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"one.yml", "two,three.yml"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		files string
		want  []string
	}{
		{filepath.Join(dir, "one.yml") + "," + filepath.Join(dir, "two,three.yml"), []string{filepath.Join(dir, "one.yml"), filepath.Join(dir, "two,three.yml")}},
		{"one.yml,two,three.yml", []string{filepath.Join(dir, "one.yml"), filepath.Join(dir, "two,three.yml")}},
		{"gone.yml,one.yml", []string{filepath.Join(dir, "gone.yml"), filepath.Join(dir, "one.yml")}},
		{"", nil},
	} {
		if got := labelPaths(composeLabels{files: c.files, dir: dir}); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.files, got, c.want)
		}
	}
}

// A linked --from: the project's directory and files stay as the labels
// name them, so that Compose makes the same containers from them.
func TestComposeProjectLinkedDirectory(t *testing.T) {
	dir := coolifyDir(t)
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{dir, link}, {link, dir}} {
		labels, from := c[0], c[1]
		host := &labelled{containers: []composeLabels{{appID, "varlatchd", filepath.Join(labels, "docker-compose.coolify-tailscale.yml"), labels, "False"}}}
		p, err := (&Compose{Directory: from, Run: &scripted{t: t, host: host}}).project(t.Context())
		if err != nil || p.Dir != labels || p.Files[0] != filepath.Join(labels, "docker-compose.coolify-tailscale.yml") {
			t.Errorf("labels %s, --from %s: %v %v", labels, from, p, err)
		}
	}
}

// What the journal records is used, and refused when the containers are
// of another project, or its files are gone; without containers it holds.
func TestComposeProjectJournalled(t *testing.T) {
	dir := coolifyDir(t)
	kept := &ComposeProject{Name: appID, Dir: dir, Files: []string{filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}}
	for _, c := range []struct {
		name, project, file, refused string
		none                         bool
	}{
		{"the same", appID, "docker-compose.coolify-tailscale.yml", "", false},
		{"no containers", "", "", "", true},
		{"another project", "varlatch", "docker-compose.coolify-tailscale.yml", "the migration's journal records the Compose project " + appID, false},
		{"other files", appID, "docker-compose.yaml", "are now of", false},
	} {
		host := &labelled{containers: []composeLabels{{c.project, "varlatchd", filepath.Join(dir, c.file), dir, "False"}}}
		if c.none {
			host.containers = nil
		}
		cmp := &Compose{Directory: dir, Run: &scripted{t: t, host: host}}
		cmp.KeepProject(kept)
		err := cmp.CheckProject(t.Context())
		if (c.refused == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.refused) {
			t.Errorf("%s: %v, want %q", c.name, err, c.refused)
		}
	}
	if err := os.Remove(kept.Files[0]); err != nil {
		t.Fatal(err)
	}
	cmp := &Compose{Directory: dir, Run: &scripted{t: t, host: &labelled{}}}
	cmp.KeepProject(kept)
	if err := cmp.CheckProject(t.Context()); err == nil || !strings.Contains(err.Error(), "which is not there") {
		t.Errorf("a file gone: %v", err)
	}
}

// Every docker compose command names the project, its directory and its
// files, with migrate's own file while .env names it; the TypeScript CLI
// is given the same in its environment; other docker commands are as they
// were.
func TestComposeCommandsNameTheProject(t *testing.T) {
	dir := coolifyDir(t)
	file := filepath.Join(dir, "docker-compose.coolify-tailscale.yml")
	named := []string{"compose", "--project-name", appID, "--project-directory", dir, "-f", file}
	run := &scripted{t: t, answers: map[string]Ran{"docker ": {}, "varlatch-ts ": {Answer: []byte("Archive created: /x (11111111-2222-3333-4444-555555555555)\nUpload completed to offsite\n")}}}
	c := &Compose{Directory: dir, Run: run, BEKFile: "/b", Destination: "d", resolved: &ComposeProject{Name: appID, Dir: dir, Files: []string{file}}}
	ctx := t.Context()
	_, _ = c.Gate(ctx)
	_ = c.Release(ctx, "g")
	_ = c.MarkMigratedOut(ctx, "g")
	_, _ = c.Export(ctx, []byte("k"), true)
	_ = c.StopIngress(ctx, Proxy)
	_ = c.StartIngress(ctx, Public, true)
	_ = c.StopTailnet(ctx)
	_ = c.StartTailnet(ctx)
	_ = c.StopStarted(ctx, []string{"postgres"})
	_ = c.ResetConvex(ctx)
	_ = c.StartServing(ctx, Coolify)
	_ = c.StopServing(ctx, Coolify)
	_, _ = c.running(ctx)
	_, _ = c.gateOffline(ctx)
	_, _, _ = c.TailnetCertExpiry(ctx, "a.example.ts.net")
	if len(run.argv) < 16 {
		t.Fatalf("%d compose commands", len(run.argv))
	}
	for _, a := range run.argv {
		if len(a) <= len(named) || !slices.Equal(a[:len(named)], named) {
			t.Errorf("ran %q, want it to start %q", a, named)
		}
	}
	if got, err := c.argv(ctx, []string{"volume", "rm", "x"}); err != nil || !slices.Equal(got, []string{"volume", "rm", "x"}) {
		t.Errorf("another docker command: %q %v", got, err)
	}
	if _, err := c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	for key, env := range run.envs {
		if want := []string{"COMPOSE_PROJECT_NAME=" + appID, "COMPOSE_FILE=" + file, "COMPOSE_PATH_SEPARATOR=:"}; !strings.HasPrefix(key, "varlatch-ts admin backup create") || !slices.Equal(env, want) {
			t.Errorf("%s: %q, want %q", key, env, want)
		}
	}
	if len(run.envs) != 1 {
		t.Errorf("%d programs with an environment", len(run.envs))
	}
	if said := c.byHand("ps"); !strings.Contains(said, "--project-name "+appID) {
		t.Errorf("by hand: %s", said)
	}
	// A reverse's database in use.
	f := "docker-compose.coolify-tailscale.yml:" + OverrideFile
	if err := c.setEnv("COMPOSE_FILE", &f); err != nil {
		t.Fatal(err)
	}
	got, err := c.argv(ctx, []string{"compose", "up"})
	if want := append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "up"); err != nil || !slices.Equal(got, want) {
		t.Errorf("%q %v, want %q", got, err, want)
	}
	stock := installationDir(t, map[string]string{"docker-compose.yml": "services: {}\n"})
	if said := (&Compose{Directory: stock, resolved: testProject(stock)}).byHand("ps"); said != "docker compose ps" {
		t.Errorf("by hand, stock: %s", said)
	}
}

// The reverse's Compose file, by the names the installation's files give:
// the stock installation's file is as it was; Coolify's rendered file
// prefixes its volumes and puts its services on the application's network.
// testdata/compose-config/coolify-tailscale.json is Compose 5.6.1's
// answer for a file Coolify 4.7.6 rendered.
func TestReverseOverrideNames(t *testing.T) {
	j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}
	plan := func(config []byte, dir string) RebuildRecord {
		t.Helper()
		run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: config}}}
		p, err := (&Compose{Directory: dir, Run: run, resolved: testProject(dir)}).RebuildPlan(t.Context(), j)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	stock := plan([]byte(stockConfig), t.TempDir())
	if stock.Keys != nil || stock.Networks != nil || !strings.Contains(override(stock), "volumes:\n  postgres-data:\n    name: varlatch_postgres-data-abcdefgh\n  convex-data:\n") ||
		!strings.Contains(override(stock), "      - varlatch-state:/var/lib/varlatch\n") || strings.Contains(override(stock), "networks:") {
		t.Errorf("stock: %+v\n%s", stock, override(stock))
	}
	b, err := os.ReadFile(filepath.Join("testdata", "compose-config", "coolify-tailscale.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cool := plan(b, dir)
	text := override(cool)
	for _, w := range []string{"  " + appID + "_postgres-data:\n    name: " + appID + "_postgres-data-abcdefgh\n", "  " + appID + "_convex-data:\n    name: " + appID + "_convex-data-abcdefgh\n",
		"      - " + appID + "_varlatch-state:/var/lib/varlatch\n", "    networks:\n      - " + appID + "\n"} {
		if !strings.Contains(text, w) {
			t.Errorf("no %q in\n%s", w, text)
		}
	}
	// --finish reads the fresh volumes from it.
	if err := os.WriteFile(filepath.Join(dir, OverrideFile), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Compose{Directory: dir}
	f := "x.yml:" + OverrideFile
	if err := c.setEnv("COMPOSE_FILE", &f); err != nil {
		t.Fatal(err)
	}
	if vols, rebuilt, err := c.dataVolumes(appID); err != nil || !rebuilt || !slices.Equal(vols, cool.Volumes) {
		t.Errorf("%v %v %v, want %v", vols, rebuilt, err, cool.Volumes)
	}
	// A file whose Postgres mounts no named volume cannot be given a fresh
	// one.
	run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"varlatch","services":{"postgres":{"volumes":["/data:/var/lib/postgresql/data"]}}}`)}}}
	if _, err := (&Compose{Directory: dir, Run: run, resolved: testProject(dir)}).RebuildPlan(t.Context(), j); err == nil || !strings.Contains(err.Error(), "mounts no named volume") {
		t.Errorf("no named volume: %v", err)
	}
	// COMPOSE_FILE keeps the installation's own names.
	for _, c := range []struct{ file, want string }{{"docker-compose.yml", "docker-compose.yml:" + OverrideFile}, {"docker-compose.coolify-tailscale.yml", "docker-compose.coolify-tailscale.yml:" + OverrideFile}} {
		d := t.TempDir()
		cmp := &Compose{Directory: d, resolved: &ComposeProject{Name: "p", Dir: d, Files: []string{filepath.Join(d, c.file)}}}
		if got, err := cmp.composeFiles(t.Context(), RebuildRecord{}); err != nil || got != c.want {
			t.Errorf("%s: %s %v", c.file, got, err)
		}
	}
}

// On a real Docker (VARLATCH_MIGRATE_TEST_DOCKER=1, with an image that is
// there as VARLATCH_MIGRATE_TEST_IMAGE): a directory shaped as Coolify's,
// its containers created, never started, from the third file under the
// application's id. Plain docker compose reads the repository's file there;
// migrate reads the containers', and its commands reach them.
func TestComposeProjectOnDocker(t *testing.T) {
	image := os.Getenv("VARLATCH_MIGRATE_TEST_IMAGE")
	if os.Getenv("VARLATCH_MIGRATE_TEST_DOCKER") != "1" || image == "" {
		t.Skip("VARLATCH_MIGRATE_TEST_DOCKER is not 1")
	}
	dir := coolifyDir(t)
	const project = "vl-migrate-test-coolify"
	rendered := "services:\n  varlatchd:\n    image: " + image + "\n    command: [\"sleep\", \"1\"]\n    labels:\n      digest: ${VARLATCH_VARLATCHD_DIGEST:?set it}\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.coolify-tailscale.yml"), []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("name: vl-migrate-test-decoy\nservices:\n  varlatchd:\n    image: "+image+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var x ExecRunner
	ctx := t.Context()
	docker := func(args ...string) Ran {
		t.Helper()
		r, err := x.Run(ctx, dir, "docker", args, nil)
		if err != nil || r.Code != 0 {
			t.Fatalf("docker %v: %v %s", args, err, r.Said)
		}
		return r
	}
	named := []string{"compose", "--project-name", project, "--project-directory", dir, "-f", filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}
	t.Cleanup(func() {
		_, _ = x.Run(context.Background(), dir, "docker", append(slices.Clone(named), "down", "--remove-orphans"), nil)
	})
	docker(append(slices.Clone(named), "create", "--pull", "never")...)
	c := &Compose{Directory: dir, Run: x}
	p, err := c.project(ctx)
	if err != nil || p.Name != project || p.Dir != dir || !slices.Equal(p.Files, []string{filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}) {
		t.Fatalf("%v %v", p, err)
	}
	ps := []string{"compose", "ps", "-a", "-q", service}
	r, err := c.docker(ctx, ps, nil)
	if err != nil || r.Code != 0 || len(strings.Fields(string(r.Answer))) != 1 {
		t.Errorf("migrate's %v: %v %s%s", ps, err, r.Answer, r.Said)
	}
	if plain, _ := x.Run(ctx, dir, "docker", ps, nil); len(strings.Fields(string(plain.Answer))) != 0 {
		t.Errorf("plain %v finds %s: the directory does not show the difference", ps, plain.Answer)
	}
	// .env is the project directory's: the digest is interpolated from it.
	cfg, err := c.docker(ctx, []string{"compose", "config", "--format", "json"}, nil)
	if err != nil || cfg.Code != 0 || !strings.Contains(string(cfg.Answer), "sha256:"+strings.Repeat("a", 64)) {
		t.Errorf("config: %v %d %s", err, cfg.Code, cfg.Said)
	}
}

// The engine gives every command that goes on with a migration the
// journal's project, and one that changed is refused before anything of
// --resume, --abort or --rollback is done: the journal and both sides are
// as they were.
func TestTheEngineKeepsTheProject(t *testing.T) {
	project := &ComposeProject{Name: appID, Dir: "/data/coolify/applications/" + appID, Files: []string{"/data/coolify/applications/" + appID + "/docker-compose.coolify-tailscale.yml"}}
	changed := errors.New("the installation was started another way since")
	for _, c := range []struct {
		name  string
		phase Phase
		run   func(*Engine) (*Journal, error)
	}{
		{"resume, held", Copied, func(e *Engine) (*Journal, error) { return e.Resume(context.Background()) }},
		{"resume, transfer", Transfer, func(e *Engine) (*Journal, error) { return e.Resume(context.Background()) }},
		{"resume, switched", Switched, func(e *Engine) (*Journal, error) { return e.Resume(context.Background()) }},
		{"abort, held", Barrier, func(e *Engine) (*Journal, error) { return e.Abort(context.Background()) }},
		{"abort, transfer", Transfer, func(e *Engine) (*Journal, error) { return e.Abort(context.Background()) }},
		{"abort, reverse", Rollback, func(e *Engine) (*Journal, error) { return e.Abort(context.Background()) }},
		{"rollback", Open, func(e *Engine) (*Journal, error) { return e.Rollback(context.Background()) }},
	} {
		w := newWorld(t)
		info := w.src.info
		info.Project = project
		j := &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: c.phase, Source: info, Ingress: Coolify, Rollback: &RollbackRecord{},
			Transfer: &TransferRecord{}, History: []Step{{Phase: Switched, At: w.eng.now().Format(time.RFC3339Nano)}}}
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(w.src.dir, JournalFile))
		w.src.projectErr = changed
		_, err := c.run(w.eng)
		after, _ := os.ReadFile(filepath.Join(w.src.dir, JournalFile))
		if !errors.Is(err, changed) || w.src.checked != 1 || len(w.src.calls) != 0 || string(before) != string(after) {
			t.Errorf("%s: %v, checked %d, calls %v, journal changed %v", c.name, err, w.src.checked, w.src.calls, string(before) != string(after))
		}
		if w.src.kept == nil || w.src.kept.Name != project.Name || !slices.Equal(w.src.kept.Files, project.Files) {
			t.Errorf("%s: kept %v", c.name, w.src.kept)
		}
	}
}
