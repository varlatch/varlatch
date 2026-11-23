// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// .env as Compose reads it (Compose 5.6.1's answers for the same lines).
func TestComposeEnv(t *testing.T) {
	for _, c := range []struct{ line, name, value string }{
		{"A=one # a comment", "A", "one"},
		{"A=one#not", "A", "one#not"},
		{"A= # nothing", "A", ""},
		{`A="two # in" # out`, "A", "two # in"},
		{`A='three $B # in'`, "A", "three $B # in"},
		{"export A=four", "A", "four"},
		{"\texport\tA=four", "A", "four"},
		{"A: five", "A", "five"},
		{"A = six  ", "A", "six"},
		{`A="x\ny"`, "A", "x\ny"},
		{`A="a \"b\""`, "A", `a "b"`},
		{"A=\"one\ntwo\"\nC=3", "A", "one\ntwo"},
		{"A=seven\r\nC=3", "A", "seven"},
		{"A=https://x.example.test/?a=b:c", "A", "https://x.example.test/?a=b:c"},
		{"# A=no\n\nA=last\nA=wins", "A", "wins"},
		{"exported=1", "exported", "1"},
		{"A=", "A", ""},
		{"NOTE a line of the operator's\nA=ok", "A", "ok"},
	} {
		dir := installationDir(t, map[string]string{".env": c.line + "\n"})
		env, err := (&Compose{Directory: dir}).envFile()
		if v, ok := env[c.name]; err != nil || !ok || v != c.value {
			t.Errorf("%q: %q %v %v, want %q", c.line, v, ok, err, c.value)
		}
	}
	dir := installationDir(t, map[string]string{".env": "B=1\nA=\"never closed\n"})
	if _, err := (&Compose{Directory: dir}).envFile(); err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "never closed") {
		t.Errorf("an open quote: %v", err)
	}
	for _, text := range []string{"COMPOSE_FILE=$X/docker-compose.yml\n", "COMPOSE_FILE=\"${X}.yml\"\n"} {
		dir := installationDir(t, map[string]string{".env": text})
		if _, _, err := (&Compose{Directory: dir}).envValue("COMPOSE_FILE"); err == nil || !strings.Contains(err.Error(), "from another variable") {
			t.Errorf("%q: %v", text, err)
		}
	}
}

// .env's COMPOSE_FILE, written as it is read: with its separator, its line
// replaced whatever its form, and put back byte for byte by an undo.
func TestComposeFileInEnv(t *testing.T) {
	for _, c := range []struct {
		name, env, want string
		files           []string
	}{
		{"none", "A=1\n", "A=1\nCOMPOSE_FILE=a.yml:" + OverrideFile + "\n", []string{"a.yml"}},
		{"plain", "COMPOSE_FILE=a.yml:b.yml\nA=1\n", "COMPOSE_FILE=a.yml:b.yml:" + OverrideFile + "\nA=1\n", []string{"a.yml", "b.yml"}},
		{"a comment", "COMPOSE_FILE=a.yml:b.yml # both\nA=1\n", "COMPOSE_FILE=a.yml:b.yml:" + OverrideFile + "\nA=1\n", []string{"a.yml", "b.yml"}},
		{"quoted, exported", "export COMPOSE_FILE=\"a.yml:b.yml\"  # both\nA=1", "COMPOSE_FILE=a.yml:b.yml:" + OverrideFile + "\nA=1", []string{"a.yml", "b.yml"}},
		{"a colon", "COMPOSE_FILE: 'a.yml:b.yml'", "COMPOSE_FILE=a.yml:b.yml:" + OverrideFile + "\n", []string{"a.yml", "b.yml"}},
		{"its own separator", "COMPOSE_PATH_SEPARATOR=;\nCOMPOSE_FILE=a.yml;b.yml\n", "COMPOSE_PATH_SEPARATOR=;\nCOMPOSE_FILE=a.yml;b.yml;" + OverrideFile + "\n", []string{"a.yml", "b.yml"}},
		{"its own separator, none named", "COMPOSE_PATH_SEPARATOR=,\n", "COMPOSE_PATH_SEPARATOR=,\nCOMPOSE_FILE=a.yml,b.yml," + OverrideFile + "\n", []string{"a.yml", "b.yml"}},
	} {
		dir := installationDir(t, map[string]string{"a.yml": "", "b.yml": "", ".env": c.env})
		cmp := &Compose{Directory: dir, reversed: true}
		var files []string
		for _, f := range c.files {
			files = append(files, filepath.Join(dir, f))
		}
		p := &ComposeProject{Name: "p", Dir: dir, Files: files}
		if own, err := cmp.ownFiles(); c.name != "none" && !strings.HasSuffix(c.name, "none named") && (err != nil || !sameFiles(own.files, files)) {
			t.Errorf("%s: read %+v %v", c.name, own, err)
		}
		plan := RebuildRecord{Override: OverrideFile}
		v, ok, err := cmp.envValue("COMPOSE_FILE")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			plan.ComposeFile = &v
			if plan.ComposeFileLine, err = cmp.envRaw("COMPOSE_FILE"); err != nil {
				t.Fatal(err)
			}
		}
		named, err := cmp.composeFiles(p, plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmp.setEnv("COMPOSE_FILE", &named, ""); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, ".env")); string(b) != c.want {
			t.Errorf("%s: wrote %q, want %q", c.name, b, c.want)
		}
		// What was written is read as the installation's, with migrate's.
		if got, err := cmp.files(p); err != nil || !slices.Equal(got, append(slices.Clone(files), filepath.Join(dir, OverrideFile))) {
			t.Errorf("%s: read back %v %v", c.name, got, err)
		}
		if own, err := cmp.ownFiles(); err != nil || !sameFiles(own.files, files) {
			t.Errorf("%s: read back %+v %v", c.name, own, err)
		}
		if err := cmp.setEnv("COMPOSE_FILE", plan.ComposeFile, plan.ComposeFileLine); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, ".env")); string(b) != c.env {
			t.Errorf("%s: put back %q, want %q", c.name, b, c.env)
		}
	}
	// What cannot be written so that Compose reads the same.
	dir := t.TempDir()
	bad := "it's.yml"
	if err := (&Compose{Directory: dir}).setEnv("COMPOSE_FILE", &bad, ""); err == nil {
		t.Error("a quote was written")
	}
	// A line appended after one put back without its line end.
	cmp := &Compose{Directory: installationDir(t, map[string]string{".env": "COMPOSE_FILE=x\nLATER=1\n"})}
	if err := cmp.setEnv("COMPOSE_FILE", nil, "COMPOSE_FILE=a.yml"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cmp.envPath()); string(b) != "COMPOSE_FILE=a.yml\nLATER=1\n" {
		t.Errorf("a line end: %q", b)
	}
}

// Every command of the source's that changes something is given only once
// the host's containers were read again, and none is when another
// directory's container is of the project by then (or the installation is
// of another project): in a run that began well, and on a --resume that
// finds no containers of its own.
func TestNothingChangesOnAnotherInstallation(t *testing.T) {
	plan := RebuildRecord{Override: OverrideFile, Volumes: []string{appID + "_postgres-data-x", appID + "_convex-data-x"}, Image: "x@sha256:y", Owner: "mig_x"}
	for name, do := range map[string]func(context.Context, *Compose) error{
		"barrier":       func(ctx context.Context, c *Compose) error { _, err := c.Barrier(ctx, time.Second); return err },
		"release":       func(ctx context.Context, c *Compose) error { return c.Release(ctx, "g") },
		"migrated out":  func(ctx context.Context, c *Compose) error { return c.MarkMigratedOut(ctx, "g") },
		"export":        func(ctx context.Context, c *Compose) error { _, err := c.Export(ctx, []byte("k"), false); return err },
		"backup":        func(ctx context.Context, c *Compose) error { _, err := c.Backup(ctx); return err },
		"stop ingress":  func(ctx context.Context, c *Compose) error { return c.StopIngress(ctx, Public) },
		"start ingress": func(ctx context.Context, c *Compose) error { return c.StartIngress(ctx, Public, false) },
		"stop tailnet":  func(ctx context.Context, c *Compose) error { return c.StopTailnet(ctx) },
		"start tailnet": func(ctx context.Context, c *Compose) error { return c.StartTailnet(ctx) },
		"rebuild":       func(ctx context.Context, c *Compose) error { return c.Rebuild(ctx, plan) },
		"import":        func(ctx context.Context, c *Compose) error { _, err := c.ImportReverse(ctx, os.DevNull); return err },
		"convex":        func(ctx context.Context, c *Compose) error { return c.ResetConvex(ctx) },
		"serve":         func(ctx context.Context, c *Compose) error { return c.StartServing(ctx, Coolify) },
		"stop serving":  func(ctx context.Context, c *Compose) error { return c.StopServing(ctx, Coolify) },
		"undo":          func(ctx context.Context, c *Compose) error { return c.UndoRebuild(ctx, plan) },
		"check rebuilt": func(ctx context.Context, c *Compose) error { return c.CheckRebuilt(ctx, plan, true) },
		"check data":    func(ctx context.Context, c *Compose) error { return c.CheckData(ctx, Coolify, &plan, nil, Removals{}) },
		"check the data": func(ctx context.Context, c *Compose) error {
			return c.CheckData(ctx, Public, nil, make([]VolumeRecord, 2), Removals{})
		},
		"mounted":      func(ctx context.Context, c *Compose) error { _, _, err := c.MountedVolumes(ctx); return err },
		"make volumes": func(ctx context.Context, c *Compose) error { _, err := c.MakeVolumes(ctx, plan); return err },
		"route": func(ctx context.Context, c *Compose) error {
			_, _, err := c.RouteFile(ctx, "https://vault.example.test")
			return err
		},
		"remove old": func(ctx context.Context, c *Compose) error {
			return c.RemoveOld(ctx, Public, make([]VolumeRecord, 2), nil, Removals{})
		},
		"remove retained": func(ctx context.Context, c *Compose) error { return c.RemoveRetained(ctx, plan, Removals{}) },
		"stop started":    func(ctx context.Context, c *Compose) error { return c.StopStarted(ctx, []string{"postgres"}) },
		"discover":        func(ctx context.Context, c *Compose) error { _, err := c.Discover(ctx); return err },
	} {
		dir := coolifyDir(t)
		file := filepath.Join(dir, "docker-compose.coolify-tailscale.yml")
		if err := os.Mkdir(filepath.Join(dir, "backups"), 0o700); err != nil {
			t.Fatal(err)
		}
		own := ctr(appID, "varlatchd", file, dir, "False")
		kept := &ComposeProject{Name: appID, Dir: dir, Files: []string{file}}
		for what, c := range map[string]struct {
			now  []composeContainer
			want string
		}{
			"another directory's container too": {[]composeContainer{own, ctr(appID, "postgres", "/srv/live/docker-compose.yml", "/srv/live", "False")}, "made from /srv/live"},
			"another directory's only":          {[]composeContainer{ctr(appID, "postgres", "/srv/live/docker-compose.yml", "/srv/live", "False")}, "made from /srv/live"},
			"another project here":              {[]composeContainer{ctr("varlatch", "varlatchd", file, dir, "False")}, "now of varlatch"},
		} {
			host := &labelled{containers: []composeContainer{own}, volumes: map[string]VolumeRecord{}}
			run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config": {Answer: []byte(stockConfig)}, "docker compose ps ": {}}}
			cmp := &Compose{Directory: dir, Run: run, BEKFile: "/b", Destination: "d"}
			cmp.KeepProject(kept, false)
			if err := cmp.CheckProject(t.Context()); err != nil {
				t.Fatal(err)
			}
			host.containers = c.now
			err := do(t.Context(), cmp)
			var changed *ProjectChangedError
			if err == nil || !errors.As(err, &changed) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s, %s: %v", name, what, err)
			}
			for _, r := range run.ran {
				if !strings.HasPrefix(r, "docker compose config") && !strings.HasPrefix(r, "docker compose ps ") {
					t.Errorf("%s, %s: ran %q", name, what, r)
				}
			}
			if len(host.removed) > 0 {
				t.Errorf("%s, %s: removed %v", name, what, host.removed)
			}
			if b, _ := os.ReadFile(cmp.envPath()); strings.Contains(string(b), "COMPOSE_FILE") {
				t.Errorf("%s, %s: .env was written", name, what)
			}
			if isFile(filepath.Join(dir, OverrideFile)) {
				t.Errorf("%s, %s: %s was written", name, what, OverrideFile)
			}
		}
	}
}

// retainedPlan is a rebuilt Coolify installation: its plan, host and
// Compose.
func retainedPlan(t *testing.T) (*Compose, *labelled, RebuildRecord) {
	t.Helper()
	dir := coolifyDir(t)
	file := filepath.Join(dir, "docker-compose.coolify-tailscale.yml")
	plan := RebuildRecord{Override: OverrideFile, Image: "x@sha256:y", Owner: "mig_x", Volumes: []string{appID + "_postgres-data-abcdefgh", appID + "_convex-data-abcdefgh"},
		Keys: []string{appID + "_postgres-data", appID + "_convex-data", appID + "_varlatch-state"}}
	host := &labelled{volumes: map[string]VolumeRecord{}, users: map[string]string{}}
	for i, n := range []string{"postgres-data", "convex-data"} {
		v := VolumeRecord{Name: appID + "_" + n, CreatedAt: "2026-01-0" + string(rune('1'+i)) + "T00:00:00Z", Project: appID}
		plan.Retained = append(plan.Retained, v)
		host.volumes[v.Name] = v
		plan.Made = append(plan.Made, VolumeRecord{Name: plan.Volumes[i], CreatedAt: "2026-11-01T00:00:00Z", Project: appID, Owner: "mig_x"})
		host.volumes[plan.Volumes[i]] = plan.Made[i]
		host.containers = append(host.containers, composeContainer{project: appID, service: dataMounts[i].service, dir: dir, files: file + "," + filepath.Join(dir, OverrideFile),
			mounts: []containerMount{{Type: "volume", Name: plan.Volumes[i], Destination: dataMounts[i].target}}})
	}
	config := `{"name":"` + appID + `","services":{"postgres":{"volumes":["` + appID + `_postgres-data:/var/lib/postgresql/data"]},"convex-backend":{"volumes":["` + appID + `_convex-data:/convex/data"]},` +
		`"varlatchd":{"volumes":["` + appID + `_varlatch-state:/var/lib/varlatch"]}},"volumes":{"` + appID + `_postgres-data":{"name":"` + plan.Volumes[0] + `"},"` + appID + `_convex-data":{"name":"` + plan.Volumes[1] + `"}}}`
	c := &Compose{Directory: dir, Run: &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(config)}}}}
	c.KeepProject(&ComposeProject{Name: appID, Dir: dir, Files: []string{file}}, true)
	if err := os.WriteFile(filepath.Join(dir, OverrideFile), []byte(override(plan)), 0o600); err != nil {
		t.Fatal(err)
	}
	v := "docker-compose.coolify-tailscale.yml:" + OverrideFile
	if err := c.setEnv("COMPOSE_FILE", &v, ""); err != nil {
		t.Fatal(err)
	}
	return c, host, plan
}

// After a reverse, --finish --delete-old-data removes the two volumes the
// journal recorded when the reverse began, and only while the installation
// runs on the fresh ones and each retained one is the one recorded, the
// project's, and mounted by nothing. Both CheckData (before the archive)
// and RemoveRetained hold them to it, in every shape.
func TestTheRetainedVolumesAreTheJournals(t *testing.T) {
	const pg, convex = appID + "_postgres-data", appID + "_convex-data"
	for _, c := range []struct {
		name    string
		change  func(h *labelled, p *RebuildRecord)
		log     Removals
		refused string
		removed []string
	}{
		{name: "as recorded", removed: []string{pg, convex}},
		{name: "one removed by an earlier run", log: Removals{Done: []string{pg}}, change: func(h *labelled, _ *RebuildRecord) { delete(h.volumes, pg) }, removed: []string{convex}},
		{name: "one begun, and gone", log: Removals{Removing: []string{pg}}, change: func(h *labelled, _ *RebuildRecord) { delete(h.volumes, pg) }, removed: []string{convex}},
		{name: "one begun, and there", log: Removals{Removing: []string{pg}}, removed: []string{pg, convex}},
		{name: "as recorded, in summer time", change: func(_ *labelled, p *RebuildRecord) { p.Retained[0].CreatedAt = "2026-01-01T02:00:00+02:00" }, removed: []string{pg, convex}},
		{name: "one gone", change: func(h *labelled, _ *RebuildRecord) { delete(h.volumes, convex) }, refused: "are not there"},
		{name: "one made since", change: func(h *labelled, _ *RebuildRecord) {
			h.volumes[convex] = VolumeRecord{Name: convex, CreatedAt: "2026-11-09T00:00:00Z", Project: appID}
		}, refused: "is not the one the journal records (it was made"},
		{name: "one at another place", change: func(h *labelled, _ *RebuildRecord) {
			v := h.volumes[convex]
			v.Mountpoint = "/elsewhere"
			h.volumes[convex] = v
		}, refused: "it is at /elsewhere"},
		{name: "a fresh one made since", change: func(h *labelled, p *RebuildRecord) {
			v := h.volumes[p.Volumes[1]]
			v.CreatedAt = "2026-11-09T00:00:00Z"
			h.volumes[p.Volumes[1]] = v
		}, refused: "is not the fresh one the reverse made"},
		{name: "a fresh one of another migration", change: func(h *labelled, p *RebuildRecord) {
			v := h.volumes[p.Volumes[0]]
			v.Owner = "mig_y"
			h.volumes[p.Volumes[0]] = v
		}, refused: "is not the fresh one the reverse made"},
		{name: "the fresh ones not recorded", change: func(_ *labelled, p *RebuildRecord) { p.Made = nil }, refused: "does not record the fresh volumes"},
		{name: "one not there when the reverse began", change: func(_ *labelled, p *RebuildRecord) { p.Retained[1].CreatedAt, p.Retained[1].Project = "", "" }, refused: "the journal's was not there"},
		{name: "another project's", change: func(h *labelled, _ *RebuildRecord) {
			v := h.volumes[convex]
			v.Project = "other"
			h.volumes[convex] = v
		}, refused: "its labels (project other"},
		{name: "unlabelled when the reverse began", change: func(_ *labelled, p *RebuildRecord) { p.Retained[1].Project = "" }, refused: "its labels"},
		{name: "unlabelled", change: func(h *labelled, p *RebuildRecord) {
			p.Retained[1].Project = ""
			h.volumes[convex] = p.Retained[1]
		}, refused: "labelled of the Compose project none"},
		{name: "mounted", change: func(h *labelled, _ *RebuildRecord) { h.users[convex] = "a-guard\n" }, refused: "is used by a-guard"},
		{name: "a fresh one", change: func(_ *labelled, p *RebuildRecord) { p.Retained[0].Name = p.Volumes[0] }, refused: "as a retained volume and as a fresh one"},
		{name: "not recorded", change: func(_ *labelled, p *RebuildRecord) { p.Retained = nil }, refused: "does not record which volumes"},
		{name: "Postgres on the retained one", change: func(h *labelled, _ *RebuildRecord) { h.containers[0].mounts[0].Name = pg }, refused: "postgres runs on " + pg},
		{name: "Convex stopped", change: func(h *labelled, _ *RebuildRecord) { h.containers[1].status = "exited" }, refused: "convex-backend does not run"},
	} {
		for _, kind := range []Ingress{Coolify, Public} {
			cmp, host, plan := retainedPlan(t)
			if c.change != nil {
				c.change(host, &plan)
			}
			before := maps.Clone(host.volumes)
			log := c.log
			log.Intend = func(string) error { return nil }
			log.Removed = func(string) error { return nil }
			checked := cmp.CheckData(t.Context(), kind, &plan, nil, log)
			if len(host.removed) != 0 || !maps.Equal(before, host.volumes) {
				t.Fatalf("%s: the check removed %v", c.name, host.removed)
			}
			err := cmp.RemoveRetained(t.Context(), plan, log)
			for what, err := range map[string]error{"check": checked, "removal": err} {
				if (err == nil) != (c.refused == "") || err != nil && !strings.Contains(err.Error(), c.refused) {
					t.Errorf("%s, %s: %v", c.name, what, err)
				}
			}
			if !slices.Equal(host.removed, c.removed) {
				t.Errorf("%s: removed %v, want %v", c.name, host.removed, c.removed)
			}
		}
	}
	// Made again, or removed, once its removal was journalled begun: not
	// this one, refused right before its removal.
	for name, change := range map[string]func(h *labelled){
		"made again": func(h *labelled) {
			v := h.volumes[convex]
			v.CreatedAt = "2026-11-09T00:00:00Z"
			h.volumes[convex] = v
		},
		"gone":    func(h *labelled) { delete(h.volumes, convex) },
		"mounted": func(h *labelled) { h.users[convex] = "late" },
	} {
		cmp, host, plan := retainedPlan(t)
		log := Removals{Removed: func(string) error { return nil }, Intend: func(v string) error {
			if v == convex {
				change(host)
			}
			return nil
		}}
		if err := cmp.RemoveRetained(t.Context(), plan, log); err == nil || !slices.Equal(host.removed, []string{pg}) {
			t.Errorf("%s: %v, removed %v", name, err, host.removed)
		}
	}
	// Taken into use between the two removals.
	cmp, host, plan := retainedPlan(t)
	log := Removals{Intend: func(string) error { return nil }, Removed: func(string) error { host.users[convex] = "late"; return nil }}
	if err := cmp.RemoveRetained(t.Context(), plan, log); err == nil || !strings.Contains(err.Error(), "used by late") || !slices.Equal(host.removed, []string{pg}) {
		t.Errorf("mounted meanwhile: %v, removed %v", err, host.removed)
	}
}

// The identities recorded when a reverse begins: what the containers
// mount, as the Compose files give it.
func TestTheReverseRecordsTheRetainedVolumes(t *testing.T) {
	const pg, convex = appID + "_postgres-data", appID + "_convex-data"
	j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}
	b, err := os.ReadFile(filepath.Join("testdata", "compose-config", "coolify-tailscale.json"))
	if err != nil {
		t.Fatal(err)
	}
	cmp, host, _ := retainedPlan(t)
	cmp.Run.(*scripted).answers = map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: b}}
	if err := cmp.setEnv("COMPOSE_FILE", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cmp.Directory, OverrideFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := cmp.RebuildPlan(t.Context(), j); err == nil || !strings.Contains(err.Error(), "which volume is the installation's is not known") {
		t.Errorf("containers on other volumes than the files': %v", err)
	}
	host.containers[0].mounts[0].Name, host.containers[1].mounts[0].Name = pg, convex
	plan, err := cmp.RebuildPlan(t.Context(), j)
	if want := []VolumeRecord{host.volumes[pg], host.volumes[convex]}; err != nil || !slices.Equal(plan.Retained, want) || plan.OverrideWas != "" || plan.ComposeFileLine != "" {
		t.Errorf("%+v %v, want %v", plan, err, want)
	}
	// Not there: the reverse goes on; --finish then refuses.
	delete(host.volumes, convex)
	if plan, err := cmp.RebuildPlan(t.Context(), j); err != nil || plan.Retained[1] != (VolumeRecord{Name: convex}) {
		t.Errorf("one not there: %+v %v", plan.Retained, err)
	}
	// A second reverse's: the first's file and line, put back by its undo.
	if err := os.WriteFile(filepath.Join(cmp.Directory, OverrideFile), []byte("# the first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cmp.envPath(), []byte("COMPOSE_FILE=\"docker-compose.coolify-tailscale.yml:"+OverrideFile+"\" # x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err = cmp.RebuildPlan(t.Context(), j)
	if err != nil || plan.OverrideWas != OverrideFile+".before-"+plan.Volumes[0][len(plan.Volumes[0])-8:] || strings.HasSuffix(plan.Volumes[0], "abcdefgh") || !strings.HasSuffix(plan.ComposeFileLine, "\" # x\n") {
		t.Fatalf("a second reverse: %+v %v", plan, err)
	}
	run := cmp.Run.(*scripted)
	if plan.Made, err = cmp.MakeVolumes(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	run.answers = map[string]Ran{"docker compose stop ": {}, "docker compose config ": {Code: 1}, "docker compose up -d postgres convex-backend": {Code: 1}}
	for _, rebuild := range []bool{false, true} {
		if rebuild {
			_ = cmp.Rebuild(t.Context(), plan)
			if b, _ := os.ReadFile(filepath.Join(cmp.Directory, OverrideFile)); string(b) != override(plan) {
				t.Errorf("rebuilt: %q", b)
			}
		}
		_ = cmp.UndoRebuild(t.Context(), plan)
		b, _ = os.ReadFile(filepath.Join(cmp.Directory, OverrideFile))
		if env, _ := os.ReadFile(cmp.envPath()); string(b) != "# the first\n" || string(env) != plan.ComposeFileLine || isFile(filepath.Join(cmp.Directory, plan.OverrideWas)) {
			t.Errorf("rebuilt %v, put back: %q, %q", rebuild, b, env)
		}
	}
}

// rolledWorld is a migration whose reverse is at phase, in Coolify's shape
// unless kind says another, Go running.
func rolledWorld(t *testing.T, phase Phase, kind Ingress) (*world, *reverseFake, *Journal) {
	t.Helper()
	w := newWorld(t)
	w.eng.Options.Ingress = kind
	j := &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: phase, Source: w.src.info, Ingress: kind, Transfer: &TransferRecord{Origin: "https://vault.example.test"},
		Rollback: &RollbackRecord{Rebuild: &RebuildRecord{Override: OverrideFile, Volumes: []string{"p_postgres-data-abcdefgh", "p_convex-data-abcdefgh"}}, Export: &CopyRecord{InstallationID: "inst_fake"}},
		History:  []Step{{Phase: Switched, At: w.eng.now().Format(time.RFC3339Nano)}}}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	head := phase
	if phase == RolledBack {
		head = RollbackTransfer
	}
	w.tgt.journal, w.tgt.database, w.tgt.running = &JournalHead{ID: j.ID, Phase: head}, true, true
	src := &reverseFake{fakeSource: w.src}
	w.eng.Source, w.eng.Target = src, &reverseTargetFake{fakeTarget: w.tgt}
	return w, src, j
}

// The address never moves to, Go never stops for, and nothing is recorded
// rolled back on, an installation that is not on its fresh volumes, though
// it answers as the same installation and release: refused on each
// --resume, Go left running, until it is.
func TestTheReverseTransferChecksTheVolumes(t *testing.T) {
	retained := errors.New("postgres runs on p_postgres-data, not on the fresh volume p_postgres-data-abcdefgh the journal names; to run it on them again: 1. set COMPOSE_FILE=")
	both := "check p_postgres-data-abcdefgh and Convex"
	t.Run("before it begins: undone", func(t *testing.T) {
		w, src, j := rolledWorld(t, RollbackChecked, Coolify)
		src.checkErr = retained
		if err := w.eng.reverseTransfer(t.Context(), j); !errors.Is(err, retained) || !slices.Equal(src.did, []string{both, "undo p_postgres-data-abcdefgh"}) || !w.tgt.running || j.Phase != Open {
			t.Errorf("%v: %v, phase %s", err, src.did, j.Phase)
		}
	})
	for _, kind := range []Ingress{Coolify, Public} {
		t.Run("pending, "+string(kind), func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackTransfer, kind)
			src.checkErr = retained
			for range 2 {
				src.did, w.tgt.calls = nil, nil
				_, err := w.eng.Resume(t.Context())
				if !errors.Is(err, retained) || !strings.Contains(err.Error(), "Go was not stopped") || !strings.Contains(err.Error(), "varlatch migrate --resume") ||
					!slices.Equal(src.did, []string{both}) || slices.Contains(w.tgt.calls, "stop") || !w.tgt.running {
					t.Fatalf("%v: %v, target %v", err, src.did, w.tgt.calls)
				}
				after, _ := readJournal(w.src.dir)
				if after.Phase != RollbackTransfer || after.Rollback.Undoing || after.Rollback.GoStopped || after.ID != j.ID {
					t.Fatalf("the journal: %+v", after.Rollback)
				}
			}
			// On them again: it goes on.
			src.checkErr, src.did = nil, nil
			_, err := w.eng.Resume(t.Context())
			after, _ := readJournal(w.src.dir)
			if err != nil || after.Phase != RolledBack || w.tgt.running {
				t.Fatalf("%v: %v, phase %s, Go running %v", err, src.did, after.Phase, w.tgt.running)
			}
		})
	}
	// Deployed again while the address moves: it answers, and Go stays.
	for n, stopped := range map[int]bool{1: false, 2: true} {
		w, src, _ := rolledWorld(t, RollbackTransfer, Coolify)
		src.check = func() error {
			if c := len(slices.DeleteFunc(slices.Clone(src.did), func(d string) bool { return d != both })); c <= n {
				return nil
			}
			return retained
		}
		_, err := w.eng.Resume(t.Context())
		after, _ := readJournal(w.src.dir)
		if !errors.Is(err, retained) || after.Phase != RollbackTransfer || w.tgt.running == stopped || w.prober.probes == 0 || slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
			t.Errorf("after %d checks: %v: %v, phase %s, running %v", n, err, src.did, after.Phase, w.tgt.running)
		}
	}
	// Recorded in the source's journal, not yet in Go's.
	w, src, _ := rolledWorld(t, RolledBack, Coolify)
	src.checkErr = retained
	if _, err := w.eng.Resume(t.Context()); !errors.Is(err, retained) || !w.tgt.running || w.tgt.journal.Phase != RollbackTransfer || strings.Contains(err.Error(), "--abort") {
		t.Errorf("rolled back: %v, running %v, Go's journal %s", err, w.tgt.running, w.tgt.journal.Phase)
	}
	src.checkErr = nil
	if _, err := w.eng.Resume(t.Context()); err != nil || w.tgt.running || w.tgt.journal.Phase != RolledBack {
		t.Errorf("rolled back, on them: %v", err)
	}
}

// finishFake is a rolled back TypeScript side for --finish.
type finishFake struct {
	*reverseFake
	removeErr error
}

func (f *finishFake) MountedVolumes(context.Context) (data, others []VolumeRecord, err error) {
	return nil, nil, nil
}
func (f *finishFake) CheckData(context.Context, Ingress, *RebuildRecord, []VolumeRecord, Removals) error {
	return nil
}
func (f *finishFake) ServeForArchive(context.Context) ([]string, error) { return nil, nil }
func (f *finishFake) StopStarted(context.Context, []string) error       { return nil }
func (f *finishFake) RemoveOld(context.Context, Ingress, []VolumeRecord, []VolumeRecord, Removals) error {
	return nil
}
func (f *finishFake) RemoveRetained(context.Context, RebuildRecord, Removals) error {
	f.do("remove retained")
	return f.removeErr
}

// Go's copy is discarded last: while the pre-migration volumes are not
// removed (the installation not on its fresh ones, or their identities not
// the recorded ones), it is there, on each --resume.
func TestFinishDiscardsGosCopyLast(t *testing.T) {
	w, src, j := rolledWorld(t, Finished, Coolify)
	wrong := errors.New("postgres runs on p_postgres-data")
	fs := &finishFake{reverseFake: src, removeErr: wrong}
	w.eng.Source = fs
	j.Finish = &FinishRecord{After: RolledBack, DeleteOldData: true, ArchiveID: "a", VerifiedAt: "x"}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	w.tgt.running, w.tgt.journal = false, &JournalHead{ID: j.ID, Phase: RolledBack}
	for range 2 {
		if _, err := w.eng.Resume(t.Context()); !errors.Is(err, wrong) || !strings.Contains(err.Error(), "Go's copy is kept") || !w.tgt.database {
			t.Fatalf("%v, Go's copy there %v: %v", err, w.tgt.database, w.tgt.calls)
		}
		after, _ := readJournal(w.src.dir)
		if after.Finish.DoneAt != "" || len(after.Finish.Removed) != 0 {
			t.Fatalf("%+v", after.Finish)
		}
	}
	fs.removeErr = nil
	if _, err := w.eng.Resume(t.Context()); err != nil || w.tgt.database {
		t.Fatalf("%v, Go's copy there %v", err, w.tgt.database)
	}
	after, _ := readJournal(w.src.dir)
	if after.Finish.DoneAt == "" || len(after.Finish.Removed) != 1 {
		t.Fatalf("%+v", after.Finish)
	}
}

// A migration stopped or interrupted before its barrier goes on only from
// the installation it began with; --abort ends it without asking the one
// that replaced it, and the next is a new migration of what is there.
func TestBeforeTheBarrierTheProjectIsKept(t *testing.T) {
	project := &ComposeProject{Name: appID, Dir: "/x", Files: []string{"/x/docker-compose.yml"}}
	changed := &ProjectChangedError{"the installation was started another way since"}
	for _, stopped := range []bool{false, true} {
		w := newWorld(t)
		info := w.src.info
		info.Project = project
		j := &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: Preflight, Stopped: stopped, Source: info, Ingress: Public, Transfer: &TransferRecord{}, History: []Step{}}
		j.Target.Config, j.Target.DataDir = "/etc/varlatch/varlatchd.conf", w.tgt.dataDir
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		w.tgt.journal = &JournalHead{ID: j.ID, Phase: Preflight}
		w.src.fail["discover"], w.src.fail["gate"] = changed, changed
		run := w.eng.Resume
		if stopped {
			run = func(ctx context.Context) (*Journal, error) { return w.eng.Run(ctx, true) }
		}
		if _, err := run(t.Context()); !errors.Is(err, changed) || w.src.kept == nil || w.src.kept.Name != appID || !slices.Equal(w.src.calls, []string{"discover"}) {
			t.Fatalf("stopped %v: %v, kept %v, %v", stopped, err, w.src.kept, w.src.calls)
		}
		if _, err := w.eng.Abort(t.Context()); err != nil || slices.ContainsFunc(w.src.calls, func(c string) bool { return strings.HasPrefix(c, "release") || c == "barrier" }) {
			t.Fatalf("abort: %v, %v", err, w.src.calls)
		}
		after, _ := readJournal(w.src.dir)
		if after.Phase != Released {
			t.Fatalf("after the abort: %s", after.Phase)
		}
		// A new migration takes the installation there is.
		w.src.fail = map[string]error{}
		next, err := w.eng.Run(t.Context(), true)
		if err != nil || next.ID == j.ID || w.src.kept != nil {
			t.Fatalf("the next: %v %v, kept %v", next, err, w.src.kept)
		}
	}
	// Past it, an abort that cannot read the source undoes nothing.
	w := newWorld(t)
	j := &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: Barrier, Barrier: &BarrierRecord{}, Source: w.src.info, Ingress: Public, Transfer: &TransferRecord{}, History: []Step{}}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	w.tgt.journal = &JournalHead{ID: j.ID, Phase: Barrier}
	w.src.fail["gate"] = changed
	if _, err := w.eng.Abort(t.Context()); err == nil {
		t.Error("an abort after the barrier that could not read the source's gate")
	}
	if after, _ := readJournal(w.src.dir); after.Phase != Barrier {
		t.Errorf("phase %s", after.Phase)
	}
}

// The fresh volumes a reverse makes are new, labelled as the migration's,
// and the only ones its undo removes: never one that had the name before,
// or got it since, though nothing uses it; also when the run was killed
// before it journalled them.
func TestTheUndoRemovesOnlyVolumesOfTheMigration(t *testing.T) {
	j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}
	const fresh, freshConvex = "varlatch_postgres-data-abcdefgh", "varlatch_convex-data-abcdefgh"
	newPlan := func(t *testing.T, have ...string) (*Compose, *labelled, RebuildRecord) {
		host := &labelled{volumes: map[string]VolumeRecord{}}
		for _, n := range have {
			host.volumes[n] = VolumeRecord{Name: n, CreatedAt: "2026-01-01T00:00:00Z", Project: "varlatch"}
		}
		cmp := stockCompose(t, &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose stop ": {}, "docker compose up ": {}, "docker compose ps ": {},
			"docker compose run --rm -T --no-deps varlatchd admin migration status": {Answer: []byte(`{"daemon":false,"gate":{"kind":"migrated-out","id":"gate-1"}}`)}}})
		plan, err := cmp.RebuildPlan(t.Context(), j)
		if err != nil {
			t.Fatal(err)
		}
		return cmp, host, plan
	}
	// A name that is taken is never planned.
	for _, taken := range []string{fresh, freshConvex} {
		_, _, plan := newPlan(t, taken)
		if slices.Contains(plan.Volumes, taken) || plan.Volumes[0][len("varlatch_postgres-data-"):] != plan.Volumes[1][len("varlatch_convex-data-"):] || plan.Owner != j.ID {
			t.Errorf("%s taken: %v", taken, plan.Volumes)
		}
	}
	for _, c := range []struct {
		name    string
		do      func(t *testing.T, c *Compose, h *labelled, p *RebuildRecord)
		removed []string
	}{
		{"made and journalled", func(t *testing.T, c *Compose, h *labelled, p *RebuildRecord) {
			var err error
			if p.Made, err = c.MakeVolumes(t.Context(), *p); err != nil || !slices.Equal(h.made, p.Volumes) {
				t.Fatalf("%v %v", h.made, err)
			}
		}, []string{fresh, freshConvex}},
		{"killed before they are made", func(*testing.T, *Compose, *labelled, *RebuildRecord) {}, nil},
		{"killed before they are made, the names taken since", func(_ *testing.T, _ *Compose, h *labelled, _ *RebuildRecord) {
			h.volumes[fresh] = VolumeRecord{Name: fresh, CreatedAt: "2026-11-01T00:00:00Z", Project: "varlatch"}
			h.volumes[freshConvex] = VolumeRecord{Name: freshConvex, CreatedAt: "2026-11-01T00:00:00Z"}
		}, nil},
		{"killed before they are made, the names taken by another migration", func(_ *testing.T, _ *Compose, h *labelled, _ *RebuildRecord) {
			h.volumes[fresh] = VolumeRecord{Name: fresh, CreatedAt: "2026-11-01T00:00:00Z", Project: "varlatch", Owner: "mig_other"}
		}, nil},
		{"killed before they are journalled", func(t *testing.T, c *Compose, _ *labelled, p *RebuildRecord) {
			if _, err := c.MakeVolumes(t.Context(), *p); err != nil {
				t.Fatal(err)
			}
		}, []string{fresh, freshConvex}},
		{"one made again since", func(t *testing.T, c *Compose, h *labelled, p *RebuildRecord) {
			var err error
			if p.Made, err = c.MakeVolumes(t.Context(), *p); err != nil {
				t.Fatal(err)
			}
			v := h.volumes[fresh]
			v.CreatedAt = "2026-11-10T00:00:00Z"
			h.volumes[fresh] = v
		}, []string{freshConvex}},
		{"an earlier version's journal, the names taken", func(_ *testing.T, _ *Compose, h *labelled, p *RebuildRecord) {
			h.volumes[fresh] = VolumeRecord{Name: fresh, CreatedAt: "2026-11-01T00:00:00Z", Project: "varlatch"}
			p.Owner = ""
		}, nil},
		{"an earlier version's journal", func(t *testing.T, c *Compose, _ *labelled, p *RebuildRecord) {
			if _, err := c.MakeVolumes(t.Context(), *p); err != nil {
				t.Fatal(err)
			}
			p.Owner = ""
		}, nil},
	} {
		cmp, host, plan := newPlan(t)
		c.do(t, cmp, host, &plan)
		if err := cmp.UndoRebuild(t.Context(), plan); err != nil || !slices.Equal(host.removed, c.removed) {
			t.Errorf("%s: %v, removed %v, want %v", c.name, err, host.removed, c.removed)
		}
	}
	// One that got the name since, or is in use, is not taken for a fresh
	// one; the rebuild does not start on it.
	cmp, host, plan := newPlan(t)
	host.volumes[fresh] = VolumeRecord{Name: fresh, CreatedAt: "2026-11-01T00:00:00Z", Project: "varlatch"}
	if _, err := cmp.MakeVolumes(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "is not this migration's") {
		t.Errorf("taken since: %v", err)
	}
	cmp, host, plan = newPlan(t)
	host.users = map[string]string{fresh: "a-container"}
	if _, err := cmp.MakeVolumes(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "used by a-container") {
		t.Errorf("in use: %v", err)
	}
	cmp, host, plan = newPlan(t)
	var err error
	if plan.Made, err = cmp.MakeVolumes(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	v := host.volumes[freshConvex]
	v.Owner = ""
	host.volumes[freshConvex] = v
	run := cmp.Run.(*scripted)
	run.ran = nil
	if err := cmp.Rebuild(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "is not the fresh one") || slices.ContainsFunc(run.ran, func(r string) bool { return !strings.HasPrefix(r, "docker compose config") }) {
		t.Errorf("another since: %v, ran %v", err, run.ran)
	}
	if isFile(filepath.Join(cmp.Directory, OverrideFile)) {
		t.Error("the override was written")
	}
}

// A forward --finish removes only the volumes the installation's
// containers were on, as its Compose files named them, before they went
// down: each the very one. A name changed in the files, a container on
// another, a volume made again, another project's: refused, before the
// archive.
func TestAForwardFinishRemovesWhatItArchived(t *testing.T) {
	const pg, convex, other = "varlatch_postgres-data", "varlatch_convex-data", "varlatch_unrelated"
	config := func(name string) Ran {
		return Ran{Answer: []byte(strings.TrimSuffix(stockConfig, "}") + `,"volumes":{"postgres-data":{"name":"` + name + `"}}}`)}
	}
	type world struct {
		c    *Compose
		h    *labelled
		run  *scripted
		down func()
	}
	build := func(t *testing.T) *world {
		host := &labelled{volumes: map[string]VolumeRecord{}, users: map[string]string{}}
		for _, n := range []string{"postgres-data", "convex-data", "varlatch-state", "tailscale-state", "caddy-data", "unrelated"} {
			host.volumes["varlatch_"+n] = VolumeRecord{Name: "varlatch_" + n, CreatedAt: "2026-01-01T00:00:00Z", Mountpoint: "/v/" + n, Project: "varlatch", Key: n}
		}
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose down": {}}}
		c := stockCompose(t, run)
		f := filepath.Join(c.Directory, "docker-compose.yml")
		add := func(svc, vol, target string) {
			l := ctr("varlatch", svc, f, c.Directory, "False")
			l.mounts = []containerMount{{Type: "volume", Name: vol, Destination: target}}
			host.containers = append(host.containers, l)
		}
		add("postgres", pg, postgresTarget)
		add("convex-backend", convex, convexTarget)
		add("varlatchd", "varlatch_varlatch-state", "/var/lib/varlatch")
		add("tailscale", "varlatch_tailscale-state", "/var/lib/tailscale")
		return &world{c: c, h: host, run: run, down: func() { host.containers = nil }}
	}
	log := func(done ...string) Removals {
		return Removals{Data: true, Done: done, Intend: func(string) error { return nil }, Removed: func(string) error { return nil }}
	}
	// Recorded, then removed: the data, and of the others what a container
	// mounted (Caddy's volume is the project's, but no container's).
	w := build(t)
	data, others, err := w.c.MountedVolumes(t.Context())
	if err != nil || len(data) != 2 || data[0] != w.h.volumes[pg] || data[1] != w.h.volumes[convex] || len(others) != 2 {
		t.Fatalf("%+v %+v %v", data, others, err)
	}
	w.down()
	if err := w.c.RemoveOld(t.Context(), Public, nil, others, log()); err != nil || !slices.Equal(w.h.removed, []string{"varlatch_tailscale-state"}) {
		t.Fatalf("without the data: %v, removed %v", err, w.h.removed)
	}
	if err := w.c.CheckData(t.Context(), Public, nil, data, log()); err != nil {
		t.Fatalf("later: %v", err)
	}
	if err := w.c.RemoveOld(t.Context(), Public, data, others, log("varlatch_tailscale-state")); err != nil ||
		!slices.Equal(w.h.removed, []string{"varlatch_tailscale-state", pg, convex, "varlatch_varlatch-state"}) {
		t.Fatalf("with it: %v, removed %v", err, w.h.removed)
	}
	for _, c := range []struct {
		name    string
		before  func(w *world) // before they are recorded
		after   func(w *world) // after
		refused string
	}{
		{name: "the files name another volume, Postgres is on the old one", before: func(w *world) { w.run.answers["docker compose config "] = config(other) }, refused: "is on " + pg + ", and its Compose files give it " + other},
		{name: "another project's volume", before: func(w *world) {
			v := w.h.volumes[pg]
			v.Project = "other"
			w.h.volumes[pg] = v
		}, refused: "labelled of the Compose project other"},
		{name: "an unlabelled volume", before: func(w *world) {
			v := w.h.volumes[pg]
			v.Project = ""
			w.h.volumes[pg] = v
		}, refused: "labelled of the Compose project none"},
		{name: "no containers to tell by", before: func(w *world) { w.down() }, refused: "has no postgres container"},
		{name: "the files name another volume since", after: func(w *world) { w.run.answers["docker compose config "] = config(other) }, refused: "give postgres the volume " + other},
		{name: "the files name another volume since, the containers gone", after: func(w *world) {
			w.down()
			w.run.answers["docker compose config "] = config(other)
		}, refused: "give postgres the volume " + other},
		{name: "Postgres started on another since", after: func(w *world) { w.h.containers[0].mounts[0].Name = other }, refused: "is on " + other},
		{name: "a volume made again since", after: func(w *world) {
			v := w.h.volumes[pg]
			v.CreatedAt = "2026-11-01T00:00:00Z"
			w.h.volumes[pg] = v
		}, refused: "is not the one the journal records"},
	} {
		w := build(t)
		if c.before != nil {
			c.before(w)
		}
		data, _, err := w.c.MountedVolumes(t.Context())
		if (err != nil) != (c.before != nil) {
			t.Errorf("%s: recorded: %v", c.name, err)
		}
		if err == nil {
			if c.after != nil {
				c.after(w)
			}
			err = w.c.CheckData(t.Context(), Public, nil, data, log())
		}
		if err == nil || !strings.Contains(err.Error(), c.refused) || len(w.h.removed) != 0 {
			t.Errorf("%s: %v, removed %v", c.name, err, w.h.removed)
		}
	}
	// Recorded before: what is removed is what was recorded, whatever the
	// files name now.
	w = build(t)
	if data, others, err = w.c.MountedVolumes(t.Context()); err != nil {
		t.Fatal(err)
	}
	w.down()
	w.run.answers["docker compose config "] = config(other)
	if err := w.c.RemoveOld(t.Context(), Public, data, others, log()); err != nil || slices.Contains(w.h.removed, other) || !slices.Contains(w.h.removed, pg) {
		t.Errorf("after the archive: %v, removed %v", err, w.h.removed)
	}
	if err := w.c.CheckData(t.Context(), Public, nil, nil, log()); err == nil || !strings.Contains(err.Error(), "does not record which volumes") {
		t.Errorf("nothing recorded: %v", err)
	}
}

// The order in a forward --finish: what the containers mount is recorded
// first, and checked before the archive and again once its services are
// up; a check that fails makes no archive, and takes nothing down.
type forwardFake struct {
	*finishFake
	checks, failAt int
	vols           []VolumeRecord
}

func (f *forwardFake) MountedVolumes(context.Context) (data, others []VolumeRecord, err error) {
	f.do("mounted")
	return f.vols, nil, nil
}
func (f *forwardFake) CheckData(_ context.Context, _ Ingress, _ *RebuildRecord, data []VolumeRecord, _ Removals) error {
	f.do("check " + data[0].Name)
	if f.checks++; f.checks == f.failAt {
		return errors.New("on another volume")
	}
	return nil
}
func (f *forwardFake) ServeForArchive(context.Context) ([]string, error) {
	f.do("serve")
	return []string{"postgres"}, nil
}
func (f *forwardFake) StopStarted(context.Context, []string) error { f.do("stop"); return nil }
func (f *forwardFake) RemoveOld(_ context.Context, _ Ingress, data, _ []VolumeRecord, _ Removals) error {
	f.do("remove " + data[0].Name)
	return nil
}

func TestAForwardFinishChecksBeforeItsArchive(t *testing.T) {
	for failAt, want := range map[int][]string{
		0: {"mounted", "check pg", "serve", "check pg", "remove pg"},
		1: {"mounted", "check pg"},
		2: {"mounted", "check pg", "serve", "check pg", "stop"},
	} {
		w, src, j := rolledWorld(t, Open, Public)
		j.Rollback = nil
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		fs := &forwardFake{finishFake: &finishFake{reverseFake: src}, failAt: failAt, vols: []VolumeRecord{{Name: "pg"}, {Name: "convex"}}}
		w.eng.Source = fs
		_, err := w.eng.Finish(t.Context(), true)
		if (err == nil) != (failAt == 0) || !slices.Equal(fs.did, want) || containsCall(w.src.calls, "backup") != (failAt == 0) {
			t.Errorf("fail at %d: %v: %v, %v", failAt, err, fs.did, w.src.calls)
		}
		after, _ := readJournal(w.src.dir)
		if len(after.Finish.Volumes) != 2 || (after.Phase == Finished) != (failAt == 0) {
			t.Errorf("fail at %d: phase %s, %+v", failAt, after.Phase, after.Finish)
		}
	}
}

// routeProber answers as the proxy would: route is where the name leads.
type routeProber struct {
	w     *world
	route func() string
	gates int
}

func (p *routeProber) Probe(context.Context, string) (string, string, error) {
	switch p.route() {
	case "go":
		return "inst_fake", "0.50.0", nil
	case "ts":
		return "", "", errors.New("GET /v1/meta answered 503")
	}
	return "", "", errors.New("GET /v1/meta answered 502")
}
func (p *routeProber) ProbeGate(context.Context, string) (string, error) {
	p.gates++
	switch p.route() {
	case "go":
		return "", nil
	case "ts":
		return "migrated-out", nil
	case "other":
		return "migration", nil
	}
	return "", errors.New("GET /readyz answered 502, not as a Varlatch server")
}

type routedFake struct{ *reverseFake }

func (routedFake) RouteFile(context.Context, string) (string, string, error) {
	return "/proxy/route.yaml", "http: the route\n", nil
}

// In Coolify's shape --rollback begins nothing until the name reaches the
// TypeScript installation through its dashboard by the operator's route:
// said, exit 75, the migration open, Go untouched.
func TestTheWayBackIsCheckedBeforeTheReverse(t *testing.T) {
	for _, c := range []struct {
		name    string
		file    bool // the route is in the proxy
		to      string
		said    string
		refused string
	}{
		{"no route", false, "ts", "the address answers as the installation inst_fake, release 0.50.0", ""},
		{"a route to the dashboard", true, "ts", "", ""},
		{"a route to something else", true, "nothing", "", "did not reach the TypeScript installation"},
		{"a route to another installation", true, "other", "in the state migration", ""},
		{"a route to a dashboard of another", true, "other dashboard", "", "it answers in the state migration, not migrated-out"},
	} {
		w, src, j := rolledWorld(t, Open, Coolify)
		w.eng.Options.TransferTimeout = 4 * time.Second
		src.importErr = errors.New("the reverse began")
		p := &routeProber{w: w}
		p.route = func() string {
			switch {
			case !c.file && w.tgt.running:
				return "go"
			case c.to != "other" && w.src.ingressDown:
				return "stopped"
			case c.to == "other dashboard":
				return "other"
			}
			return c.to
		}
		w.eng.Source, w.eng.Prober = routedFake{src}, p
		_, err := w.eng.Rollback(t.Context())
		after, _ := readJournal(w.src.dir)
		if c.file && c.to == "ts" {
			if !errors.Is(err, src.importErr) || !slices.Contains(src.did, "rebuild") || !w.src.ingressDown {
				t.Errorf("%s: %v, %v, the dashboard down %v after the undo", c.name, err, src.did, w.src.ingressDown)
			}
			if !strings.Contains(strings.Join(w.said, "\n"), "remove the route put in the proxy") {
				t.Errorf("%s: the undo said %v", c.name, w.said)
			}
			continue
		}
		said := strings.Join(w.said, "\n")
		if c.refused == "" && (!errors.Is(err, ErrAwaitingOperator) || !strings.Contains(said, c.said) || !strings.Contains(said, "/proxy/route.yaml") || !strings.Contains(said, "http: the route") ||
			!strings.Contains(said, "do not Deploy, Restart or Stop the TypeScript application")) {
			t.Errorf("%s: %v, %s", c.name, err, said)
		}
		if c.refused != "" && (err == nil || !strings.Contains(err.Error(), c.refused) || !strings.Contains(err.Error(), "nothing was done")) {
			t.Errorf("%s: %v", c.name, err)
		}
		if after.Phase != Open || after.ID != j.ID || len(src.did) != 0 || !w.tgt.running || !w.src.ingressDown || w.tgt.gate {
			t.Errorf("%s: phase %s, %v, Go running %v, the dashboard down %v", c.name, after.Phase, src.did, w.tgt.running, w.src.ingressDown)
		}
	}
}

// The proxy's file: the name's route to the dashboard's one container.
func TestRouteFile(t *testing.T) {
	dir := coolifyDir(t)
	file := filepath.Join(dir, "docker-compose.coolify-tailscale.yml")
	web := ctr(appID, dashboardService, file, dir, "False")
	web.name, web.status = "varlatch-web-"+appID+"-1", "exited"
	for _, c := range []struct {
		name, origin string
		containers   []composeContainer
		want         []string
		refused      string
	}{
		{"https", "https://vault.example.test", []composeContainer{web, ctr(appID, "postgres", file, dir, "False")},
			[]string{"rule: \"Host(`vault.example.test`)\"", "entryPoints: [https]", "priority: 100000", "certResolver: letsencrypt", "url: \"http://varlatch-web-" + appID + "-1:80\""}, ""},
		{"http", "http://127.0.0.1:1", []composeContainer{web}, []string{"Host(`127.0.0.1`)", "entryPoints: [http]"}, ""},
		{"none", "https://vault.example.test", []composeContainer{ctr(appID, "postgres", file, dir, "False")}, nil, "0 varlatch-web containers"},
		{"two", "https://vault.example.test", []composeContainer{web, web}, nil, "2 varlatch-web containers"},
		{"no host", "x", []composeContainer{web}, nil, "has no host"},
	} {
		path, text, err := (&Compose{Directory: dir, Run: &scripted{t: t, host: &labelled{containers: c.containers}}}).RouteFile(t.Context(), c.origin)
		if (err == nil) != (c.refused == "") || err != nil && !strings.Contains(err.Error(), c.refused) {
			t.Errorf("%s: %v", c.name, err)
		}
		for _, w := range c.want {
			if !strings.Contains(text, w) || path != "/data/coolify/proxy/dynamic/varlatch-rollback.yaml" {
				t.Errorf("%s: no %q in %s\n%s", c.name, w, path, text)
			}
		}
		if err == nil && strings.Contains(text, "tls:") != strings.HasPrefix(c.origin, "https") {
			t.Errorf("%s: %s", c.name, text)
		}
	}
}

// What is written to .env is read by other shells: a separator of this
// shell's alone is refused, before anything is read or written with it.
func TestTheSeparatorIsTheFiles(t *testing.T) {
	for _, c := range []struct{ env, shell, refused string }{
		{"", "", ""},
		{"", ":", ""},
		{"", ";", "unset it, or set it in"},
		{"COMPOSE_PATH_SEPARATOR=;\n", ";", ""},
		{"COMPOSE_PATH_SEPARATOR=;\n", "", ""},
		{"COMPOSE_PATH_SEPARATOR=;\n", ":", "another shell reads"},
	} {
		dir := installationDir(t, map[string]string{"a.yml": "", "b.yml": "", ".env": c.env})
		p := &ComposeProject{Name: "p", Dir: dir, Files: []string{filepath.Join(dir, "a.yml"), filepath.Join(dir, "b.yml")}}
		cmp := &Compose{Directory: dir, reversed: true}
		if c.shell != "" {
			cmp.Env = []string{"COMPOSE_PATH_SEPARATOR=" + c.shell}
		}
		files, err := cmp.composeFiles(p, RebuildRecord{})
		if (err == nil) != (c.refused == "") || err != nil && !strings.Contains(err.Error(), c.refused) {
			t.Errorf("%q in .env, %q in the shell: %q %v", c.env, c.shell, files, err)
		}
		if err != nil {
			continue
		}
		if err := cmp.setEnv("COMPOSE_FILE", &files, ""); err != nil {
			t.Fatal(err)
		}
		if got, err := (&Compose{Directory: dir, reversed: true}).files(p); err != nil || len(got) != 3 {
			t.Errorf("%q in .env, %q in the shell, read by a fresh shell: %v %v", c.env, c.shell, got, err)
		}
	}
}

// The commands migrate says are a shell's.
func TestCommandsByHandAreQuoted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "the operator's dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &ComposeProject{Name: "p", Dir: dir, Files: []string{filepath.Join(dir, "a b.yml")}}
	said := (&Compose{Directory: dir, resolved: p}).byHand("up -d --no-deps x")
	out, err := exec.Command("sh", "-c", "docker() { for a in \"$@\"; do printf '%s\\n' \"$a\"; done; }; "+said).Output()
	if want := strings.Join([]string{"compose", "--project-name", "p", "--project-directory", dir, "-f", filepath.Join(dir, "a b.yml"), "up", "-d", "--no-deps", "x", ""}, "\n"); err != nil || string(out) != want {
		t.Errorf("%s: %v\n%s\nwant\n%s", said, err, out, want)
	}
}
