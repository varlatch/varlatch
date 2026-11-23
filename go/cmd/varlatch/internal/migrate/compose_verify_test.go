// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"errors"
	"maps"
	"os"
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
		cmp := &Compose{Directory: dir}
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
	plan := RebuildRecord{Override: OverrideFile, Volumes: []string{appID + "_postgres-data-x", appID + "_convex-data-x"}, Image: "x@sha256:y"}
	for name, do := range map[string]func(context.Context, *Compose) error{
		"barrier":         func(ctx context.Context, c *Compose) error { _, err := c.Barrier(ctx, time.Second); return err },
		"release":         func(ctx context.Context, c *Compose) error { return c.Release(ctx, "g") },
		"migrated out":    func(ctx context.Context, c *Compose) error { return c.MarkMigratedOut(ctx, "g") },
		"export":          func(ctx context.Context, c *Compose) error { _, err := c.Export(ctx, []byte("k"), false); return err },
		"backup":          func(ctx context.Context, c *Compose) error { _, err := c.Backup(ctx); return err },
		"stop ingress":    func(ctx context.Context, c *Compose) error { return c.StopIngress(ctx, Public) },
		"start ingress":   func(ctx context.Context, c *Compose) error { return c.StartIngress(ctx, Public, false) },
		"stop tailnet":    func(ctx context.Context, c *Compose) error { return c.StopTailnet(ctx) },
		"start tailnet":   func(ctx context.Context, c *Compose) error { return c.StartTailnet(ctx) },
		"rebuild":         func(ctx context.Context, c *Compose) error { return c.Rebuild(ctx, plan) },
		"import":          func(ctx context.Context, c *Compose) error { _, err := c.ImportReverse(ctx, os.DevNull); return err },
		"convex":          func(ctx context.Context, c *Compose) error { return c.ResetConvex(ctx) },
		"serve":           func(ctx context.Context, c *Compose) error { return c.StartServing(ctx, Coolify) },
		"stop serving":    func(ctx context.Context, c *Compose) error { return c.StopServing(ctx, Coolify) },
		"undo":            func(ctx context.Context, c *Compose) error { return c.UndoRebuild(ctx, plan) },
		"check rebuilt":   func(ctx context.Context, c *Compose) error { return c.CheckRebuilt(ctx, plan, true) },
		"check data":      func(ctx context.Context, c *Compose) error { return c.CheckData(ctx, Coolify, &plan, Removals{}) },
		"remove old":      func(ctx context.Context, c *Compose) error { return c.RemoveOld(ctx, Public, true, Removals{}) },
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
			cmp.KeepProject(kept)
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
	plan := RebuildRecord{Override: OverrideFile, Image: "x@sha256:y", Volumes: []string{appID + "_postgres-data-abcdefgh", appID + "_convex-data-abcdefgh"},
		Keys: []string{appID + "_postgres-data", appID + "_convex-data", appID + "_varlatch-state"}}
	host := &labelled{volumes: map[string]VolumeRecord{}, users: map[string]string{}}
	for i, n := range []string{"postgres-data", "convex-data"} {
		v := VolumeRecord{Name: appID + "_" + n, CreatedAt: "2026-01-0" + string(rune('1'+i)) + "T00:00:00Z", Project: appID}
		plan.Retained = append(plan.Retained, v)
		host.volumes[v.Name] = v
		host.volumes[plan.Volumes[i]] = VolumeRecord{Name: plan.Volumes[i], CreatedAt: "2026-11-01T00:00:00Z", Project: appID}
		host.containers = append(host.containers, composeContainer{project: appID, service: dataMounts[i].service, dir: dir, files: file + "," + filepath.Join(dir, OverrideFile),
			mounts: []containerMount{{Type: "volume", Name: plan.Volumes[i], Destination: dataMounts[i].target}}})
	}
	config := `{"name":"` + appID + `","services":{"postgres":{"volumes":["` + appID + `_postgres-data:/var/lib/postgresql/data"]},"convex-backend":{"volumes":["` + appID + `_convex-data:/convex/data"]},` +
		`"varlatchd":{"volumes":["` + appID + `_varlatch-state:/var/lib/varlatch"]}},"volumes":{"` + appID + `_postgres-data":{"name":"` + plan.Volumes[0] + `"},"` + appID + `_convex-data":{"name":"` + plan.Volumes[1] + `"}}}`
	c := &Compose{Directory: dir, Run: &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(config)}}}}
	c.KeepProject(&ComposeProject{Name: appID, Dir: dir, Files: []string{file}})
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
		}, refused: "it is another one"},
		{name: "one not there when the reverse began", change: func(_ *labelled, p *RebuildRecord) { p.Retained[1].CreatedAt, p.Retained[1].Project = "", "" }, refused: "it is another one"},
		{name: "another project's", change: func(h *labelled, _ *RebuildRecord) {
			v := h.volumes[convex]
			v.Project = "other"
			h.volumes[convex] = v
		}, refused: "labelled of the Compose project other"},
		{name: "unlabelled when the reverse began", change: func(_ *labelled, p *RebuildRecord) { p.Retained[1].Project = "" }, refused: "labelled of the Compose project"},
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
			checked := cmp.CheckData(t.Context(), kind, &plan, log)
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
	// Taken into use between the two removals.
	cmp, host, plan := retainedPlan(t)
	host.seen = nil
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
	if err != nil || plan.OverrideWas != OverrideFile+".before-abcdefgh" || !strings.HasSuffix(plan.ComposeFileLine, "\" # x\n") {
		t.Fatalf("a second reverse: %+v %v", plan, err)
	}
	run := cmp.Run.(*scripted)
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
			if kind == Coolify {
				if !errors.Is(err, ErrAwaitingOperator) || !slices.Equal(src.did, []string{both, "serve"}) || !strings.Contains(strings.Join(w.said, "\n"), "do not Deploy or Redeploy the TypeScript application") {
					t.Fatalf("%v: %v", err, src.did)
				}
				_, err = w.eng.Resume(t.Context())
			}
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
		jj, _ := readJournal(w.src.dir)
		jj.Rollback.Asked = true
		if err := writeJournal(w.src.dir, jj); err != nil {
			t.Fatal(err)
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

func (f *finishFake) CheckData(context.Context, Ingress, *RebuildRecord, Removals) error { return nil }
func (f *finishFake) ServeForArchive(context.Context) ([]string, error)                  { return nil, nil }
func (f *finishFake) StopStarted(context.Context, []string) error                        { return nil }
func (f *finishFake) RemoveOld(context.Context, Ingress, bool, Removals) error           { return nil }
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
