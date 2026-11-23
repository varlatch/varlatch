// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// The source's gate is exactly the migration's: its volume, its kind, its
// phase and its id; read in a container of its own, the volume read only.
func TestCheckGate(t *testing.T) {
	for _, c := range []struct {
		name string
		do   func(h *labelled, g *GateRef)
		want string // "" for the gate
	}{
		{"the gate", func(*labelled, *GateRef) {}, ""},
		{"an earlier build's journal, which records no volume", func(_ *labelled, g *GateRef) { g.State = nil }, ""},
		{"the volume gone", func(h *labelled, _ *GateRef) { delete(h.volumes, stateVol.Name) }, "is not there"},
		{"the volume made again, empty", func(h *labelled, _ *GateRef) {
			v := stateVol
			v.CreatedAt = "2026-11-23T00:00:00Z"
			h.volumes[v.Name], h.gates[v.Name] = v, ""
		}, "is not the one that carried the gate when the migration began"},
		{"the volume made again, the gate put in it", func(h *labelled, _ *GateRef) {
			v := stateVol
			v.CreatedAt = "2026-11-23T00:00:00Z"
			h.volumes[v.Name] = v
		}, "is not the one that carried the gate when the migration began"},
		{"another project's volume", func(h *labelled, _ *GateRef) {
			v := stateVol
			v.Project = "another"
			h.volumes[v.Name] = v
		}, "its labels"},
		{"the volume made again, an earlier build's journal", func(h *labelled, g *GateRef) {
			g.State, h.gates[stateVol.Name] = nil, ""
		}, "holds no gate"},
		{"the file gone", func(h *labelled, _ *GateRef) { h.gates[stateVol.Name] = "" }, "holds no gate (maintenance.json): the TypeScript installation would take requests"},
		{"a file that is not one", func(h *labelled, _ *GateRef) { h.gates[stateVol.Name] = "{" }, "cannot be read"},
		{"another id", func(h *labelled, g *GateRef) { g.ID = "gate-2" }, "is migrated-out gate-1 (paused), not the migration's own, gate-2"},
		{"the barrier only", func(h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, "migrated-out", "migration", 1)
		}, "is migration gate-1"},
		{"the barrier, where it may be it", func(h *labelled, g *GateRef) {
			g.Barrier, h.gates[stateVol.Name] = true, strings.Replace(gateText, "migrated-out", "migration", 1)
		}, ""},
		{"a capture's, where the barrier may be it", func(h *labelled, g *GateRef) {
			g.Barrier, h.gates[stateVol.Name] = true, strings.Replace(gateText, "migrated-out", "capture", 1)
		}, "is capture gate-1"},
		{"a restore's", func(h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, "migrated-out", "restore", 1)
		}, "is restore gate-1"},
		{"draining", func(h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, "paused", "draining", 1)
		}, "(draining)"},
		{"one that expires", func(h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, `"expiresAt":null`, `"expiresAt":1795000000000`, 1)
		}, "not the migration's own"},
		{"no gate recorded", func(_ *labelled, g *GateRef) { g.ID = "" }, "records no gate"},
	} {
		host, g := gatedHost(), gate1
		c.do(host, &g)
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}}}
		cmp := stockCompose(t, run)
		err := cmp.CheckGate(t.Context(), g)
		if (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if len(run.ran) > 1 || len(host.made) > 0 {
			t.Errorf("%s: ran %q, made %v", c.name, run.ran, host.made)
		}
	}
	// Its container on another volume; another state directory; a bind mount.
	for name, c := range map[string]struct {
		config string
		on     string
		want   string
	}{
		"a container on another volume": {stockConfig, "varlatch_other", "varlatchd container is on varlatch_other"},
		"another state directory":       {strings.Replace(stockConfig, `"varlatchd":{`, `"varlatchd":{"environment":{"VARLATCH_STATE_DIR":"/elsewhere"},`, 1), "", "in another directory than /var/lib/varlatch"},
		"a bind mount":                  {strings.Replace(stockConfig, `"varlatchd":{"volumes":[{"type":"volume","source":"varlatch-state"`, `"varlatchd":{"volumes":[{"type":"bind","source":"/srv/state"`, 1), "", "mounts no named volume at /var/lib/varlatch"},
	} {
		host := gatedHost()
		cmp := stockCompose(t, &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(c.config)}}})
		if c.on != "" {
			l := ownCtr(cmp, "varlatchd")
			l.mounts[0].Name = c.on
			host.containers = append(host.containers, l)
		}
		if err := cmp.CheckGate(t.Context(), gate1); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		// Told by the plan too, before anything: an undo reads its gate there.
		j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd", Volumes: stockVolumes}}
		if _, err := cmp.RebuildPlan(t.Context(), j); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the plan: %v, want %q", name, err, c.want)
		}
	}
	// An image that is gone is pulled, never through the gate's own run.
	host := gatedHost()
	run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker image inspect ": {Code: 1}, "docker pull -q other@sha256:z": {Code: 1}}}
	g := gate1
	g.Image = "other@sha256:z"
	if err := stockCompose(t, run).CheckGate(t.Context(), g); err == nil || !strings.Contains(err.Error(), "the image other sha256:z is not on this host") || host.reads != 0 {
		t.Errorf("the image gone: %v", err)
	}
}

// ServeGated starts nothing, Postgres and the sidecar included, without
// the gate; and not varlatchd when the gate went while those started.
func TestServeGatedWithoutTheGate(t *testing.T) {
	for _, config := range []string{stockConfig, sidecarConfig} {
		for at, want := range map[int]string{1: "", 2: "varlatchd"} {
			host := gatedHost()
			run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(config)}, "docker compose ps ": {}, "docker compose up ": {}, "docker compose start ": {}}}
			cmp := stockCompose(t, run)
			inspects := 0
			host.inspected = func(string) {
				if inspects++; inspects == at {
					host.gates[stateVol.Name] = ""
				}
			}
			var started []string
			err := cmp.ServeGated(t.Context(), GatedStart{Gate: gate1, Owned: config == sidecarConfig, Starting: func(s string) error { started = append(started, s); return nil }})
			if err == nil || !strings.Contains(err.Error(), "holds no gate") {
				t.Errorf("at %d: %v", at, err)
			}
			for _, r := range run.ran {
				if want == "" && !strings.HasPrefix(r, "docker compose config") || strings.HasSuffix(r, " varlatchd") {
					t.Errorf("at %d: ran %q", at, r)
				}
			}
			if slices.Contains(started, "varlatchd") || at == 1 && len(started) > 0 {
				t.Errorf("at %d: journalled %v", at, started)
			}
		}
	}
}

// --rollback on Coolify without the migration's gate (the state volume or
// its file gone, Postgres and Convex kept): refused before anything is
// started, asked or journalled; lost once its services run, the dashboard
// is not started and the reverse is undone.
func TestTheWayBackNeedsTheGate(t *testing.T) {
	lost := errors.New("the volume p_varlatch-state holds no gate")
	newWorld := func(up string) (*world, *reverseFake, *Journal, *routeProber) {
		w, src, j := rolledWorld(t, Open, Coolify)
		w.eng.Options.TransferTimeout = 2 * time.Second
		w.src.ingressDown = true
		p := &routeProber{w: w, id: j.ID}
		p.route = func() string {
			if w.src.ingressDown {
				return "file: nothing"
			}
			return up
		}
		w.eng.Source, w.eng.Prober = routedFake{src}, p
		return w, src, j, p
	}
	w, src, j, p := newWorld("file: ts")
	src.gateErr = func(int) error { return lost }
	_, err := w.eng.Rollback(t.Context())
	after, _ := readJournal(w.src.dir)
	if !errors.Is(err, lost) || !strings.Contains(err.Error(), "nothing was started") || len(src.did) != 0 || p.gates != 0 || len(w.said) != 0 || len(after.History) != 1 || after.Phase != Open || !w.src.ingressDown {
		t.Errorf("before: %v, %v, asked %d, phase %s", err, src.did, p.gates, after.Phase)
	}
	if want := (GateRef{ID: "gate-1", State: j.Source.State, Image: j.Source.DigestRepository + "@" + j.Source.Digest}); len(src.gates) != 1 || src.gates[0] != want {
		if len(src.gates) != 1 || src.gates[0].ID != want.ID || src.gates[0].Image != want.Image || src.gates[0].State == nil || *src.gates[0].State != stateVol {
			t.Errorf("the gate asked for: %+v", src.gates)
		}
	}
	// After ServeGated (its own two checks are the Compose side's).
	w, src, _, p = newWorld("file: ts")
	src.starts = []string{"postgres", "varlatchd"}
	src.gateErr = func(n int) error {
		if n == 3 {
			return lost
		}
		return nil
	}
	_, err = w.eng.Rollback(t.Context())
	after, _ = readJournal(w.src.dir)
	if !errors.Is(err, lost) || !strings.Contains(err.Error(), "the TypeScript dashboard was not started") || w.src.recreates != 0 || !w.src.ingressDown || after.Phase != Open || p.gates != 1 ||
		!slices.Equal(src.did, []string{"serve gated, the sidecar false", "stop started postgres varlatchd"}) {
		t.Errorf("once it runs: %v, %v, made again %d, probed %d, phase %s", err, src.did, w.src.recreates, p.gates, after.Phase)
	}
}

// What the route's check started is stopped by an undo before the plan is
// recorded, that and no more: on a route that does not work, and on
// --resume and --abort of one killed there.
func TestTheUndoStopsWhatTheCheckStarted(t *testing.T) {
	for _, starts := range [][]string{nil, {"postgres"}, {"postgres", "varlatchd"}, {"varlatchd"}} {
		want := []string{"serve gated, the sidecar false"}
		stop := "stop started " + strings.Join(starts, " ")
		if starts != nil {
			want = append(want, stop)
		}
		w, src, j := rolledWorld(t, Open, Coolify)
		w.eng.Options.TransferTimeout = 2 * time.Second
		src.starts, w.src.ingressDown = starts, true
		p := &routeProber{w: w, id: j.ID, route: func() string { return "file: nothing" }}
		w.eng.Source, w.eng.Prober = routedFake{src}, p
		if _, err := w.eng.Rollback(t.Context()); err == nil || !slices.Equal(src.did, want) {
			t.Errorf("%v: %v: %v, want %v", starts, err, src.did, want)
		}
		for _, abort := range []bool{false, true} {
			w, src, j := rolledWorld(t, Rollback, Coolify)
			j.Rollback = &RollbackRecord{Started: starts}
			if err := writeJournal(w.src.dir, j); err != nil {
				t.Fatal(err)
			}
			w.tgt.journal = &JournalHead{ID: j.ID, Phase: Rollback}
			var err error
			if abort {
				_, err = w.eng.Abort(t.Context())
			} else {
				_, err = w.eng.Resume(t.Context())
			}
			after, _ := readJournal(w.src.dir)
			if (abort && err != nil) || !slices.Equal(src.did, want[1:]) || after.Phase != Open {
				t.Errorf("%v, abort %v: %v: %v, phase %s", starts, abort, err, src.did, after.Phase)
			}
		}
	}
	// With a plan, its undo puts them back: nothing is stopped besides.
	w, src, j := rolledWorld(t, Rollback, Coolify)
	j.Rollback.Started = []string{"postgres"}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	if _, err := w.eng.Abort(t.Context()); err != nil || !slices.Equal(src.did, []string{"undo p_postgres-data-abcdefgh"}) {
		t.Errorf("with a plan: %v %v", err, src.did)
	}
}

// A gate an undo made, the import having lifted the migration's, is
// journalled, and is the one a later reverse asks for.
func TestTheUndosGateIsKnownLater(t *testing.T) {
	w, src, _ := rolledWorld(t, RollbackChecked, Coolify)
	src.remade = "gate-9"
	if _, err := w.eng.Abort(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, _ := readJournal(w.src.dir)
	if after.SourceGate != "gate-9" || after.Barrier.GateID != "gate-1" || src.gates[0].ID != "gate-1" || sourceGate(after).ID != "gate-9" {
		t.Errorf("%+v, asked %+v", after.SourceGate, src.gates)
	}
}

// The gate after an undone rebuild: the migration's, when the import did
// not lift it; another made, journalled before it is marked, when it did;
// varlatchd starts behind it only.
func TestTheUndoStartsBehindAGate(t *testing.T) {
	const status, barrier, mark, up = "docker compose run --rm -T --no-deps varlatchd admin migration status", "docker compose run --rm -T --no-deps varlatchd admin migration barrier",
		"docker compose run --rm -T --no-deps varlatchd admin migration mark-migrated-out --id ", "docker compose up -d --no-deps varlatchd"
	made := strings.Replace(gateText, "gate-1", "gate-9", 1)
	for _, c := range []struct {
		name, status, file string
		gated              string // the gate journalled
		fail               string
	}{
		{"not lifted", `{"gate":{"kind":"migrated-out","id":"gate-1"}}`, gateText, "", ""},
		{"lifted", `{"gate":null}`, made, "gate-9", ""},
		{"killed before it was journalled", `{"gate":{"kind":"migration","id":"gate-9"}}`, made, "gate-9", ""},
		{"killed before it was journalled, marked", `{"gate":{"kind":"migrated-out","id":"gate-9"}}`, made, "gate-9", ""},
		{"gone again before varlatchd starts", `{"gate":{"kind":"migrated-out","id":"gate-1"}}`, "", "", "holds no gate"},
		{"a restore's", `{"gate":{"kind":"restore","id":"gate-1"}}`, gateText, "", "behind a restore gate"},
	} {
		host := gatedHost()
		host.gates[stateVol.Name] = c.file
		// Made again by the undo's own commands: another than the journal's.
		v := stateVol
		v.CreatedAt = "2026-11-23T00:00:00Z"
		host.volumes[v.Name] = v
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose stop ": {}, "docker compose up ": {}, "docker compose ps ": {},
			status: {Answer: []byte(c.status)}, barrier: {Answer: []byte(`{"gate":{"kind":"migration","id":"gate-9"}}`)}, mark: {}}}
		var gated []string
		err := stockCompose(t, run).UndoRebuild(t.Context(), RebuildRecord{Override: OverrideFile}, gate1, func(id string) error {
			gated = append(gated, id)
			if slices.ContainsFunc(run.ran, func(r string) bool { return strings.HasPrefix(r, mark) }) {
				t.Errorf("%s: journalled after it was marked", c.name)
			}
			return nil
		})
		if (err == nil) != (c.fail == "") || err != nil && !strings.Contains(err.Error(), c.fail) || slices.Contains(run.ran, up) != (c.fail == "") || strings.Join(gated, " ") != c.gated {
			t.Errorf("%s: %v, journalled %v, ran %q", c.name, err, gated, run.ran)
		}
	}
}

// What answers is the origin's own: a redirect elsewhere is its answer.
func TestTheProbesFollowNoRedirectAway(t *testing.T) {
	gate := func(w http.ResponseWriter) {
		w.Header().Set(routeHeader, "mig_x")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"ready":false,"state":"migrated-out"}`)
	}
	followed := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed++
		if r.URL.Path == "/v1/meta" {
			fmt.Fprint(w, `{"installationId":"inst_x","serverVersion":"0.23.0"}`)
			return
		}
		gate(w)
	}))
	defer other.Close()
	var to string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/here") {
			gate(w)
			return
		}
		w.Header().Set(routeHeader, "mig_x")
		http.Redirect(w, r, to, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	for _, away := range []string{other.URL, strings.Replace(srv.URL, "http:", "https:", 1), strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)} {
		to = away + "/readyz"
		got, err := (HTTPProber{}).ProbeGate(t.Context(), srv.URL)
		if err != nil || got.migratedOut() || got.Server || got.Status != http.StatusTemporaryRedirect || followed != 0 {
			t.Errorf("to %s: %+v %v, followed %d", to, got, err, followed)
		}
		to = away + "/v1/meta"
		if id, version, err := (HTTPProber{}).Probe(t.Context(), srv.URL); err == nil || followed != 0 {
			t.Errorf("to %s: %s %s, followed %d", to, id, version, followed)
		}
	}
	to = srv.URL + "/here"
	if got, err := (HTTPProber{}).ProbeGate(t.Context(), srv.URL); err != nil || !got.migratedOut() || got.Route != "mig_x" {
		t.Errorf("a redirect within the origin: %+v %v", got, err)
	}
}

// The Docker Compose a migration and its way back need, told before
// anything.
func TestTheComposeVersion(t *testing.T) {
	for said, ok := range map[string]bool{
		"2.31.0": false, "2.30.3": false, "2.24.7": false, "1.29.2": false, "v2.31.9": false, "2.31.0-desktop.2": false,
		"2.32.0": true, "v2.32.0": true, "2.32.4": true, "2.33.0-desktop.1": true, "2.40.3+ds1-0ubuntu1": true, "5.2.0": true, "5.6.1": true, "5.8.0": true, "10.0.0": true,
		"": false, "dev": false, "2.32": false, "Docker Compose version v2.40.0": false,
	} {
		run := &scripted{t: t, version: &Ran{Answer: []byte(said + "\n")}, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}}}
		cmp := stockCompose(t, run)
		err := cmp.checkVersion(t.Context())
		if (err == nil) != ok || err != nil && !strings.Contains(err.Error(), "varlatch migrate needs 2.32.0 or later") {
			t.Errorf("%q: %v", said, err)
		}
		if ok {
			continue
		}
		for name, do := range map[string]func() error{
			"migrate": func() error { _, err := cmp.Discover(t.Context()); return err },
			"reverse": func() error { _, err := cmp.RebuildPlan(t.Context(), &Journal{ID: "mig_x"}); return err },
		} {
			if err := do(); err == nil || !strings.Contains(err.Error(), "2.32.0 or later") || len(run.ran) != 0 {
				t.Errorf("%q, %s: %v, ran %q", said, name, err, run.ran)
			}
		}
	}
	run := &scripted{t: t, version: &Ran{Code: 1, Answer: []byte("5.2.0")}}
	if err := stockCompose(t, run).checkVersion(t.Context()); err == nil {
		t.Error("a failed docker compose version")
	}
}
