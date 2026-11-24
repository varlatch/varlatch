// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
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
		// The same through varlatchd's own container, stopped or running.
		for _, status := range []string{"created", "exited", "running"} {
			l := ownCtr(cmp, "varlatchd")
			l.status = status
			host.containers, run.ran = []composeContainer{l}, nil
			if err := cmp.CheckGate(t.Context(), g); (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s, through its container: %v, want %q", c.name, err, c.want)
			}
			if len(run.ran) > 1 || len(host.made) > 0 {
				t.Errorf("%s, through its container: ran %q, made %v", c.name, run.ran, host.made)
			}
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
		!slices.Equal(src.did, []string{"serve gated, the sidecar false", "hold gate-1", "stop front", "stop started postgres varlatchd", "stop front", "held gate-1", "held gate-1"}) {
		t.Errorf("once it runs: %v, %v, made again %d, probed %d, phase %s", err, src.did, w.src.recreates, p.gates, after.Phase)
	}
}

// What the route's check started is stopped by an undo before the plan is
// recorded, that and no more: on a route that does not work, and on
// --resume and --abort of one killed there.
func TestTheUndoStopsWhatTheCheckStarted(t *testing.T) {
	for _, starts := range [][]string{nil, {"postgres"}, {"postgres", "varlatchd"}, {"varlatchd"}} {
		want := []string{"serve gated, the sidecar false", "hold gate-1", "stop front"}
		if starts != nil {
			want = append(want, "stop started "+strings.Join(starts, " "))
		}
		want = append(want, "stop front", "held gate-1", "held gate-1")
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
	if _, err := w.eng.Abort(t.Context()); err != nil || slices.ContainsFunc(src.did, func(d string) bool { return strings.HasPrefix(d, "stop started") }) {
		t.Errorf("with a plan: %v %v", err, src.did)
	}
}

// A gate an undo finds, another than the migration's (an earlier build's
// undo made one), is journalled, and is the one a later reverse asks for.
func TestTheUndosGateIsKnownLater(t *testing.T) {
	w, src, _ := rolledWorld(t, RollbackChecked, Coolify)
	src.remade = "gate-9"
	other := stateVol
	other.CreatedAt = "2026-11-23T00:00:00Z"
	src.remadeIn = &other
	if _, err := w.eng.Abort(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, _ := readJournal(w.src.dir)
	if after.Source.State == nil || *after.Source.State != other {
		t.Errorf("the volume: %+v", after.Source.State)
	}
	if after.SourceGate != "gate-9" || after.Barrier.GateID != "gate-1" || src.did[0] != "hold gate-1" || sourceGate(after).ID != "gate-9" || src.position != "46" {
		t.Errorf("%+v, %v, position %q", after.SourceGate, src.did, src.position)
	}
}

// An undo's first step: the gate stands in the volume that carries it, made
// again as the release makes it when the import lifted it, whatever the
// Compose files are; what is there and not the migration's is left.
func TestHoldGate(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(cmp *Compose, h *labelled, g *GateRef)
		want string // the refusal
		wrote,
		id string
	}{
		{"there", func(*Compose, *labelled, *GateRef) {}, "", "", "gate-1"},
		{"lifted", func(_ *Compose, h *labelled, _ *GateRef) { h.gates[stateVol.Name] = "" }, "", "new", "gate-1"},
		{"a killed undo's barrier of an earlier build", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.ReplaceAll(strings.Replace(gateText, "migrated-out", "migration", 1), "gate-1", "gate-9")
		}, "", "replace", "gate-1"},
		{"another migrated-out one", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, "gate-1", "gate-9", 1)
		}, "", "", "gate-9"},
		{"a restore's", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, "migrated-out", "restore", 1)
		}, "behind a restore gate (gate-1), not the migration's: left as it is", "", ""},
		{"a capture's", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(strings.Replace(gateText, "migrated-out", "capture", 1), `"expiresAt":null`, `"expiresAt":1`, 1)
		}, "behind a capture gate", "", ""},
		{"one that expires", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, `"expiresAt":null`, `"expiresAt":1`, 1)
		}, "behind a migrated-out gate", "", ""},
		{"unreadable", func(_ *Compose, h *labelled, _ *GateRef) { h.gates[stateVol.Name] = "{" }, "cannot be read", "", ""},
		{"a link", func(_ *Compose, h *labelled, _ *GateRef) { h.gates[stateVol.Name] = "link" }, "is not a plain file", "", ""},
		{"the volume gone", func(_ *Compose, h *labelled, _ *GateRef) {
			delete(h.volumes, stateVol.Name)
			delete(h.gates, stateVol.Name)
		}, "", "new", "gate-1"},
		{"the volume another's of the project, empty", func(_ *Compose, h *labelled, _ *GateRef) {
			v := stateVol
			v.CreatedAt = "2026-11-23T00:00:00Z"
			h.volumes[v.Name], h.gates[v.Name] = v, ""
		}, "", "new", "gate-1"},
		{"another project's volume", func(_ *Compose, h *labelled, _ *GateRef) {
			v := stateVol
			v.Project = "another"
			h.volumes[v.Name], h.gates[v.Name] = v, ""
		}, "is not of its project varlatch", "", ""},
		{"its server on another volume", func(cmp *Compose, h *labelled, _ *GateRef) {
			l := ownCtr(cmp, "varlatchd")
			l.mounts[0].Name = "another"
			h.containers, h.gates[stateVol.Name] = []composeContainer{l}, ""
		}, "it is another", "", ""},
		{"its server's state a part of the volume", func(cmp *Compose, h *labelled, _ *GateRef) {
			l := ownCtr(cmp, "varlatchd")
			l.id = "c1"
			h.containers, h.gates[stateVol.Name] = []composeContainer{l}, ""
			h.inspects = map[string]string{"c1": `[] [{"Type":"volume","Name":"varlatch_varlatch-state","Destination":"/var/lib/varlatch","Driver":"local","RW":true}] [{"Type":"volume","Source":"x","Target":"/var/lib/varlatch","VolumeOptions":{"Subpath":"p"}}] null`}
		}, "a part of it", "", ""},
		{"an earlier build's journal", func(_ *Compose, h *labelled, g *GateRef) { g.State, h.gates[stateVol.Name] = nil, "" }, "", "new", "gate-1"},
		{"no gate recorded", func(_ *Compose, h *labelled, g *GateRef) { g.ID, h.gates[stateVol.Name] = "", "" }, "records no gate", "", ""},
		{"it cannot be written", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = ""
			h.runErr = func(write bool) *Ran {
				if write {
					return &Ran{Code: 1, Said: []byte("No space left on device")}
				}
				return nil
			}
		}, "No space left on device", "", ""},
		{"written, and not there", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = ""
			h.runErr = func(write bool) *Ran {
				if write {
					return &Ran{}
				}
				return nil
			}
		}, "holds no gate", "", ""},
		{"it cannot be read", func(_ *Compose, h *labelled, _ *GateRef) {
			h.runErr = func(bool) *Ran { return &Ran{Code: 125, Said: []byte("the daemon is down")} }
		}, "the daemon is down", "", ""},
	} {
		host, g := gatedHost(), gate1
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}}}
		cmp := stockCompose(t, run)
		c.set(cmp, host, &g)
		recorded := g.State != nil
		before := host.gates[stateVol.Name]
		held, err := cmp.HoldGate(t.Context(), g, "46")
		if (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if wrote := strings.TrimPrefix(strings.Join(host.writes, " "), stateVol.Name+" "); wrote != c.wrote {
			t.Errorf("%s: wrote %q, want %q", c.name, wrote, c.wrote)
		}
		after := host.gates[stateVol.Name]
		switch {
		case c.wrote != "":
			if after != `{"id":"gate-1","kind":"migrated-out","phase":"paused","expiresAt":null,"archiveId":null,"frozenPosition":"46","frozenSnapshot":null}` {
				t.Errorf("%s: wrote %s", c.name, after)
			}
		case after != before:
			t.Errorf("%s: the gate is %s", c.name, after)
		}
		if c.want == "" {
			if held.ID != c.id || held.State == nil || *held.State != host.volumes[stateVol.Name] {
				t.Errorf("%s: held %+v", c.name, held)
			}
			if err := cmp.CheckHeld(t.Context(), held); err != nil {
				t.Errorf("%s: held: %v", c.name, err)
			}
		}
		// Nothing of the Compose files is asked for, when the volume is
		// recorded: they may not be whole. Nothing is started.
		for _, r := range run.ran {
			if recorded || !strings.HasPrefix(r, "docker compose config ") {
				t.Errorf("%s: ran %q", c.name, r)
			}
		}
	}
	// A position that is none is not written as one.
	if b := string(gate1.text("x")); !strings.Contains(b, `"frozenPosition":null`) {
		t.Error(b)
	}
	if _, err := parseGate(gate1.text("46")); err != nil {
		t.Error(err)
	}
}

// Whoever starts the server, it is behind the gate: the gate in the recorded
// volume, the server's containers on it, whole, and no import running.
func TestCheckHeld(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(cmp *Compose, h *labelled, g *GateRef)
		want string
	}{
		{"held, its server running", func(cmp *Compose, h *labelled, _ *GateRef) {
			h.containers = []composeContainer{ownCtr(cmp, "varlatchd")}
		}, ""},
		{"held, without containers", func(*Compose, *labelled, *GateRef) {}, ""},
		{"lifted", func(_ *Compose, h *labelled, _ *GateRef) { h.gates[stateVol.Name] = "" }, "holds no gate"},
		{"another gate", func(_ *Compose, h *labelled, g *GateRef) { g.ID = "gate-2" }, "not the migration's own, gate-2"},
		{"the barrier only", func(_ *Compose, h *labelled, _ *GateRef) {
			h.gates[stateVol.Name] = strings.Replace(gateText, "migrated-out", "migration", 1)
		}, "not the migration's own"},
		{"the volume gone", func(_ *Compose, h *labelled, _ *GateRef) { delete(h.volumes, stateVol.Name) }, "is not there"},
		{"another volume", func(_ *Compose, h *labelled, _ *GateRef) {
			v := stateVol
			v.CreatedAt = "2026-11-23T00:00:00Z"
			h.volumes[v.Name] = v
		}, "is not the one that carries the gate"},
		{"its server on another volume", func(cmp *Compose, h *labelled, _ *GateRef) {
			l := ownCtr(cmp, "varlatchd")
			l.mounts[0].Name, l.status = "another", "exited"
			h.containers = []composeContainer{l}
		}, "it is another"},
		{"the import running", func(cmp *Compose, h *labelled, _ *GateRef) {
			l := ctr("varlatch", importService, filepath.Join(cmp.Directory, "docker-compose.yml"), cmp.Directory, "True")
			l.name = "the-import"
			h.containers = []composeContainer{l}
		}, "the reverse's import (the-import) still runs"},
		{"the import ended", func(cmp *Compose, h *labelled, _ *GateRef) {
			l := ctr("varlatch", importService, filepath.Join(cmp.Directory, "docker-compose.yml"), cmp.Directory, "True")
			l.status = "exited"
			h.containers = []composeContainer{l}
		}, ""},
		{"no volume recorded", func(_ *Compose, _ *labelled, g *GateRef) { g.State = nil }, "does not record"},
		{"another directory's container of the project", func(_ *Compose, h *labelled, _ *GateRef) {
			h.containers = []composeContainer{ctr("varlatch", "varlatchd", "/srv/live/docker-compose.yml", "/srv/live", "False")}
		}, "made from /srv/live"},
	} {
		host, g := gatedHost(), gate1
		run := &scripted{t: t, host: host}
		cmp := stockCompose(t, run)
		c.set(cmp, host, &g)
		if err := cmp.CheckHeld(t.Context(), g); (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if len(run.ran) > 0 || len(host.writes) > 0 {
			t.Errorf("%s: ran %q, wrote %v", c.name, run.ran, host.writes)
		}
	}
}

// The undone rebuild starts its server only with start, and behind the gate
// that stands already: it makes none.
func TestTheUndoStartsBehindTheGate(t *testing.T) {
	for _, c := range []struct {
		name, file string
		start      bool
		fail       string
	}{
		{"behind it", gateText, true, ""},
		{"not started, its sidecar's to be", gateText, false, ""},
		{"gone by then", "", true, "holds no gate"},
	} {
		host := gatedHost()
		host.gates[stateVol.Name] = c.file
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose up ": {}, "docker compose ps ": {}}}
		cmp := stockCompose(t, run)
		run.onRun = makes(cmp, host, false)
		err := cmp.UndoRebuild(t.Context(), RebuildRecord{Override: OverrideFile}, gate1, c.start)
		if (err == nil) != (c.fail == "") || err != nil && !strings.Contains(err.Error(), c.fail) || slices.Contains(run.ran, "docker start made") != (c.start && c.fail == "") || len(host.writes) > 0 {
			t.Errorf("%s: %v, ran %q", c.name, err, run.ran)
		}
		for _, r := range run.ran {
			if strings.Contains(r, " run ") {
				t.Errorf("%s: ran %q", c.name, r)
			}
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

// The state directory is the whole of its volume, in the very container
// that starts: a part of it, another mount, one in it or over it is refused.
func TestTheContainersStateDirectory(t *testing.T) {
	const (
		env  = `["PATH=/x","VARLATCH_STATE_DIR=/var/lib/varlatch"]`
		own  = `{"Type":"volume","Name":"varlatch_varlatch-state","Destination":"/var/lib/varlatch","Driver":"local","RW":true}`
		none = ` null null`
	)
	for _, c := range []struct{ name, inspect, want string }{
		{"as the stock file has it", env + " [" + own + "]" + none, ""},
		{"the image's own state directory, the long form", `["PATH=/x"] [` + own + `,{"Type":"bind","Destination":"/backups","RW":true}] [{"Type":"volume","Source":"varlatch_varlatch-state","Target":"/var/lib/varlatch"}] {"/tmp":""}`, ""},
		{"an empty subpath", env + " [" + own + `] [{"Type":"volume","Source":"varlatch_varlatch-state","Target":"/var/lib/varlatch","VolumeOptions":{"Subpath":""}}] null`, ""},
		{"a part of the volume", env + " [" + own + `] [{"Type":"volume","Source":"varlatch_varlatch-state","Target":"/var/lib/varlatch/","VolumeOptions":{"Subpath":"other"}}] null`, "a part of it"},
		{"another volume", env + ` [{"Type":"volume","Name":"another","Destination":"/var/lib/varlatch","Driver":"local","RW":true}]` + none, "it is another"},
		{"a bind mount", env + ` [{"Type":"bind","Destination":"/var/lib/varlatch","RW":true}]` + none, "it is a bind"},
		{"nothing there", env + ` [{"Type":"bind","Destination":"/backups","RW":true}]` + none, "mounted there 0 times"},
		{"twice", env + " [" + own + "," + own + "]" + none, "mounted there 2 times"},
		{"the gate's own file mounted over it", env + " [" + own + `,{"Type":"bind","Destination":"/var/lib/varlatch/maintenance.json","RW":true}]` + none, "something is mounted in it, at /var/lib/varlatch/maintenance.json"},
		{"a file mounted in it, as asked", env + " [" + own + `] [{"Type":"bind","Source":"/x","Target":"/var/lib/varlatch/x"}] null`, "or something else"},
		{"a volume mounted in it, as asked", env + " [" + own + `] [{"Type":"volume","Source":"x","Target":"/var/lib/varlatch/x"}] null`, "or something else"},
		{"a temporary file system over it", env + " [" + own + `] null {"/var/lib/varlatch":""}`, "a temporary file system"},
		{"read only", env + ` [{"Type":"volume","Name":"varlatch_varlatch-state","Destination":"/var/lib/varlatch","Driver":"local","RW":false}]` + none, "read only"},
		{"another driver", env + ` [{"Type":"volume","Name":"varlatch_varlatch-state","Destination":"/var/lib/varlatch","Driver":"nfs","RW":true}]` + none, "driver is nfs"},
		{"another state directory", `["VARLATCH_STATE_DIR=/elsewhere"] [` + own + "]" + none, "in another directory than /var/lib/varlatch"},
		{"unreadable", "null", "did not give the container's mounts"},
	} {
		host := gatedHost()
		cmp := stockCompose(t, &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose ps ": {}, "docker compose up ": {}}})
		l := ownCtr(cmp, "varlatchd")
		l.id, l.status = "c1", "exited"
		host.containers, host.inspects = []composeContainer{l}, map[string]string{"c1": c.inspect}
		for what, do := range map[string]func() error{
			"gate":  func() error { return cmp.CheckGate(t.Context(), gate1) },
			"start": func() error { return cmp.startGated(t.Context(), gate1, false) },
			"state": func() error { _, err := cmp.CheckState(t.Context()); return err },
		} {
			host.containers[0].status = "exited"
			if err := do(); (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s, %s: %v, want %q", c.name, what, err, c.want)
			}
			if started := host.containers[0].status == "running"; started != (what == "start" && c.want == "") {
				t.Errorf("%s, %s: started %v", c.name, what, started)
			}
		}
	}
	// Its value is never said, whatever it holds.
	host := gatedHost()
	cmp := stockCompose(t, &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}}})
	l := ownCtr(cmp, "varlatchd")
	l.id = "c1"
	host.containers, host.inspects = []composeContainer{l}, map[string]string{"c1": `["X=not-to-be-said","VARLATCH_STATE_DIR=/not-to-be-said"] [] null null`}
	if err := cmp.CheckGate(t.Context(), gate1); err == nil || strings.Contains(err.Error(), "not-to-be-said") {
		t.Errorf("%v", err)
	}
}

// The gate's file is a plain one of its own, read as JavaScript reads it.
func TestTheGatesFile(t *testing.T) {
	at := func(b []byte) error {
		host := gatedHost()
		cmp := stockCompose(t, &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}}})
		l := ownCtr(cmp, "varlatchd")
		l.id = "c1"
		host.containers, host.tars = []composeContainer{l}, map[string][]byte{"c1": b}
		return cmp.CheckGate(t.Context(), gate1)
	}
	plain := tarOf("maintenance.json", gateText, tar.TypeReg)
	two := append(slices.Clone(plain[:1024]), plain...)
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"a file":         {plain, ""},
		"a link":         {tarOf("maintenance.json", "", tar.TypeSymlink), "is not a plain file"},
		"a directory":    {tarOf("maintenance.json", "", tar.TypeDir), "is not a plain file"},
		"another name":   {tarOf("maintenance.json.1", gateText, tar.TypeReg), "is not a plain file"},
		"a large one":    {tarOf("maintenance.json", gateText+strings.Repeat(" ", maxGate), tar.TypeReg), "is not a plain file"},
		"two of them":    {two, "is not one file"},
		"not an archive": {[]byte("x"), "cannot be read"},
	} {
		if err := at(c.b); (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	const rest = `"phase":"paused","expiresAt":null,"archiveId":null`
	for text, want := range map[string]string{
		gateText: "",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `}`:                                                              "",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `,"frozenPosition":"46","frozenSnapshot":"00000003-0000001B-1"}`: "",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `,"frozenPosition":null,"frozenSnapshot":null}`:                  "",
		// A capture, which the release clears at its start, read as migrated
		// out by a decoder that takes any case, or the last of two.
		`{"id":"gate-1","kind":"capture",` + rest + `,"Kind":"migrated-out"}`:                                                                 "a key a gate has not",
		`{"id":"gate-1","kind":"capture","expiresAt":1795000000000,"phase":"paused","archiveId":null,"KIND":"migrated-out","EXPIRESAT":null}`: "a key a gate has not",
		`{"id":"gate-1","kind":"capture",` + rest + `,"kind":"migrated-out"}`:                                                                 "kind twice",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `,"kind":"capture"}`:                                                                 "kind twice",
		`{"id":"gate-1","kind":"capture",` + rest + `,"\u006bind":"migrated-out"}`:                                                            "kind twice",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `,"more":1}`:                                                                         "a key a gate has not",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `}{}`:                                                                                "something follows it",
		`{"id":"gate-1","kind":"migrated-out",` + rest + "}\n":                                                                                "something follows it",
		`[{"id":"gate-1","kind":"migrated-out",` + rest + `}]`:                                                                                "not one JSON object",
		`{"id":"gate-1","kind":"migrated-out",` + rest:                                                                                        "not one JSON object",
		`{"id":"gate-1","kind":"migrated-out","phase":"paused","expiresAt":null}`:                                                             "it has no archiveId",
		`{"id":"gate-1","kind":"migrated-out","phase":"paused","archiveId":null}`:                                                             "it has no expiresAt",
		`{"id":"gate-1","kind":"migrated-out","phase":"paused","expiresAt":0,"archiveId":null}`:                                               "not the migration's own",
		`{"id":"gate-1","kind":"migrated-out","phase":"paused","expiresAt":null,"archiveId":"x"}`:                                             "not the migration's own",
		`{"id":"gate-1","kind":"migrated-out","phase":"paused","expiresAt":{},"archiveId":null}`:                                              "is not a value",
		`{"id":1,"kind":"migrated-out",` + rest + `}`:                                                                                         "id is not a text",
		`{"id":"gate-1","kind":["migrated-out"],` + rest + `}`:                                                                                "kind is not a text",
		`{"id":"","kind":"migrated-out",` + rest + `}`:                                                                                        "id is not a text",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `,"frozenPosition":"x"}`:                                                             "not a position",
		`{"id":"gate-1","kind":"migrated-out",` + rest + `,"frozenSnapshot":"x"}`:                                                             "not a snapshot",
		"{\"id\":\"gate-1\",\"kind\":\"migrated-out\"," + rest + ",\"frozenPosition\":\"4\xff\"}":                                             "not UTF-8",
		"\ufeff" + gateText: "not one JSON object",
		"null":              "not one JSON object",
		"":                  "",
	} {
		if text == "" {
			continue
		}
		if err := at(tarOf("maintenance.json", text, tar.TypeReg)); (err == nil) != (want == "") || err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
		// The same through migrate's own container.
		host := gatedHost()
		host.gates[stateVol.Name] = text
		cmp := stockCompose(t, &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}}})
		if err := cmp.CheckGate(t.Context(), gate1); (err == nil) != (want == "") || err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("%s, without a container: %v, want %q", text, err, want)
		}
	}
}

// The container whose gate was read is the one that starts, and the one
// that is the installation's after: one Compose makes on another volume, one
// made again meanwhile, a gate that went, are not started behind.
func TestTheCheckedContainerStarts(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(cmp *Compose, h *labelled, run *scripted)
		want string
		runs string // the container that runs after
	}{
		{"made, read and started", func(*Compose, *labelled, *scripted) {}, "", "made"},
		{"its gate gone once it is made", func(_ *Compose, h *labelled, run *scripted) {
			made := run.onRun
			run.onRun = func(key string) {
				if made(key); strings.Contains(key, "--no-start") {
					h.gates[stateVol.Name] = ""
				}
			}
		}, "holds no gate", ""},
		{"made with a part of the volume", func(_ *Compose, h *labelled, _ *scripted) {
			h.inspects = map[string]string{"made": `[] [{"Type":"volume","Name":"varlatch_varlatch-state","Destination":"/var/lib/varlatch","Driver":"local","RW":true}] [{"Type":"volume","Source":"varlatch_varlatch-state","Target":"/var/lib/varlatch","VolumeOptions":{"Subpath":"other"}}] null`}
		}, "a part of it", ""},
		{"deployed again before it starts", func(cmp *Compose, h *labelled, run *scripted) {
			reads := 0
			h.seen = func() {
				// After the read of the gate, the next listing.
				if h.reads == 1 {
					if reads++; reads == 1 {
						l := ownCtr(cmp, "varlatchd")
						l.id, l.status = "another", "running"
						h.containers = []composeContainer{l}
					}
				}
			}
		}, "was made again while it was started", "another"},
		{"the volume lost once it is made", func(_ *Compose, h *labelled, run *scripted) {
			made := run.onRun
			run.onRun = func(key string) {
				if made(key); strings.Contains(key, "--no-start") {
					v := stateVol
					v.CreatedAt = "2026-11-23T00:00:00Z"
					h.volumes[v.Name] = v
				}
			}
		}, "is not the one that carried the gate", ""},
		{"the volume lost before", func(_ *Compose, h *labelled, _ *scripted) { delete(h.volumes, stateVol.Name) }, "is not there", ""},
	} {
		host := gatedHost()
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose up ": {}}}
		cmp := stockCompose(t, run)
		run.onRun = makes(cmp, host, false)
		c.set(cmp, host, run)
		err := cmp.startGated(t.Context(), gate1, true)
		if (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		runs := ""
		for _, l := range host.containers {
			if l.status == "running" {
				runs += l.id
			}
		}
		if runs != c.runs {
			t.Errorf("%s: %q runs, want %q", c.name, runs, c.runs)
		}
		if c.name == "the volume lost before" && len(run.ran) > 1 {
			t.Errorf("%s: ran %q", c.name, run.ran)
		}
	}
	if err := stockCompose(t, &scripted{t: t}).startGated(t.Context(), GateRef{}, true); err == nil || !strings.Contains(err.Error(), "records no gate") {
		t.Errorf("no gate: %v", err)
	}
}

// An undo does not leave it to Compose to see that Postgres and Convex are
// on the fresh volumes (an earlier one does not): those containers go, by
// their ids, and nothing else.
func TestTheUndoOnAnOldCompose(t *testing.T) {
	plan := RebuildRecord{Override: OverrideFile, Owner: "mig_x", Volumes: []string{"varlatch_postgres-data-abcdefgh", "varlatch_convex-data-abcdefgh"}}
	for _, v := range stockVolumes {
		v.CreatedAt, v.Project = "2026-01-01T00:00:00Z", "varlatch"
		plan.Retained = append(plan.Retained, v)
	}
	for _, c := range []struct {
		name string
		old  bool
		set  func(h *labelled)
		want string
		rm   []string
	}{
		{"an old one", true, func(*labelled) {}, "", []string{"docker rm c-postgres-0", "docker rm c-convex-backend-1"}},
		{"a newer one", false, func(*labelled) {}, "", []string{"docker rm c-postgres-0", "docker rm c-convex-backend-1"}},
		{"Convex not rebuilt yet", true, func(h *labelled) { h.containers[1].mounts[0].Name = stockVolumes[1].Name }, "", []string{"docker rm c-postgres-0"}},
		{"on a volume of neither", true, func(h *labelled) { h.containers[0].mounts[0].Name = "theirs" }, "neither the volume from before the reverse", nil},
		{"the volume from before gone", true, func(h *labelled) { delete(h.volumes, stockVolumes[0].Name) }, "is not there", nil},
		{"the volume from before another", true, func(h *labelled) {
			v := h.volumes[stockVolumes[1].Name]
			v.CreatedAt = "2026-11-01T00:00:00Z"
			h.volumes[v.Name] = v
		}, "is not the one convex-backend was on", []string{"docker rm c-postgres-0"}},
	} {
		host := gatedHost()
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose up ": {}, "docker compose ps ": {},
			"docker compose run --rm -T --no-deps varlatchd admin migration status": {Answer: []byte(`{"gate":{"kind":"migrated-out","id":"gate-1"}}`)}}}
		cmp := stockCompose(t, run)
		run.onRun = makes(cmp, host, c.old)
		for i, d := range dataMounts {
			l := ownCtr(cmp, d.service)
			l.mounts = []containerMount{{Type: "volume", Name: plan.Volumes[i], Destination: d.target}}
			host.containers = append(host.containers, l)
			host.volumes[plan.Volumes[i]] = VolumeRecord{Name: plan.Volumes[i], Project: "varlatch", Owner: "mig_x"}
			host.volumes[stockVolumes[i].Name] = plan.Retained[i]
		}
		// A killed run's import, still going, and another service.
		imp := ctr("varlatch", importService, filepath.Join(cmp.Directory, "docker-compose.yml"), cmp.Directory, "True")
		imp.id = "import"
		host.containers = append(host.containers, imp, ownCtr(cmp, "varlatch-web"))
		c.set(host)
		err := cmp.UndoRebuild(t.Context(), plan, gate1, true)
		if (err == nil) != (c.want == "") || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		var rm []string
		for _, r := range run.ran {
			if strings.HasPrefix(r, "docker rm ") {
				rm = append(rm, r)
			}
		}
		if !slices.Equal(rm, c.rm) || run.ran[0] != "docker stop c-postgres-0 c-convex-backend-1 import" {
			t.Errorf("%s: %q", c.name, run.ran)
		}
		if removed := c.want == ""; removed != slices.Equal(host.removed, plan.Volumes) {
			t.Errorf("%s: removed %v", c.name, host.removed)
		}
		for _, l := range host.containers {
			if l.service == "varlatch-web" && l.status != "" {
				t.Errorf("%s: the dashboard was %s", c.name, l.status)
			}
		}
	}
	// What Compose did is held, not taken from its exit status: nothing made,
	// or still on the reverse's volume.
	for _, left := range []string{"", plan.Volumes[0]} {
		host := gatedHost()
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config ": {Answer: []byte(stockConfig)}, "docker compose up ": {}}}
		cmp := stockCompose(t, run)
		for i, d := range dataMounts {
			host.volumes[stockVolumes[i].Name] = plan.Retained[i]
			l := ownCtr(cmp, d.service)
			l.mounts = []containerMount{{Type: "volume", Name: stockVolumes[i].Name, Destination: d.target}}
			host.containers = append(host.containers, l)
		}
		run.onRun = func(key string) {
			if !strings.HasPrefix(key, "docker compose up ") {
				return
			}
			if host.containers[0].mounts[0].Name = left; left == "" {
				host.containers = host.containers[1:]
			}
		}
		if err := cmp.restoreVolumes(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "postgres did not go back to the volume from before the reverse") {
			t.Errorf("left on %q: %v", left, err)
		}
	}
	// What does not stop is said, not taken for stopped.
	host := gatedHost()
	run := &scripted{t: t, host: host}
	cmp := stockCompose(t, run)
	l := ownCtr(cmp, "varlatchd")
	l.name, l.status = "the-server", "running"
	host.containers = []composeContainer{l}
	host.acted = func(string, string) { host.containers[0].status = "restarting" }
	if err := cmp.StopServers(t.Context()); err == nil || !strings.Contains(err.Error(), "the-server did not stop") {
		t.Errorf("not stopped: %v", err)
	}
	host.acted = nil
	if err := cmp.StopServers(t.Context()); err != nil || host.containers[0].status != "exited" {
		t.Errorf("stopped: %v", err)
	}
}

// The undo's order: the gate first, Go's barrier last, and only while the
// gate is held; a warning before what it warns of, journalled.
func TestTheUndosOrder(t *testing.T) {
	for _, c := range []struct {
		phase Phase
		kind  Ingress
		want  []string
	}{
		{Rollback, Public, []string{"hold gate-1", "undo p_postgres-data-abcdefgh", "held gate-1", "held gate-1", "lift"}},
		{RollbackChecked, Coolify, []string{"hold gate-1", "stop front", "undo p_postgres-data-abcdefgh", "stop front", "held gate-1", "held gate-1", "lift"}},
		{RollbackTransfer, Public, []string{"hold gate-1", "stop serving", "undo p_postgres-data-abcdefgh", "stop front", "held gate-1", "held gate-1", "lift"}},
		{RollbackTransfer, Coolify, []string{"hold gate-1", "stop serving", "stop front", "undo p_postgres-data-abcdefgh", "stop front", "held gate-1", "held gate-1", "lift"}},
	} {
		w, src, _ := rolledWorld(t, c.phase, c.kind)
		tgt := w.eng.Target.(*reverseTargetFake)
		tgt.onRelease = func() { src.do("lift") }
		if _, err := w.eng.Abort(t.Context()); err != nil || !slices.Equal(src.did, c.want) || !src.started {
			t.Errorf("%s, %s: %v: %v, want %v", c.phase, c.kind, err, src.did, c.want)
		}
	}
	// A sidecar the forward handoff stopped: its server is not started.
	w, src, j := rolledWorld(t, RollbackChecked, Coolify)
	j.Tailnet = &TailnetRecord{Handoff: &tailhandoff.State{Phase: tailhandoff.Done}}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	up := true
	fs := &sidecarFake{routedFake: routedFake{src}, up: &up}
	w.eng.Source = fs
	if _, err := w.eng.Abort(t.Context()); err != nil || src.started || !fs.stopped {
		t.Errorf("the sidecar's: %v, started %v, the sidecar stopped %v", err, src.started, fs.stopped)
	}
}

// The gate that cannot be held: nothing of the TypeScript side is started or
// put back, and Go's barrier stands, said with what to do; --resume and
// --abort try again.
func TestTheUndoNeedsTheGateHeld(t *testing.T) {
	lost := errors.New("the volume is not of its project")
	for _, kind := range []Ingress{Coolify, Public} {
		for _, phase := range []Phase{RollbackImported, RollbackTransfer} {
			w, src, j := rolledWorld(t, phase, kind)
			tgt := w.eng.Target.(*reverseTargetFake)
			j.Rollback.Barrier = &BarrierRecord{}
			if err := writeJournal(w.src.dir, j); err != nil {
				t.Fatal(err)
			}
			src.holdErr = lost
			want := []string{"hold gate-1"}
			if phase != RollbackTransfer {
				want = append(want, "stop servers")
				if kind == Coolify {
					want = append(want, "stop front")
				}
			}
			for _, how := range []string{"--abort", "--resume", "--abort"} {
				src.did = nil
				var err error
				if how == "--abort" {
					_, err = w.eng.Abort(t.Context())
				} else {
					_, err = w.eng.Resume(t.Context())
				}
				for _, said := range []string{lost.Error(), "Go stays behind its barrier: the outage goes on, and no data is lost", "nothing of it was started", "Do not start the TypeScript installation", "By hand: ", "varlatch migrate --resume"} {
					if err == nil || !strings.Contains(err.Error(), said) {
						t.Errorf("%s, %s, %s: %v, want %q", kind, phase, how, err, said)
					}
				}
				if after, _ := readJournal(w.src.dir); !slices.Equal(src.did, want) || tgt.released != 0 || after.Phase != phase || !after.Rollback.Undoing {
					t.Errorf("%s, %s, %s: %v, lifted %d, phase %s", kind, phase, how, src.did, tgt.released, after.Phase)
				}
			}
			src.holdErr = nil
			if _, err := w.eng.Abort(t.Context()); err != nil || tgt.released != 1 {
				t.Errorf("%s, %s: held again: %v", kind, phase, err)
			}
		}
	}
	// Held at first, not when Go's barrier is to be lifted: before its
	// journal says open, and right before the lift.
	for n, phase := range map[int]Phase{1: RollbackImported, 2: Open} {
		w, src, j := rolledWorld(t, RollbackImported, Coolify)
		tgt := w.eng.Target.(*reverseTargetFake)
		j.Rollback.Barrier = &BarrierRecord{}
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		src.heldErr = func(i int) error {
			if i == n {
				return lost
			}
			return nil
		}
		_, err := w.eng.Abort(t.Context())
		after, _ := readJournal(w.src.dir)
		if phase != Open && (err == nil || !errors.Is(err, lost)) || tgt.released != 0 || after.Phase != phase {
			t.Errorf("check %d: %v, lifted %d, phase %s", n, err, tgt.released, after.Phase)
		}
		// --resume lifts it only when it is held.
		w.tgt.barrier = "paused"
		src.heldErr = func(int) error { return lost }
		if _, err := w.eng.Resume(t.Context()); !errors.Is(err, lost) || tgt.released != 0 {
			t.Errorf("check %d, --resume: %v, lifted %d", n, err, tgt.released)
		}
		src.heldErr = nil
		if _, err := w.eng.Resume(t.Context()); tgt.released != 1 {
			t.Errorf("check %d, --resume once held: %v, lifted %d", n, err, tgt.released)
		}
	}
	// Before Go's barrier was asked for, there is none to lift.
	w, src, j := rolledWorld(t, Rollback, Coolify)
	j.Rollback = &RollbackRecord{Started: []string{"postgres"}}
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	src.holdErr = lost
	if _, err := w.eng.Abort(t.Context()); !errors.Is(err, lost) || !strings.Contains(err.Error(), "Go goes on as it was") {
		t.Errorf("before the barrier: %v", err)
	}
}

// Go's outage does not wait for the TypeScript side's recovery: its gate
// held, Go opens and its barrier is lifted; --resume (or --abort) puts the
// rest back, and no reverse and no --finish begins before.
func TestTheUndoEndsGosOutage(t *testing.T) {
	stuck := errors.New("postgres did not go back")
	for _, kind := range []Ingress{Coolify, Public} {
		for _, how := range []string{"--resume", "--abort"} {
			w, src, _ := rolledWorld(t, RollbackChecked, kind)
			tgt := w.eng.Target.(*reverseTargetFake)
			src.undoErr = stuck
			// Said and journalled before Go opens.
			tgt.onRelease = func() {
				at, _ := readJournal(w.src.dir)
				if !strings.Contains(strings.Join(w.said, "\n"), "The TypeScript installation is not put back") || !strings.Contains(at.Rollback.Unrestored, stuck.Error()) {
					t.Errorf("%s: lifted before it was said (%v) and journalled (%q)", kind, w.said, at.Rollback.Unrestored)
				}
				src.do("lift")
			}
			_, err := w.eng.Abort(t.Context())
			after, _ := readJournal(w.src.dir)
			want := []string{"hold gate-1", "undo p_postgres-data-abcdefgh", "stop servers", "held gate-1", "held gate-1", "lift"}
			if kind == Coolify {
				want = []string{"hold gate-1", "stop front", "undo p_postgres-data-abcdefgh", "stop front", "stop servers", "held gate-1", "held gate-1", "lift"}
			}
			if err == nil || !strings.Contains(err.Error(), "is not put back") || !strings.Contains(err.Error(), "Do not start it") || after.Phase != Open || tgt.released != 1 || !strings.Contains(after.Rollback.Unrestored, stuck.Error()) ||
				after.Rollback.Undoing || !after.Rollback.Undone.Released || !slices.Equal(src.did, want) || !w.tgt.running {
				t.Fatalf("%s: %v: %+v, %v, lifted %d", kind, err, after.Rollback, src.did, tgt.released)
			}
			src.did = nil
			if _, err := w.eng.Rollback(t.Context()); err == nil || !strings.Contains(err.Error(), "varlatch migrate --resume first") || len(src.did) != 0 {
				t.Errorf("%s: another reverse: %v %v", kind, err, src.did)
			}
			w.eng.Source = &finishFake{reverseFake: src}
			if _, err := w.eng.Finish(t.Context(), true); err == nil || !strings.Contains(err.Error(), "varlatch migrate --resume first") || len(src.did) != 0 {
				t.Errorf("%s: --finish: %v %v", kind, err, src.did)
			}
			w.eng.Source = src
			again := func() error {
				var err error
				if how == "--abort" {
					_, err = w.eng.Abort(t.Context())
				} else {
					_, err = w.eng.Resume(t.Context())
				}
				return err
			}
			if err := again(); !errors.Is(err, stuck) || !strings.Contains(err.Error(), "Go serves") || !slices.Equal(src.did, []string{"held gate-1", "undo p_postgres-data-abcdefgh", "stop servers"}) || tgt.released != 1 {
				t.Errorf("%s, %s, still stuck: %v %v", kind, how, err, src.did)
			}
			// Not held by then: nothing is started.
			lost := errors.New("the volume holds no gate")
			src.did, src.heldErr = nil, func(int) error { return lost }
			if err := again(); !errors.Is(err, lost) || !slices.Equal(src.did, []string{"held gate-1"}) {
				t.Errorf("%s, %s, not held: %v %v", kind, how, err, src.did)
			}
			src.did, src.undoErr, src.heldErr = nil, nil, nil
			if err := again(); err != nil || !slices.Equal(src.did, []string{"held gate-1", "undo p_postgres-data-abcdefgh"}) {
				t.Errorf("%s, %s: %v %v", kind, how, err, src.did)
			}
			if after, _ := readJournal(w.src.dir); after.Rollback.Unrestored != "" || after.Phase != Open {
				t.Errorf("%s, %s: after: %+v", kind, how, after.Rollback)
			}
		}
	}
	// Journalled before it is said: killed there, the next run knows.
	w, src, _ := rolledWorld(t, RollbackImported, Coolify)
	src.undoErr = stuck
	said, say := 0, w.eng.Options.Say
	w.eng.Options.Say = func(text string) {
		say(text)
		if at, _ := readJournal(w.src.dir); strings.Contains(text, "is not put back") {
			if said++; !strings.Contains(at.Rollback.Unrestored, stuck.Error()) || at.Phase == Open {
				t.Errorf("said in phase %s with %q journalled", at.Phase, at.Rollback.Unrestored)
			}
		}
	}
	_, err := w.eng.Abort(t.Context())
	if err == nil || said != 1 {
		t.Errorf("%v, said %d times", err, said)
	}
	// Through --resume of an interrupted reverse: said, with what not to do.
	w, src, _ = rolledWorld(t, RollbackImported, Coolify)
	src.undoErr = stuck
	_, err = w.eng.Resume(t.Context())
	for _, want := range []string{"the reverse was undone: Go runs and takes requests again", "is not put back", stuck.Error(), "it is behind its gate, and its server is stopped", "Do not start it", "varlatch migrate --resume puts it back"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v, want %q", err, want)
		}
	}
}

// What an undo's steps left counts, not what an earlier one said: a stop
// that failed at first (the reverse's Compose file gone, say) and is so by
// the end does not keep Go behind its barrier; one that is not does.
func TestTheUndoCountsWhatIsSo(t *testing.T) {
	failed := errors.New("open docker-compose.varlatch-rollback.yml: no such file or directory")
	for _, phase := range []Phase{RollbackTransfer, RollbackChecked} {
		for _, kind := range []Ingress{Coolify, Public, Proxy} {
			if phase == RollbackChecked && kind != Coolify {
				continue
			}
			w, src, _ := rolledWorld(t, phase, kind)
			tgt := w.eng.Target.(*reverseTargetFake)
			src.servingErr = failed
			if kind == Coolify {
				src.frontErrs = []error{failed, nil}
			}
			if _, err := w.eng.Abort(t.Context()); err != nil || tgt.released != 1 {
				t.Errorf("%s, %s: %v, lifted %d", phase, kind, err, tgt.released)
			}
			w, src, _ = rolledWorld(t, phase, kind)
			tgt = w.eng.Target.(*reverseTargetFake)
			src.frontErrs = []error{failed, failed, failed}
			if _, err := w.eng.Abort(t.Context()); !errors.Is(err, failed) && !strings.Contains(fmt.Sprint(err), failed.Error()) || tgt.released != 0 {
				t.Errorf("%s, %s, still: %v, lifted %d", phase, kind, err, tgt.released)
			}
		}
	}
}

// What waiting does not change is not waited for: a program that is not
// there or not to be run, an installation that is another's. A network's
// refusal, even a forbidden one, is.
func TestPermanent(t *testing.T) {
	dir := t.TempDir()
	noExec, script := filepath.Join(dir, "closed"), filepath.Join(dir, "garbage")
	for p, mode := range map[string]os.FileMode{noExec: 0o600, script: 0o700} {
		if err := os.WriteFile(p, []byte("\x00not a program"), mode); err != nil {
			t.Fatal(err)
		}
	}
	for name, program := range map[string]string{"not there": filepath.Join(dir, "none"), "not on the path": "vl-no-such-program", "not to be executed": noExec, "not a program": script, "a directory": dir} {
		if _, err := (ExecRunner{}).Run(t.Context(), "", program, nil, nil); err == nil || !permanent(err) || !permanent(fmt.Errorf("asking: %w", err)) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := (ExecRunner{}).Stream(t.Context(), "", program, nil, nil, io.Discard); err == nil || !permanent(err) {
			t.Errorf("%s, streamed: %v", name, err)
		}
	}
	if !permanent(fmt.Errorf("x: %w", &ProjectChangedError{})) {
		t.Error("another installation")
	}
	for name, err := range map[string]error{
		"a failure":           errors.New("exit 1"),
		"a forbidden network": &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EACCES)},
		"no more processes":   &StartError{Name: "x", Err: syscall.EAGAIN},
		"the deadline":        context.DeadlineExceeded,
		"no":                  nil,
	} {
		if permanent(err) {
			t.Errorf("%s", name)
		}
	}
	// The wait for the source's server.
	w := newTailnetWorld(t)
	w.src.running = true
	w.src.fail = map[string]error{"gate": &StartError{Name: "docker", Err: fs.ErrNotExist}}
	start := w.src.clock.now()
	if err := w.eng.sourceAnswers(t.Context()); err == nil || w.src.clock.now() != start {
		t.Errorf("%v after %s", err, w.src.clock.now().Sub(start))
	}
	// The reach probe: its exit status says which.
	for code, want := range map[int]bool{exitConfig: true, 1: false} {
		h := &Host{Varlatchd: "varlatchd", Run: &scripted{t: t, answers: map[string]Ran{"varlatchd admin tailnet reaches": {Code: code, Said: []byte("permission denied")}}}}
		var perm *tailhandoff.PermanentError
		if _, err := h.TailnetReaches(t.Context(), "vault", "n1", time.Second); err == nil || errors.As(err, &perm) != want || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("exit %d: %v", code, err)
		}
	}
	h := &Host{Varlatchd: filepath.Join(dir, "none"), Run: ExecRunner{}}
	var perm *tailhandoff.PermanentError
	if _, err := h.TailnetReaches(t.Context(), "vault", "n1", time.Second); !errors.As(err, &perm) {
		t.Errorf("no varlatchd: %v", err)
	}
}

// The image's user's programs are given an environment of their own: its
// temporary directory and home are one migrate made for it, held to be
// writable before anything; nothing of the user migrate runs as.
func TestTheImagesEnvironment(t *testing.T) {
	env := imageEnv([]string{"PATH=/bin", "HOME=/root", "TMPDIR=/tmp/user/0", "XDG_RUNTIME_DIR=/run/user/0", "USER=root", "SSL_CERT_FILE=/r.pem", "https_proxy=http://p:1", "NO_PROXY=x", "VARLATCH_X=1", "MAIL=/x", "TZ=UTC"}, "/own")
	if want := []string{"HOME=/own", "TMPDIR=/own", "PATH=/bin", "SSL_CERT_FILE=/r.pem", "https_proxy=http://p:1", "NO_PROXY=x", "VARLATCH_X=1", "TZ=UTC"}; !slices.Equal(env, want) {
		t.Errorf("%q", env)
	}
	me := Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	root := t.TempDir()
	data, keys, conf := filepath.Join(root, "data"), filepath.Join(root, "keys"), filepath.Join(root, "varlatchd.conf")
	for _, d := range []string{data, keys} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(conf, []byte("root_kek_file = /keys/root-kek\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, "varlatchd")
	const state = `{"journal":null,"database":false,"dataDir":"/x","release":"0.50.0","publicUrl":"https://vault.example.test","listen":"x","listenHttps":"","migrationGate":false,"running":false}`
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"$TMPDIR $HOME $PWD\" >> "+filepath.Join(root, "seen")+"\necho '"+state+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	img := &Image{Host: &Host{Varlatchd: fake, Run: ExecRunner{Env: []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=/closed", "HOME=/closed"}, As: &me}}, Service: "varlatch-go",
		Ref: "ghcr.io/varlatch/varlatchd:0.50.0@sha256:" + hexOf(randomBytes(32)), DataDir: data, KeysDir: keys, ServiceConfig: conf, User: me}
	stage := t.TempDir()
	cleanup, err := PrepareImage(t.Context(), img, stage, true)
	defer cleanup()
	seen, _ := os.ReadFile(filepath.Join(root, "seen"))
	own := filepath.Join(filepath.Dir(img.Host.Config), "tmp")
	if err != nil || string(seen) != own+" "+own+" /\n" {
		t.Errorf("%v: %q, want %s", err, seen, own)
	}
	if st, err := os.Stat(own); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("%v %v", st, err)
	}
	// One it cannot write in: refused, nothing of the target asked.
	if os.Getuid() == 0 {
		return
	}
	_ = os.Remove(filepath.Join(root, "seen"))
	sh := filepath.Join(root, "sh")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\necho 'Permission denied' >&2; exit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
	img.Host.Run = ExecRunner{As: &me}
	again, err := PrepareImage(t.Context(), img, stage, true)
	defer again()
	if _, serr := os.Stat(filepath.Join(root, "seen")); err == nil || !strings.Contains(err.Error(), "cannot write in") || !strings.Contains(err.Error(), "TMPDIR set to a directory every user can pass through") || !os.IsNotExist(serr) {
		t.Errorf("%v, asked %v", err, serr)
	}
}

// The sidecar's certificate is asked for once it has heard of its name: a
// node just renamed may not have, and would refuse it each time. Never for a
// name it does not hear of.
func TestTheCertificateWaitsForTheName(t *testing.T) {
	was := certNameWait
	defer func() { certNameWait = was }()
	for _, c := range []struct{ after, wait, asked int }{{0, 3, 1}, {1, 3, 1}, {9, 2, 0}} {
		dir := t.TempDir()
		certNameWait = c.wait
		script := ""
		run := &scripted{t: t, answers: map[string]Ran{"docker compose exec -T tailscale sh -c ": {}}}
		if err := stockCompose(t, run).RenewTailnetCert(t.Context(), "vault.x.ts.net", time.Hour); err != nil {
			t.Fatal(err)
		}
		script = strings.TrimPrefix(run.ran[0], "docker compose exec -T tailscale sh -c ")
		fake := `#!/bin/sh
echo "$@" >> "` + dir + `/calls"
case "$1" in
status) n=$(grep -c '^status' "` + dir + `/calls"); [ "$n" -gt ` + fmt.Sprint(c.after) + ` ] && echo '{"Self":{"DNSName":"vault.x.ts.net."},"CertDomains":["vault.x.ts.net"]}' || echo '{"Self":{"DNSName":"vault.x.ts.net."},"CertDomains":["vault-o.x.ts.net"]}' ;;
esac
`
		if err := os.WriteFile(filepath.Join(dir, "tailscale"), []byte(fake), 0o700); err != nil {
			t.Fatal(err)
		}
		r, err := ExecRunner{Env: []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "TMPDIR=" + dir}}.Run(t.Context(), dir, "sh", []string{"-c", script}, nil)
		calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
		asked := strings.Count(string(calls), "cert --min-validity")
		if err != nil || (r.Code == 0) != (c.asked == 1) || asked != c.asked || c.asked == 0 && !strings.Contains(string(r.Said), "is not named vault.x.ts.net yet") {
			t.Errorf("after %d: %v %+v, asked %d: %s", c.after, err, r.Code, asked, calls)
		}
	}
}
