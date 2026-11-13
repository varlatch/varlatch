// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"time"
)

// Plan is one G9a run: the load phases in order, the backups started
// during them, the converge period and the thresholds. The server and the
// k6 script both read the same plan file, and the report judges the run by
// it.
type Plan struct {
	Phases []Phase `json:"phases"`
	// Backups start at an offset into a named phase.
	Backups []Backup `json:"backups"`
	// ConvergeEverySeconds is the period of the simulated converge run,
	// counted from the start of the run.
	ConvergeEverySeconds float64 `json:"convergeEverySeconds"`
	Targets              int     `json:"targets"`
	// WALBound is the checkpointer's bound in bytes: the shipped one
	// (storage.DefaultWALBound) for a gate run.
	WALBound int64 `json:"walBound"`
	// ProbeIntervalMs paces the fsync probe that runs through the load.
	ProbeIntervalMs int `json:"probeIntervalMs"`
	// BackupStepPages and BackupPauseMs pace the snapshot (0: the engine's
	// defaults, which a gate run uses). A smoke run slows its backups so
	// that they overlap the bound.
	BackupStepPages int `json:"backupStepPages,omitempty"`
	BackupPauseMs   int `json:"backupPauseMs,omitempty"`
	// IdleProbeSeconds is the fsync probe before the load starts.
	IdleProbeSeconds float64    `json:"idleProbeSeconds"`
	Thresholds       Thresholds `json:"thresholds"`
}

// Phase is a constant arrival rate for a duration. A warm-up phase runs the
// same load but is not judged.
type Phase struct {
	Name    string  `json:"name"`
	Rate    int     `json:"rate"`
	Seconds float64 `json:"seconds"`
	Warmup  bool    `json:"warmup,omitempty"`
}

// Backup starts a paced snapshot AtSeconds into Phase.
type Backup struct {
	Phase     string  `json:"phase"`
	AtSeconds float64 `json:"atSeconds"`
}

// Thresholds are G9a's pass criteria that are numbers.
type Thresholds struct {
	// P95Ms is the most a phase's (and a window's) p95 retrieval may take.
	P95Ms float64 `json:"p95Ms"`
	// MemoryMiB is the most the cgroup's anon memory may reach after the
	// first minute (G9's steady memory).
	MemoryMiB float64 `json:"memoryMiB"`
	// MemoryAfterSeconds is when the memory criterion starts to apply.
	MemoryAfterSeconds float64 `json:"memoryAfterSeconds"`
	// WALPeakFactor times WALBound is the WAL size never to be reached.
	WALPeakFactor float64 `json:"walPeakFactor"`
	// WindowPadSeconds widens each TRUNCATE and backup window on both sides.
	WindowPadSeconds float64 `json:"windowPadSeconds"`
}

// DefaultPlan is ADR-0059's G9a load profile: a minute of warm-up at 10/s,
// then 10/s for 15 minutes with a backup in it, 30/s for 5 minutes, and
// 50/s for 15 minutes with a backup starting in its middle; a converge run
// a minute for 20 targets; the shipped WAL bound.
func DefaultPlan() Plan {
	return Plan{
		Phases: []Phase{
			{Name: "warmup", Rate: 10, Seconds: 60, Warmup: true},
			{Name: "p10", Rate: 10, Seconds: 900},
			{Name: "p30", Rate: 30, Seconds: 300},
			{Name: "p50", Rate: 50, Seconds: 900},
		},
		Backups:              []Backup{{Phase: "p10", AtSeconds: 420}, {Phase: "p50", AtSeconds: 450}},
		ConvergeEverySeconds: 60,
		Targets:              20,
		WALBound:             64 << 20,
		ProbeIntervalMs:      100,
		IdleProbeSeconds:     30,
		Thresholds: Thresholds{
			P95Ms:              100,
			MemoryMiB:          300,
			MemoryAfterSeconds: 60,
			WALPeakFactor:      2,
			WindowPadSeconds:   1,
		},
	}
}

// Scaled returns the plan with every duration and offset multiplied by f
// (for smoke runs; f < 1). Rates, thresholds and the bound are unchanged.
// The converge period keeps at least 10 s (a run takes a few seconds and
// must not overlap the next) and the idle probe at least 5 s.
func (p Plan) Scaled(f float64) Plan {
	q := p
	q.Phases = append([]Phase(nil), p.Phases...)
	for i := range q.Phases {
		q.Phases[i].Seconds = math.Round(q.Phases[i].Seconds*f*1000) / 1000
	}
	q.Backups = append([]Backup(nil), p.Backups...)
	for i := range q.Backups {
		q.Backups[i].AtSeconds = math.Round(q.Backups[i].AtSeconds*f*1000) / 1000
	}
	q.ConvergeEverySeconds = max(10, math.Round(p.ConvergeEverySeconds*f*1000)/1000)
	q.IdleProbeSeconds = max(5, math.Round(p.IdleProbeSeconds*f*1000)/1000)
	q.Thresholds.MemoryAfterSeconds = math.Round(p.Thresholds.MemoryAfterSeconds*f*1000) / 1000
	return q
}

// Validate refuses a plan the harness cannot run or judge.
func (p Plan) Validate() error {
	if len(p.Phases) == 0 {
		return errors.New("plan: no phases")
	}
	names := map[string]Phase{}
	judged := 0
	for _, ph := range p.Phases {
		if ph.Name == "" || ph.Rate <= 0 || ph.Seconds <= 0 {
			return fmt.Errorf("plan: phase %q needs a name, a rate and a duration", ph.Name)
		}
		if _, dup := names[ph.Name]; dup {
			return fmt.Errorf("plan: phase %q twice", ph.Name)
		}
		names[ph.Name] = ph
		if !ph.Warmup {
			judged++
		}
	}
	if judged == 0 {
		return errors.New("plan: every phase is a warm-up")
	}
	for _, b := range p.Backups {
		ph, ok := names[b.Phase]
		if !ok {
			return fmt.Errorf("plan: backup in unknown phase %q", b.Phase)
		}
		if b.AtSeconds < 0 || b.AtSeconds >= ph.Seconds {
			return fmt.Errorf("plan: backup at %gs is outside phase %q (%gs)", b.AtSeconds, b.Phase, ph.Seconds)
		}
	}
	switch {
	case p.ConvergeEverySeconds <= 0:
		return errors.New("plan: convergeEverySeconds must be positive")
	case p.Targets <= 0:
		return errors.New("plan: targets must be positive")
	case p.WALBound <= 0:
		return errors.New("plan: walBound must be positive")
	case p.ProbeIntervalMs <= 0:
		return errors.New("plan: probeIntervalMs must be positive")
	case p.BackupStepPages < 0 || p.BackupPauseMs < 0:
		return errors.New("plan: backup pacing must not be negative")
	case p.IdleProbeSeconds < 3:
		return errors.New("plan: idleProbeSeconds must be at least 3 (a p99 needs 100 samples of each kind)")
	case p.Thresholds.P95Ms <= 0 || p.Thresholds.MemoryMiB <= 0 || p.Thresholds.WALPeakFactor <= 0:
		return errors.New("plan: thresholds must be positive")
	}
	return nil
}

// gatePlan is the profile a run must follow to count for G9a (a variable so
// that tests can judge short runs as gate runs).
var gatePlan = DefaultPlan

// NotGate lists how p differs from G9a's profile; empty means a run of it
// can count for the gate. The fsync probe's pacing may differ.
func (p Plan) NotGate() []string {
	g := gatePlan()
	var d []string
	if !slices.Equal(p.Phases, g.Phases) {
		d = append(d, "phases")
	}
	if !slices.Equal(p.Backups, g.Backups) || p.BackupStepPages != g.BackupStepPages || p.BackupPauseMs != g.BackupPauseMs {
		d = append(d, "backups")
	}
	if p.ConvergeEverySeconds != g.ConvergeEverySeconds || p.Targets != g.Targets {
		d = append(d, "converge")
	}
	if p.WALBound != g.WALBound {
		d = append(d, "WAL bound")
	}
	if p.Thresholds != g.Thresholds {
		d = append(d, "thresholds")
	}
	return d
}

// Converges is how many converge runs the plan schedules during the load
// (one every period, the last before the load ends).
func (p Plan) Converges() int {
	period, n := seconds(p.ConvergeEverySeconds), 0
	for t := period; t < p.Duration(); t += period {
		n++
	}
	return n
}

// PhaseStart is the offset of a phase from the start of the run.
func (p Plan) PhaseStart(name string) (time.Duration, bool) {
	var at float64
	for _, ph := range p.Phases {
		if ph.Name == name {
			return seconds(at), true
		}
		at += ph.Seconds
	}
	return 0, false
}

// Duration is the whole load.
func (p Plan) Duration() time.Duration {
	var s float64
	for _, ph := range p.Phases {
		s += ph.Seconds
	}
	return seconds(s)
}

// BackupOffsets are the backups' offsets from the start of the run.
func (p Plan) BackupOffsets() []time.Duration {
	var out []time.Duration
	for _, b := range p.Backups {
		start, _ := p.PhaseStart(b.Phase)
		out = append(out, start+seconds(b.AtSeconds))
	}
	return out
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// ReadPlan reads and validates a plan file.
func ReadPlan(path string) (Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return Plan{}, fmt.Errorf("plan %s: %w", path, err)
	}
	return p, p.Validate()
}

// WritePlan writes a plan file (indented, for people and k6).
func WritePlan(path string, p Plan) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
