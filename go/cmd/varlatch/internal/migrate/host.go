// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Host is a host install of varlatchd, the migration's target (go-step7
// decision 20's first shape): its varlatchd and its configuration, driven
// through `varlatchd admin migrate` (slices 7.3a, 7.3b, 7.4a), offline,
// before the service is started.
type Host struct {
	// Varlatchd is the varlatchd program; Config its varlatchd.conf.
	Varlatchd string
	Config    string
	Run       Runner
	// Unit is the target's systemd unit ("varlatchd"), started and
	// stopped around the address transfer.
	Unit string
}

func (h *Host) unit() string {
	if h.Unit == "" {
		return "varlatchd"
	}
	return h.Unit
}

// unitName is a systemd unit's name as systemctl takes it as an argument:
// no option (a leading -), no path.
var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.\\@][A-Za-z0-9:_.\\@-]*$`)

// ValidUnit says whether name may be given to systemctl as a unit.
func ValidUnit(name string) bool { return len(name) <= 256 && unitName.MatchString(name) }

// Start is `systemctl start <unit>`.
func (h *Host) Start(ctx context.Context) error { return h.systemctl(ctx, "start") }

// Stop is `systemctl stop <unit>`.
func (h *Host) Stop(ctx context.Context) error { return h.systemctl(ctx, "stop") }

func (h *Host) systemctl(ctx context.Context, verb string) error {
	if !ValidUnit(h.unit()) {
		return fmt.Errorf("%q is not a systemd unit's name", h.unit())
	}
	r, err := h.Run.Run(ctx, "", "systemctl", []string{verb, h.unit()}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("systemctl "+verb+" "+h.unit(), r)
	}
	return nil
}

func (h *Host) admin(ctx context.Context, args []string, stdin []byte) (Ran, error) {
	full := append([]string{"admin", "migrate"}, args...)
	if h.Config != "" {
		full = append(full, "--config", h.Config)
	}
	return h.Run.Run(ctx, "", h.Varlatchd, full, stdin)
}

// Describe is `admin migrate state`.
func (h *Host) Describe(ctx context.Context) (TargetInfo, TargetState, error) {
	info := TargetInfo{Config: h.Config}
	r, err := h.admin(ctx, []string{"state"}, nil)
	if err != nil {
		return info, TargetState{}, err
	}
	if r.Code != 0 {
		return info, TargetState{}, failure("varlatchd admin migrate state", r)
	}
	var s struct {
		Journal     *JournalHead `json:"journal"`
		Database    bool         `json:"database"`
		DataDir     string       `json:"dataDir"`
		Release     string       `json:"release"`
		PublicURL   string       `json:"publicUrl"`
		Listen      string       `json:"listen"`
		ListenHTTPS string       `json:"listenHttps"`
		Gate        *bool        `json:"migrationGate"`
		Running     bool         `json:"running"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &s); err != nil || s.DataDir == "" {
		return info, TargetState{}, errors.New("varlatchd admin migrate state did not answer in JSON")
	}
	if s.Release == "" || s.Gate == nil {
		return info, TargetState{}, errors.New("the target's varlatchd is older than this varlatch (its admin migrate state names no release, address or gate): install the varlatchd of this release")
	}
	info.DataDir, info.Release, info.PublicURL, info.Listen, info.ListenHTTPS = s.DataDir, s.Release, s.PublicURL, s.Listen, s.ListenHTTPS
	return info, TargetState{Journal: s.Journal, Database: s.Database, Gate: *s.Gate, Running: s.Running}, nil
}

// Keys is `admin migrate keys`, the keys on its stdin as JSON, each
// file's bytes in base64 (so no copy of a key is an uncleared string here).
func (h *Host) Keys(ctx context.Context, rootKEK, bek []byte) (string, string, error) {
	b, err := json.Marshal(struct {
		RootKEK []byte `json:"rootKek"`
		BEK     []byte `json:"bek,omitempty"`
	}{rootKEK, bek})
	if err != nil {
		return "", "", err
	}
	defer clear(b)
	r, err := h.admin(ctx, []string{"keys"}, b)
	if err != nil {
		return "", "", err
	}
	if r.Code != 0 {
		return "", "", failure("varlatchd admin migrate keys", r)
	}
	var s struct {
		RootKEK string `json:"rootKek"`
		BEK     string `json:"bek"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &s); err != nil {
		return "", "", errors.New("varlatchd admin migrate keys did not answer in JSON")
	}
	return s.RootKEK, s.BEK, nil
}

// WriteJournal is `admin migrate state --write`, the journal on stdin.
func (h *Host) WriteJournal(ctx context.Context, j *Journal) error {
	b, err := j.Encode()
	if err != nil {
		return err
	}
	r, err := h.admin(ctx, []string{"state", "--write"}, b)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("varlatchd admin migrate state --write", r)
	}
	return nil
}

func scratchArgs(scratch string) []string {
	if scratch == "" {
		return nil
	}
	return []string{"--scratch", scratch}
}

// Import is `admin migrate import --json`.
func (h *Host) Import(ctx context.Context, bundle, scratch string) (CopyRecord, error) {
	r, err := h.admin(ctx, append([]string{"import", "--in", bundle, "--json"}, scratchArgs(scratch)...), nil)
	if err != nil {
		return CopyRecord{}, err
	}
	if r.Code != 0 {
		return CopyRecord{}, failure("varlatchd admin migrate import", r)
	}
	var s struct {
		InstallationID     string `json:"installationId"`
		Tables             int64  `json:"tables"`
		Rows               int64  `json:"rows"`
		SessionsEnded      int64  `json:"sessionsEnded"`
		CredentialsRevoked int64  `json:"credentialsRevoked"`
		MigratedPosition   int64  `json:"migratedPosition"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &s); err != nil || s.InstallationID == "" {
		return CopyRecord{}, errors.New("varlatchd admin migrate import did not answer in JSON")
	}
	return CopyRecord{InstallationID: s.InstallationID, Tables: s.Tables, Rows: s.Rows, SessionsEnded: s.SessionsEnded,
		CredsRevoked: s.CredentialsRevoked, MigratedPosition: s.MigratedPosition}, nil
}

// Check is `admin migrate check --json`, the run key on its stdin. A
// report that fails is a CheckSummary not passed, not an error.
func (h *Host) Check(ctx context.Context, bundle, scratch string, runKey []byte) (CheckSummary, error) {
	key := RunKeyText(runKey)
	defer clear(key)
	r, err := h.admin(ctx, append([]string{"check", "--in", bundle, "--json"}, scratchArgs(scratch)...), key)
	if err != nil {
		return CheckSummary{}, err
	}
	if r.Code != 0 && r.Code != 1 {
		return CheckSummary{}, failure("varlatchd admin migrate check", r)
	}
	var rep struct {
		Passed *bool `json:"passed"`
		Checks []struct {
			Name     string `json:"name"`
			Passed   bool   `json:"passed"`
			Checked  int64  `json:"checked"`
			Failures []struct {
				Table string `json:"table"`
				Class string `json:"class"`
				What  string `json:"what"`
			} `json:"failures"`
			More int `json:"more"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &rep); err != nil || rep.Passed == nil {
		if r.Code == 1 {
			return CheckSummary{}, failure("varlatchd admin migrate check", r)
		}
		return CheckSummary{}, errors.New("varlatchd admin migrate check did not answer in JSON")
	}
	s := CheckSummary{Passed: *rep.Passed && r.Code == 0}
	for _, c := range rep.Checks {
		s.Checks = append(s.Checks, CheckResult{Name: c.Name, Passed: c.Passed, Checked: c.Checked})
		for i, f := range c.Failures {
			if i >= 3 {
				break
			}
			where := f.Table
			if f.Class != "" {
				where = f.Class
			}
			s.Faults = append(s.Faults, strings.TrimPrefix(fmt.Sprintf("%s: %s: %s", c.Name, where, f.What), ": "))
		}
	}
	return s, nil
}

// Discard is `admin migrate discard --id`.
func (h *Host) Discard(ctx context.Context, id string) error {
	r, err := h.admin(ctx, []string{"discard", "--id", id}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("varlatchd admin migrate discard", r)
	}
	return nil
}
