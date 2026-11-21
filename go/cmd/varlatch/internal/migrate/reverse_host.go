// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// The reverse's Go side (slice 7.6a), through `varlatchd admin migrate`:
// the barrier and its release go through the running varlatchd's control
// socket; the export reads the barrier's frozen copy and the checks the
// kept copy, both beside it. An image's service (Image embeds Host) runs
// them as the image's user.

// ReverseTarget is the Go installation a reverse migration leaves.
type ReverseTarget interface {
	// Barrier opens (or continues) Go's migration barrier, drains it and
	// freezes the installation.
	Barrier(ctx context.Context, id string, drain time.Duration) (BarrierRecord, error)
	// ReleaseBarrier lifts it.
	ReleaseBarrier(ctx context.Context, id string) error
	// ExportReverse writes the reverse bundle to out, the transformed copy
	// kept in keep (a new directory).
	ExportReverse(ctx context.Context, out, keep string) (CopyRecord, error)
	// CheckReverse holds the kept copy against the TypeScript release's
	// export of the database it rebuilt, runKey on a pipe.
	CheckReverse(ctx context.Context, bundle, keep string, runKey []byte) (CheckSummary, error)
	// Archives are the Go installation's archives.
	Archives(ctx context.Context) ([]ArchiveInfo, error)
}

// Barrier is `admin migrate barrier --id --drain-seconds`.
func (h *Host) Barrier(ctx context.Context, id string, drain time.Duration) (BarrierRecord, error) {
	seconds := int(drain / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	r, err := h.admin(ctx, []string{"barrier", "--id", id, "--drain-seconds", strconv.Itoa(seconds)}, nil)
	if err != nil {
		return BarrierRecord{}, err
	}
	if r.Code != 0 {
		return BarrierRecord{}, failure("varlatchd admin migrate barrier", r)
	}
	var b struct {
		Gate struct {
			ID    string `json:"id"`
			Phase string `json:"phase"`
		} `json:"gate"`
		Drained struct {
			Ms int64 `json:"ms"`
		} `json:"drained"`
		Frozen struct {
			AuditPosition string `json:"auditPosition"`
			At            string `json:"at"`
		} `json:"frozen"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &b); err != nil || b.Gate.ID != id || b.Gate.Phase != "paused" || b.Frozen.AuditPosition == "" {
		return BarrierRecord{}, errors.New("varlatchd admin migrate barrier did not answer with its gate, paused, and its frozen point")
	}
	return BarrierRecord{GateID: b.Gate.ID, AuditPosition: b.Frozen.AuditPosition, FrozenAt: b.Frozen.At, DrainedMs: b.Drained.Ms}, nil
}

// ReleaseBarrier is `admin migrate release --id`.
func (h *Host) ReleaseBarrier(ctx context.Context, id string) error {
	r, err := h.admin(ctx, []string{"release", "--id", id}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("varlatchd admin migrate release", r)
	}
	return nil
}

// ExportReverse is `admin migrate export --reverse --out --keep --json`.
func (h *Host) ExportReverse(ctx context.Context, out, keep string) (CopyRecord, error) {
	r, err := h.admin(ctx, []string{"export", "--reverse", "--out", out, "--keep", keep, "--json"}, nil)
	if err != nil {
		return CopyRecord{}, err
	}
	if r.Code != 0 {
		return CopyRecord{}, failure("varlatchd admin migrate export --reverse", r)
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
		return CopyRecord{}, errors.New("varlatchd admin migrate export --reverse did not answer in JSON")
	}
	return CopyRecord{InstallationID: s.InstallationID, Tables: s.Tables, Rows: s.Rows, SessionsEnded: s.SessionsEnded,
		CredsRevoked: s.CredentialsRevoked, MigratedPosition: s.MigratedPosition}, nil
}

// CheckReverse is `admin migrate check --reverse --scratch <keep> --json`.
func (h *Host) CheckReverse(ctx context.Context, bundle, keep string, runKey []byte) (CheckSummary, error) {
	return h.check(ctx, []string{"check", "--reverse", "--in", bundle, "--scratch", keep, "--json"}, runKey)
}

// Archives is `admin backup status`'s archives.
func (h *Host) Archives(ctx context.Context) ([]ArchiveInfo, error) {
	args := []string{"admin", "backup", "status"}
	if h.Config != "" {
		args = append(args, "--config", h.Config)
	}
	r, err := h.Run.Run(ctx, "", h.Varlatchd, args, nil)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, failure("varlatchd admin backup status", r)
	}
	var s struct {
		Archives []ArchiveInfo `json:"archives"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &s); err != nil {
		return nil, fmt.Errorf("varlatchd admin backup status did not answer in JSON")
	}
	return s.Archives, nil
}
