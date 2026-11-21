// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// The tailnet name's certificate issuance count across a migration and
// its rollback (ADR-0059 Decision 9; go-step7 decision 11; step 6
// decision 16's count, certificate_issuances, #344). The handoff counts
// its attempts in the source's ledger (LedgerFile), kept across runs:
//   - once the forward handoff is checked, the ledger's attempts are written
//     into Go's count (varlatchd admin certificate record), so the count
//     lives on with Go's installation and its archives; --finish writes
//     them again, should that have failed;
//   - a rollback merges Go's attempts for the name into the ledger before
//     the name moves back, so attempts recorded on Go's side count too;
//   - a forward migration after a rollback counts both again.
// Each attempt is one by its name and start: written or merged twice, it
// counts once.

// IssuanceAttempt is one certificate attempt for a name (its full domain,
// <machine>.<tailnet suffix>, as the count keeps it).
type IssuanceAttempt struct {
	Name      string     `json:"name"`
	StartedAt time.Time  `json:"startedAt"`
	Outcome   string     `json:"outcome"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
}

// TailnetIssuances is a target's count: what it lists, and what it records.
type TailnetIssuances interface {
	// Issuances is every attempt the target's count keeps
	// (varlatchd admin certificate issuances --all --json).
	Issuances(ctx context.Context) ([]IssuanceAttempt, error)
	// RecordIssuances records attempts made elsewhere, each once
	// (varlatchd admin certificate record).
	RecordIssuances(ctx context.Context, attempts []IssuanceAttempt) error
}

// Issuances is `varlatchd admin certificate issuances --all --json`.
func (h *Host) Issuances(ctx context.Context) ([]IssuanceAttempt, error) {
	r, err := h.certificateAdmin(ctx, "issuances", "--all", "--json")
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, failure("varlatchd admin certificate issuances", r)
	}
	var out struct {
		Attempts []IssuanceAttempt `json:"attempts"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &out); err != nil {
		return nil, errors.New("varlatchd admin certificate issuances did not answer in JSON")
	}
	return out.Attempts, nil
}

// RecordIssuances is `varlatchd admin certificate record --attempts`.
func (h *Host) RecordIssuances(ctx context.Context, attempts []IssuanceAttempt) error {
	b, err := json.Marshal(attempts)
	if err != nil {
		return err
	}
	r, err := h.certificateAdmin(ctx, "record", "--attempts", string(b))
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("varlatchd admin certificate record", r)
	}
	return nil
}

func (h *Host) certificateAdmin(ctx context.Context, args ...string) (Ran, error) {
	full := append([]string{"admin", "certificate"}, args...)
	if h.Config != "" {
		full = append(full, "--config", h.Config)
	}
	return h.Run.Run(ctx, "", h.Varlatchd, full, nil)
}

// domainOf is the count's name for a ledger's machine name.
func domainOf(name, suffix string) string {
	if suffix == "" || strings.Contains(name, ".") {
		return strings.ToLower(name)
	}
	return strings.ToLower(name + "." + suffix)
}

// outcomeOf is the count's outcome for a ledger entry's.
func outcomeOf(o tailhandoff.Outcome) string {
	switch o {
	case tailhandoff.Issued:
		return "issued"
	case tailhandoff.Refused:
		return "refused"
	}
	return "started"
}

// recordIssuances writes the ledger's attempts into the target's count, once the forward migration is open. It changes
// nothing in the migration: an attempt that cannot be written now is
// written by the next run, the ledger being kept.
func (e *Engine) recordIssuances(ctx context.Context, rec *TailnetRecord) error {
	ti, ok := e.Target.(TailnetIssuances)
	if !ok || rec == nil {
		return nil
	}
	entries, err := (&fileLedger{path: e.ledgerPath()}).read()
	if err != nil {
		return err
	}
	// Every name the ledger counts: the tailnet name's, and the temporary
	// names' (each its own exact name to the CA).
	var attempts []IssuanceAttempt
	for _, x := range entries {
		attempts = append(attempts, IssuanceAttempt{Name: domainOf(x.Name, rec.Suffix), StartedAt: x.StartedAt.UTC(), Outcome: outcomeOf(x.Outcome), EndedAt: x.EndedAt})
	}
	if len(attempts) == 0 {
		return nil
	}
	return ti.RecordIssuances(ctx, attempts)
}

// mergeIssuances merges the target's attempts for the handoff's name into
// the ledger before a rollback's handoff, each once (by start).
func (e *Engine) mergeIssuances(ctx context.Context, rec *TailnetRecord) error {
	ti, ok := e.Target.(TailnetIssuances)
	if !ok || rec == nil {
		return nil
	}
	theirs, err := ti.Issuances(ctx)
	if err != nil {
		return fmt.Errorf("reading Go's certificate issuance count: %w", err)
	}
	l := &fileLedger{path: e.ledgerPath()}
	entries, err := l.read()
	if err != nil {
		return err
	}
	domain := domainOf(rec.Name, rec.Suffix)
	added := 0
	for _, a := range theirs {
		if a.Name != domain {
			continue
		}
		at := a.StartedAt.UTC()
		if slices.ContainsFunc(entries, func(x ledgerEntry) bool { return strings.EqualFold(x.Name, rec.Name) && x.StartedAt.Equal(at) }) {
			continue
		}
		id, err := newID()
		if err != nil {
			return err
		}
		x := ledgerEntry{ID: id, Name: strings.ToLower(rec.Name), StartedAt: at, EndedAt: a.EndedAt}
		switch a.Outcome {
		case "issued":
			x.Outcome = tailhandoff.Issued
		case "refused":
			x.Outcome = tailhandoff.Refused
		}
		entries = append(entries, x)
		added++
	}
	if added == 0 {
		return nil
	}
	return l.write(entries)
}
