// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// The target's node, through `varlatchd admin tailnet` (its handoff
// commands, varlatchd's tailnetnode.go): offline before the target starts,
// through its control socket after.

func (h *Host) tailnetAdmin(ctx context.Context, args ...string) (Ran, error) {
	full := append([]string{"admin", "tailnet"}, args...)
	if h.Config != "" {
		full = append(full, "--config", h.Config)
	}
	return h.Run.Run(ctx, "", h.Varlatchd, full, nil)
}

// TailnetEnroll is `admin tailnet enroll --json`.
func (h *Host) TailnetEnroll(ctx context.Context, hostname string, certificate bool) (EnrolledNode, error) {
	args := []string{"enroll", "--hostname", hostname, "--json"}
	if certificate {
		args = append(args, "--certificate")
	}
	r, err := h.tailnetAdmin(ctx, args...)
	if err != nil {
		return EnrolledNode{}, err
	}
	if r.Code != 0 {
		return EnrolledNode{}, failure("varlatchd admin tailnet enroll", r)
	}
	var n EnrolledNode
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &n); err != nil || n.StableID == "" || n.DNSName == "" {
		return EnrolledNode{}, errors.New("varlatchd admin tailnet enroll did not answer in JSON")
	}
	return n, nil
}

// TailnetCertificate is `admin tailnet certificate obtain --json`: one
// attempt; a rate-limit refusal wraps tailhandoff.ErrRateLimited.
func (h *Host) TailnetCertificate(ctx context.Context, name string) error {
	args := []string{"certificate", "obtain", "--name", name, "--json"}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left > time.Second {
			args = append(args, "--timeout", left.Truncate(time.Second).String())
		}
	}
	r, err := h.tailnetAdmin(ctx, args...)
	if err != nil {
		return err
	}
	if r.Code == 0 {
		return nil
	}
	var out struct {
		Refusal string `json:"refusal"`
		Message string `json:"message"`
	}
	if json.Unmarshal(bytes.TrimSpace(lastLine(r.Answer)), &out) == nil && out.Refusal == "rate-limited" {
		return fmt.Errorf("%w: %s", tailhandoff.ErrRateLimited, out.Message)
	}
	return failure("varlatchd admin tailnet certificate obtain", r)
}

// TailnetCertExpiry is `admin tailnet certificate expiry --json`.
func (h *Host) TailnetCertExpiry(ctx context.Context, name string) (time.Time, bool, error) {
	r, err := h.tailnetAdmin(ctx, "certificate", "expiry", "--name", name, "--json")
	if err != nil {
		return time.Time{}, false, err
	}
	if r.Code != 0 {
		return time.Time{}, false, failure("varlatchd admin tailnet certificate expiry", r)
	}
	var out struct {
		NotAfter *time.Time `json:"notAfter"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &out); err != nil {
		return time.Time{}, false, errors.New("varlatchd admin tailnet certificate expiry did not answer in JSON")
	}
	if out.NotAfter == nil {
		return time.Time{}, false, nil
	}
	return *out.NotAfter, true, nil
}

// TailnetOpen is `admin tailnet open --json`.
func (h *Host) TailnetOpen(ctx context.Context) error {
	r, err := h.tailnetAdmin(ctx, "open", "--json")
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("varlatchd admin tailnet open", r)
	}
	return nil
}

// TailnetReaches is `admin tailnet reaches --json`.
func (h *Host) TailnetReaches(ctx context.Context, name, stableID string, wait time.Duration) (bool, error) {
	r, err := h.tailnetAdmin(ctx, "reaches", "--name", name, "--stable-id", stableID, "--wait", wait.Truncate(time.Second).String(), "--json")
	if err != nil {
		return false, err
	}
	if r.Code != 0 {
		return false, failure("varlatchd admin tailnet reaches", r)
	}
	var out struct {
		Reaches *bool  `json:"reaches"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &out); err != nil || out.Reaches == nil {
		return false, errors.New("varlatchd admin tailnet reaches did not answer in JSON")
	}
	if !*out.Reaches && strings.Contains(out.Message, "access rules") {
		// Seen nothing at all: the reason is said, and the check fails
		// closed.
		return false, errors.New(out.Message)
	}
	return *out.Reaches, nil
}
