// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"math"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Step-up approvals in the CLI (ADR-0054 Decision 3), ported from
// approvals.ts at v0.22.0. When an operation needs the person's approval
// with a trusted passkey, the server stores a pending approval bound to that
// exact request and answers STEP_UP_REQUIRED. The CLI prints its summary and
// the dashboard address on stderr, then:
//
//   - outside assisted mode, waits, polling at the approval's interval
//     (SLOW_DOWN adds to it), until it is approved, and the client repeats
//     the request once with the Varlatch-Approval header;
//   - in assisted mode (ADR-0043), does not wait: a coding agent stops,
//     shows the address to the person, and once they approved runs the same
//     command again with `--approval <id>`. Exit 75.
//
// `--approval <id>` resumes: the CLI waits for that approval (bounded by its
// expiry) before the command's first change request, then sends it with
// every change request.
//
// Exit statuses: 75 when the approval is still pending and the CLI does not
// wait (assisted mode), or it expired before anyone approved it; 77 when it
// was cancelled or closed, was used already, or does not exist for this
// person; 130 when the person stopped the wait with Ctrl-C (the CLI then
// cancels the approval, best effort).

// approvalWaiting is what the CLI says while it waits.
const approvalWaiting = "Waiting for your approval (Ctrl-C stops waiting and cancels it)..."

// approvalError is approvals.ts's ApprovalError as main.ts's catch prints
// it: its message escaped, and its status.
func approvalError(message string, code int) error { return Fail(Printable(message), code) }

// approvalID is an approval's id as the server sent it, as a template
// shows it.
func approvalIDOf(approval any) string {
	id, ok := jsval.Get(approval, "id")
	return jsTemplate(id, ok)
}

// ended is approvals.ts's ended: the error an approval in that state ends
// the wait with, or nil while it is pending or approved (or in a state this
// CLI does not know, which it keeps waiting through).
func ended(approval any, state string) error {
	id := Printable(approvalIDOf(approval))
	switch state {
	case "expired":
		return approvalError("Approval "+id+" expired before it was approved. Nothing was changed; run the command again for a new one.", ExitTempfail)
	case "consumed":
		return approvalError("Approval "+id+" was already used. Run the command again for a new one.", ExitDenied)
	case "closed":
		reason, _ := jsval.Get(approval, "closeReason")
		switch reason {
		case "cancelled":
			return approvalError("Approval "+id+" was cancelled. Nothing was changed.", ExitDenied)
		case "reset":
			return approvalError("Approval "+id+" was closed by the host operator's reset of the security controls. Nothing was changed.", ExitDenied)
		case "organization-deleted":
			return approvalError("Approval "+id+" was closed: its organization was deleted. Nothing was changed.", ExitDenied)
		}
		return approvalError("Approval "+id+" was closed. Nothing was changed.", ExitDenied)
	}
	return nil
}

func stateOf(approval any) string {
	state, _ := jsval.Get(approval, "state")
	s, _ := state.(string)
	return s
}

// notFound is the wait's end for an approval this person has none of.
func notFound(id string) error {
	return approvalError("No approval "+id+" exists for you (an approval belongs to the person who asked for it). Nothing was changed.", ExitDenied)
}

// waitForApproval polls the approval until it is approved, at its
// interval, honouring SLOW_DOWN, never past its expiry: the approved
// approval, or the error that ended the wait. ctx ending stops the wait at
// once (Ctrl-C).
func waitForApproval(ctx context.Context, api *apiclient.Client, first any) (any, error) {
	approval := first
	intervalValue, _ := jsval.Get(approval, "interval")
	interval := apiclient.Number(intervalValue)
	if !jsjson.Truthy(intervalValue) || math.IsNaN(interval) {
		interval = 5
	}
	interval = max(1, interval)
	expiresAt, _ := jsval.Get(approval, "expiresAt")
	deadline, _ := jsval.DateParse(jsjson.String(expiresAt))
	for {
		state := stateOf(approval)
		if stop := ended(approval, state); stop != nil {
			return nil, stop
		}
		if state == "approved" {
			return approval, nil
		}
		left := deadline - float64(time.Now().UnixMilli())
		if left <= 0 {
			return nil, ended(approval, "expired")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pause := interval * 1000
		if left < pause {
			pause = left
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(pause) * time.Millisecond):
		}
		next, err := api.GetApproval(ctx, approvalIDOf(approval))
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			var e *apiclient.APIError
			if errors.As(err, &e) && e.CodeIs("SLOW_DOWN") {
				askedValue, _ := jsval.Get(e.Details, "interval")
				asked := apiclient.Number(askedValue)
				if !math.IsNaN(asked) && !math.IsInf(asked, 0) && asked > interval {
					interval = asked
				} else {
					interval += 5
				}
				continue
			}
			if errors.As(err, &e) && e.CodeIs("RESOURCE_NOT_FOUND") {
				return nil, notFound(Printable(approvalIDOf(approval)))
			}
			return nil, err
		}
		approval = next
	}
}

// interrupts is how a run hears Ctrl-C: a channel of interrupts and a
// function that stops listening. Tests replace it.
var interrupts = func() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt)
	return ch, func() { signal.Stop(ch) }
}

// cancelBudget bounds the best-effort cancel after Ctrl-C.
const cancelBudget = 3 * time.Second

// waitInterruptibly waits for the approval with Ctrl-C handled: an
// interrupt stops the wait at once (the pause and the poll in flight both
// end), so a poll answering "approved" a moment later can never let the
// request be sent. Then it cancels the approval (best effort, a few seconds
// at most) and exits 130; a second Ctrl-C exits at once.
func (r *Run) waitInterruptibly(api *apiclient.Client, approval any, announce []string) (any, error) {
	signals, stop := interrupts()
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	interrupted := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				select {
				case <-interrupted:
					os.Exit(ExitInterrupted) // the second Ctrl-C
				default:
				}
				once.Do(func() { close(interrupted); cancel() })
			}
		}
	}()
	for _, line := range announce {
		_ = r.warn(line)
	}
	approved, err := waitForApproval(ctx, api, approval)
	select {
	case <-interrupted:
	default:
		return approved, err
	}
	id := Printable(approvalIDOf(approval))
	_ = r.warn("Stopped waiting. Cancelling approval " + id + "; nothing was changed.")
	cancelCtx, done := context.WithTimeout(context.Background(), cancelBudget)
	_, _ = api.CancelApproval(cancelCtx, approvalIDOf(approval))
	done()
	return nil, ExitWith(ExitInterrupted)
}

// rerunCommand is approvals.ts's rerunCommand: the command line to run
// again after approving, with `--approval <id>` added, as shell words.
func rerunCommand(argv []string, approvalID string, assisted bool) string {
	words := []string{"varlatch"}
	if assisted && !slices.Contains(argv, "--assisted") {
		words = append(words, "--assisted")
	}
	words = append(append(words, approvalOption, approvalID), argv...)
	for i, w := range words {
		words[i] = shellWord(w)
	}
	return strings.Join(words, " ")
}

// assistedStopLines is approvals.ts's assistedStopLines: for assisted
// mode, stop, show the address to the person, and run the command again
// after they approved.
func (r *Run) assistedStopLines(approval any, rerun string) ([]string, error) {
	lines, err := r.approvalLines(approval)
	if err != nil {
		return nil, err
	}
	expiresAt, ok := jsval.Get(approval, "expiresAt")
	return append(lines,
		"Coding agent: stop here. Show the address above to the person and ask them to approve it themselves; "+
			"do not open or approve it for them. Nothing was changed yet.",
		"After they approved, run the same command again (before "+templateTime(jsUndefinedOr(expiresAt, ok))+"):",
		"  "+Printable(rerun)), nil
}

// stepUpHandler is approvals.ts's stepUpHandler, the client's OnStepUp:
// print what is asked and where to approve it; in assisted mode stop with
// 75, otherwise wait and let the client repeat the request with the
// approval. polling is the client that polls and cancels the approval.
func (r *Run) stepUpHandler(polling func() *apiclient.Client) func(approval any) (bool, error) {
	return func(approval any) (bool, error) {
		id := approvalIDOf(approval)
		if r.Assisted.On {
			lines, err := r.assistedStopLines(approval, rerunCommand(r.argv, id, true))
			if err != nil {
				return false, err
			}
			for _, line := range lines {
				_ = r.warn(line)
			}
			return false, approvalError("Waiting for the person to approve "+id+".", ExitTempfail)
		}
		lines, err := r.approvalLines(approval)
		if err != nil {
			return false, err
		}
		if _, err := r.waitInterruptibly(polling(), approval, append(lines, approvalWaiting)); err != nil {
			return false, err
		}
		_ = r.warn("Approved. Sending the request again with the approval.")
		return true, nil
	}
}

// resumeReady is approvals.ts's resumingFetch: before the command's first
// change request (anything but a GET), wait until the approval --approval
// names is approved, then let the request go (the client adds the
// Varlatch-Approval header). Reads go out at once. The wait happens once.
func (r *Run) resumeReady(approvalID string, polling func() *apiclient.Client) func(method string) error {
	var once sync.Once
	var ready error
	return func(method string) error {
		if strings.ToUpper(method) == "GET" {
			return nil
		}
		once.Do(func() {
			client := polling()
			approval, err := client.GetApproval(context.Background(), approvalID)
			if err != nil {
				var e *apiclient.APIError
				if errors.As(err, &e) && e.CodeIs("RESOURCE_NOT_FOUND") {
					ready = notFound(approvalID)
					return
				}
				ready = err
				return
			}
			var announce []string
			if stateOf(approval) == "pending" {
				lines, err := r.approvalLines(approval)
				if err != nil {
					ready = err
					return
				}
				announce = append(lines, approvalWaiting)
			}
			_, ready = r.waitInterruptibly(client, approval, announce)
		})
		return ready
	}
}
