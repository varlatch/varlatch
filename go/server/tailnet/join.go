// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

// Joining the tailnet. tsnet.Server.Up ends at the first error its backend
// tells its watchers, though the backend itself keeps trying: a control
// server that limits registrations (HTTP 429, or 503 with Retry-After) for
// a moment would leave a node that joins a minute later with nobody waiting
// for it. So the wait is taken up again after such an error, and ends at
// once at one that says the control server will not have the node.

// RefusedError is a join the control server refused (an auth key it does
// not take, a node it does not know): trying again answers the same.
type RefusedError struct{ Err error }

func (e *RefusedError) Error() string { return e.Err.Error() }
func (e *RefusedError) Unwrap() error { return e.Err }

// errNodeClosed is a join of a node closed meanwhile.
var errNodeClosed = errors.New("tailnet: the node was closed")

// The pause before a join is waited for again: tsnet's backend tries by
// itself, by the control server's Retry-After, so this only paces the
// watching.
const (
	joinRetryFirst = time.Second
	joinRetryMax   = 15 * time.Second
)

const (
	// backendError begins an error of Up that tsnet's backend reported.
	backendError = "tsnet.Up: backend: "
	// Of those, the ones that pass by themselves: a registration the
	// control server limits, and a watch that fell behind.
	rateLimited = "rate limited"
	watchBehind = "IPN bus consumer fell behind"
)

// passing is whether a join that ended with err may still succeed as it
// is: everything but the backend's report of what the control server
// answered.
func passing(err error) bool {
	said, ok := strings.CutPrefix(err.Error(), backendError)
	return !ok || strings.Contains(said, rateLimited) || strings.Contains(said, watchBehind)
}

// RateLimited is whether err is a join the control server put off.
func RateLimited(err error) bool { return err != nil && strings.Contains(err.Error(), rateLimited) }

// join waits until up says the node is on its tailnet, through every error
// that passes (waiting, when set, hears each one, before the pause), until
// ctx ends or closed is closed. A *RefusedError is one that does not pass.
func join(ctx context.Context, closed <-chan struct{}, up func(context.Context) error, waiting func(error)) error {
	var last error
	for pause := joinRetryFirst; ; pause = min(2*pause, joinRetryMax) {
		err := up(ctx)
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil:
			if last != nil {
				return fmt.Errorf("%w (before that: %v)", err, last)
			}
			return err
		case !passing(err):
			return &RefusedError{Err: err}
		}
		last = err
		if waiting != nil {
			waiting(err)
		}
		t := time.NewTimer(pause)
		select {
		case <-t.C:
		case <-closed:
			t.Stop()
			return errNodeClosed
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("%w (%v)", err, ctx.Err())
		}
	}
}

// upOf is srv's Up, its status left out.
func upOf(srv *tsnet.Server) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := srv.Up(ctx)
		return err
	}
}

// Join waits until the node is on the tailnet, as Up does; waiting hears
// each error the wait goes on after.
func (n *TSNode) Join(ctx context.Context, waiting func(error)) error {
	return join(ctx, n.closed, upOf(n.srv), waiting)
}

// Up waits until the node is on the tailnet: Running, on a network map the
// control plane sent since the node started. A control plane that puts the
// node off (a rate limit) is waited for until ctx ends; one that refuses it
// is a *RefusedError. The map may still lag the control plane's own records
// (a rename just made through its API): where the node must be as expected,
// AwaitStatus waits for it.
func (n *TSNode) Up(ctx context.Context) error { return n.Join(ctx, nil) }
