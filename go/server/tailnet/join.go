// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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
// not take, a node it does not know): trying again answers the same. Its
// text is the control server's own, the auth key taken out (withoutKey): for
// the operator at a terminal, never a log.
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
	// Of those, the ones that pass by themselves, whole: a registration the
	// control server limits (with how long tsnet waits), and a watch that
	// fell behind. Any other text is the control server's refusal, whatever
	// words it has in it.
	limitedFor  = "node registration rate limited; will retry after "
	watchBehind = "IPN bus consumer fell behind; closing watch"
)

// passing is whether a join that ended with err may still succeed as it
// is: everything but the backend's report of what the control server
// answered.
func passing(err error) bool {
	said, ok := strings.CutPrefix(err.Error(), backendError)
	return !ok || said == watchBehind || RateLimited(err)
}

// RateLimited is whether err is tsnet's report of a registration the control
// server put off.
func RateLimited(err error) bool {
	if err == nil {
		return false
	}
	wait, ok := strings.CutPrefix(err.Error(), backendError+limitedFor)
	if !ok {
		return false
	}
	_, perr := time.ParseDuration(wait)
	return perr == nil
}

// keyShape is an auth key as Tailscale and Headscale write them.
var keyShape = regexp.MustCompile(`(?i)\b(ts|hs)key-[\w-]+`)

// withoutKey is text with the auth key the node joins with taken out, whole
// or as it is sent (without its parameters, or the signature wrapped into
// it), and anything shaped like one: a control server's answer may repeat
// what it was given.
func withoutKey(text, authKey string) string {
	sent, _, _ := strings.Cut(authKey, "--TL")
	bare, _, _ := strings.Cut(sent, "?")
	for _, k := range []string{authKey, sent, bare} {
		if k != "" {
			text = strings.ReplaceAll(text, k, keyTaken)
			text = strings.ReplaceAll(text, url.QueryEscape(k), keyTaken)
		}
	}
	return keyShape.ReplaceAllString(text, keyTaken)
}

const keyTaken = "[auth key]"

// keyless is err without the auth key in its text; err itself when there is
// none in it.
func keyless(err error, authKey string) error {
	if err == nil {
		return nil
	}
	if text := withoutKey(err.Error(), authKey); text != err.Error() {
		return errors.New(text)
	}
	return err
}

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

// upOf is srv's Up, its status and its auth key left out.
func upOf(srv *tsnet.Server) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := srv.Up(ctx)
		return keyless(err, srv.AuthKey)
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
