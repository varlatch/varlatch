// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
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
// text is fixed, never the control server's own words, which may repeat the
// auth key in any form.
type RefusedError struct{ text string }

func (e *RefusedError) Error() string { return e.text }

// refusedText is a refused registration: tsnet's backend reports one only as
// the error in an answer of HTTP 200.
const refusedText = "the control server refused the node's registration (HTTP 200, with an error in its answer, whose words are not shown: they may repeat the auth key). Check the key (expired, used or revoked?) and the control server's own log"

// refusedBy is err as a *RefusedError.
func refusedBy(err error) error {
	if strings.TrimPrefix(err.Error(), backendError) == logsRequired {
		// tsnet's own words.
		return &RefusedError{text: "the tailnet requires its nodes to log to Tailscale (data plane audit logs), which varlatchd's node never does"}
	}
	return &RefusedError{text: refusedText}
}

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
	// And one of tsnet's own that does not pass.
	logsRequired = "tailnet requires logging to be enabled. Remove --no-logs-no-support from tailscaled command line."
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
var keyShape = regexp.MustCompile(`(?i)(ts|hs)key-[\w-]`)

// keyTaken is said in place of a text that has the auth key in it.
const keyTaken = "[not shown: it has the auth key in it]"

// withoutKey is text, or keyTaken in place of all of it when it has the auth
// key the node joins with in it: a control server's answer may repeat what
// it was given.
func withoutKey(text, authKey string) string {
	if hasKey(text, authKey) {
		return keyTaken
	}
	return text
}

// maxEscapes is how many layers of percent escapes hasKey looks through.
const maxEscapes = 3

// hasKey is whether text has authKey in it, or anything shaped like an auth
// key: as it is, or under percent escapes, wholly or partly escaped. The key
// is looked for whole, as it is sent (without the signature wrapped into it,
// or its parameters), and as its secret part alone. A text with more layers
// of escapes than are looked through counts as one that has it.
func hasKey(text, authKey string) bool {
	sent, _, _ := strings.Cut(authKey, "--TL")
	bare, _, _ := strings.Cut(sent, "?")
	var parts []string
	for _, k := range []string{authKey, sent, bare} {
		if k == "" {
			continue
		}
		parts = append(parts, k)
		if secret := k[strings.LastIndexByte(k, '-')+1:]; len(secret) >= 8 {
			parts = append(parts, secret)
		}
	}
	for range maxEscapes + 1 {
		if keyShape.MatchString(text) || slices.ContainsFunc(parts, func(k string) bool { return strings.Contains(text, k) }) {
			return true
		}
		next := unescape(text)
		if next == text {
			return false
		}
		text = next
	}
	return true
}

// unescape is text with one layer of its percent escapes decoded; a percent
// sign that begins none stays.
func unescape(text string) string {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		if text[i] == '%' && i+2 < len(text) {
			if b, err := hex.DecodeString(text[i+1 : i+3]); err == nil {
				out = append(out, b[0])
				i += 2
				continue
			}
		}
		out = append(out, text[i])
	}
	return string(out)
}

// keyless is err without the auth key in its text; err itself when there is
// none in it.
func keyless(err error, authKey string) error {
	if err == nil {
		return nil
	}
	if hasKey(err.Error(), authKey) {
		return errors.New(keyTaken)
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
		case !passing(err):
			// Before anything else: its words go no further.
			return refusedBy(err)
		case ctx.Err() != nil:
			if last != nil {
				return fmt.Errorf("%w (before that: %v)", err, last)
			}
			return err
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
		if err != nil && !passing(err) {
			// Told by join from what passes: kept as it is until then, and
			// its words go no further.
			return err
		}
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
