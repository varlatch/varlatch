// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/logtail"
	"tailscale.com/net/netns"
)

// The restore's probe (internal docs/design/go-step6.md decision 16): before
// a restored installation's node enrols, a short-lived ephemeral node joins
// with the same auth key under a name of its own, reads the peers it can
// see, and logs out. A peer under the configured hostname (compared without
// case) means the old installation's node still holds the name: the
// restore is refused before enrolment. The tailnet's ACLs may hide nodes
// from the probe, so "not seen" is not "free": the read-back after
// enrolment (NameSuffixed) is the guard. A second probe node then joins
// with the key again: a key that cannot (single-use) would be spent before
// the real enrolment, so the restore refuses it.

// ProbeConfig is what the probe joins with.
type ProbeConfig struct {
	// Dir holds the probes' state, removed after each.
	Dir        string
	Hostname   string
	ControlURL string
	AuthKey    string
	Tags       []string
	// Timeout bounds each probe node's join (default 60 s).
	Timeout time.Duration
	// betweenJoins, set by tests, runs after the first probe node left.
	betweenJoins func()
	// observe, set by tests, hears what each probe node did: "join <name>
	// ephemeral", "logout <name>", "removed <dir>".
	observe func(event string)
}

// ProbeResult is what the probe found.
type ProbeResult struct {
	// Seen are the DNS names of the peers under the configured hostname.
	Seen []string `json:"seen"`
	// Reusable: the key joined a second time.
	Reusable bool `json:"reusable"`
	// SecondJoin is why the second join failed, when it did.
	SecondJoin string `json:"secondJoin,omitempty"`
}

// ProbeName runs the probe. An error is a first join that failed (the key,
// the control server, the network): nothing could be checked.
func ProbeName(ctx context.Context, c ProbeConfig) (ProbeResult, error) {
	var res ProbeResult
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	seen, err := probeJoin(ctx, c, true)
	if err != nil {
		return res, fmt.Errorf("tailnet: the probe could not join with the auth key: %w", err)
	}
	res.Seen = seen
	if c.betweenJoins != nil {
		c.betweenJoins()
	}
	if _, err := probeJoin(ctx, c, false); err != nil {
		res.SecondJoin = err.Error()
		return res, nil
	}
	res.Reusable = true
	return res, nil
}

// probeJoin joins one ephemeral probe node, reads its peers when look is
// set, logs it out (an ephemeral node logged out is deleted by the control
// plane) and removes its state.
func probeJoin(ctx context.Context, c ProbeConfig, look bool) ([]string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	name := "varlatch-restore-probe-" + hex.EncodeToString(suffix)
	observe := c.observe
	if observe == nil {
		observe = func(string) {}
	}
	dir, err := os.MkdirTemp(c.Dir, ".tailnet-probe-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if os.RemoveAll(dir) == nil {
			observe("removed " + dir)
		}
	}()
	srv, err := newServer(NodeConfig{Dir: dir, Hostname: name, ControlURL: c.ControlURL, AuthKey: c.AuthKey, Tags: c.Tags})
	if err != nil {
		return nil, err
	}
	// Ephemeral: logged out, the control plane deletes it.
	srv.Ephemeral = true
	netns.SetEnabled(false)
	envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	logtail.Disable()
	defer srv.Close()
	if srv.Ephemeral {
		observe("join " + name + " ephemeral")
	}
	jctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	if _, err := srv.Up(jctx); err != nil {
		return nil, err
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if lc.Logout(lctx) == nil {
			observe("logout " + name)
		}
	}()
	if !look {
		return nil, nil
	}
	st, err := lc.Status(jctx)
	if err != nil {
		return nil, err
	}
	var seen []string
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		dns := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
		label, _, _ := strings.Cut(dns, ".")
		if strings.EqualFold(p.HostName, c.Hostname) || strings.EqualFold(label, c.Hostname) {
			seen = append(seen, dns)
		}
	}
	return seen, nil
}

// ErrNameHeld is a restore whose node's name is still held.
var ErrNameHeld = errors.New("tailnet: the configured name is still held by another node")
