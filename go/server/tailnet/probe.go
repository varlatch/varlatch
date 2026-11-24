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

	"tailscale.com/client/local"
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
	// KeyTags is NodeConfig's: on a self-hosted control server the probe
	// node advertises no tags, and takes its auth key's.
	KeyTags bool
	// Timeout bounds each probe node's join (default 60 s).
	Timeout time.Duration
	// NamePrefix is the probe node's name before its random part
	// (varlatch-restore-probe- by default).
	NamePrefix string
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
	err := probeJoin(ctx, c, func(ctx context.Context, lc *local.Client) error {
		peers, err := probePeers(ctx, lc)
		for _, p := range peers {
			if p.Label == strings.ToLower(c.Hostname) || strings.EqualFold(p.HostName, c.Hostname) {
				res.Seen = append(res.Seen, p.DNSName)
			}
		}
		return err
	})
	if err != nil {
		return res, fmt.Errorf("tailnet: the probe could not join with the auth key: %w", err)
	}
	if c.betweenJoins != nil {
		c.betweenJoins()
	}
	if err := probeJoin(ctx, c, nil); err != nil {
		res.SecondJoin = err.Error()
		return res, nil
	}
	res.Reusable = true
	return res, nil
}

// probePeer is a peer as a probe node sees it.
type probePeer struct {
	// DNSName is its MagicDNS name, lower case, without the trailing dot;
	// Label that name's first label.
	DNSName, Label string
	HostName       string
	StableID       string
}

// probePeers are the peers a probe node sees now.
func probePeers(ctx context.Context, lc *local.Client) ([]probePeer, error) {
	st, err := lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	var out []probePeer
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		dns := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
		label, _, _ := strings.Cut(dns, ".")
		out = append(out, probePeer{DNSName: dns, Label: label, HostName: p.HostName, StableID: string(p.ID)})
	}
	return out, nil
}

// probeJoin joins one ephemeral probe node, runs look with its local
// client when set, logs it out (an ephemeral node logged out is deleted by
// the control plane) and removes its state.
func probeJoin(ctx context.Context, c ProbeConfig, look func(context.Context, *local.Client) error) error {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	prefix := c.NamePrefix
	if prefix == "" {
		prefix = "varlatch-restore-probe-"
	}
	name := prefix + hex.EncodeToString(suffix)
	observe := c.observe
	if observe == nil {
		observe = func(string) {}
	}
	dir, err := os.MkdirTemp(c.Dir, ".tailnet-probe-")
	if err != nil {
		return err
	}
	defer func() {
		if os.RemoveAll(dir) == nil {
			observe("removed " + dir)
		}
	}()
	srv, err := newServer(NodeConfig{Dir: dir, Hostname: name, ControlURL: c.ControlURL, AuthKey: c.AuthKey, Tags: c.Tags, KeyTags: c.KeyTags})
	if err != nil {
		return err
	}
	// Ephemeral: logged out, the control plane deletes it.
	srv.Ephemeral = true
	prepareTsnet()
	defer srv.Close()
	if srv.Ephemeral {
		observe("join " + name + " ephemeral")
	}
	jctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	if err := srv.Start(); err != nil {
		return keyless(err, c.AuthKey)
	}
	if err := join(jctx, nil, upOf(srv), nil); err != nil {
		return err
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if lc.Logout(lctx) == nil {
			observe("logout " + name)
		}
	}()
	if look == nil {
		return nil
	}
	// The look has the operation's context: its wait may outlast the join's
	// timeout.
	return look(ctx, lc)
}

// ReachResult is what the reach check found: Reaches when name, resolved
// from the probe (a client node of the tailnet), is the node with the
// expected StableID, and only it.
type ReachResult struct {
	Reaches bool `json:"reaches"`
	// Holders are the peers whose MagicDNS name's first label is name
	// (compared without case), with their StableIDs.
	Holders []ReachHolder `json:"holders"`
}

// ReachHolder is a peer under the name.
type ReachHolder struct {
	DNSName  string `json:"dnsName"`
	StableID string `json:"stableId"`
}

// Reaches is the handoff's final check (go-step7 decision 11): an
// ephemeral probe node joins with the auth key, as the restore's probe
// does, and looks, every second until wait has passed, for name among its
// peers: MagicDNS resolves a name from that same map, so the name reaches
// the node when the one peer under it is stableID. It logs out and leaves
// no state. An error is a join that failed: nothing could be checked. The
// tailnet's access rules must let the node's tags see each other, or the
// probe sees nothing and the check fails closed.
func Reaches(ctx context.Context, c ProbeConfig, name, stableID string, wait time.Duration) (ReachResult, error) {
	var res ReachResult
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.NamePrefix == "" {
		c.NamePrefix = "varlatch-reach-probe-"
	}
	want := strings.ToLower(name)
	err := probeJoin(ctx, c, func(ctx context.Context, lc *local.Client) error {
		deadline := time.Now().Add(wait)
		for {
			peers, err := probePeers(ctx, lc)
			if err != nil {
				return err
			}
			res.Holders = nil
			for _, p := range peers {
				if p.Label == want {
					res.Holders = append(res.Holders, ReachHolder{DNSName: p.DNSName, StableID: p.StableID})
				}
			}
			res.Reaches = len(res.Holders) == 1 && res.Holders[0].StableID == stableID
			if res.Reaches || !time.Now().Before(deadline) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
	})
	if err != nil {
		return res, fmt.Errorf("tailnet: the reach probe could not join with the auth key: %w", err)
	}
	return res, nil
}

// ErrNameHeld is a restore whose node's name is still held.
var ErrNameHeld = errors.New("tailnet: the configured name is still held by another node")
