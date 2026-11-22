// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The restore's tailnet handoff (internal docs/design/go-step7.md decision
// 11; step 6 decision 16's interim rule replaced): a restore onto a fresh
// host takes the dead installation's tailnet name over, by rename, rather
// than waiting for its node to be deleted.
//
// `varlatchd admin tailnet take-name (--oauth-client-file <file> |
// --headscale-url <https://IP[:port]> --headscale-api-key-file <file>)
// [--json]` runs offline, under the data directory's lock, after `tailnet
// enroll` held the restored node under its temporary name
// (<name>-vl-<op>-n) and before varlatchd first starts:
//   - on Tailscale (tailnet_control_url unset), the control plane is
//     Tailscale's API with the operator's OAuth client (devices:core only,
//     O4), read from its file; on Headscale (tailnet_control_url set,
//     slice 7.5c c4), it is Headscale's API with --headscale-url matching
//     tailnet_control_url and an API key file expiring within the hour,
//     expired when take-name ends however it ends (Headscale's CLI is
//     refused because its listing carries no HTTP Date header). Both go
//     through the outbound policy's client (go/server/outbound, purpose
//     tailnet_control); a self-hosted Headscale on a private or host-only
//     IP needs an outbound_allow entry in varlatchd.conf;
//   - the dead node is the one device under the configured name, and dead:
//     not connected to the control plane, and last seen more than deadGrace
//     ago by the control plane's Date header (checked when planned and
//     again right before the first rename; a node seen since may be the old
//     installation still running, and is never renamed from under it); it
//     is renamed to <name>-vl-<op>-o and the restored node to the name,
//     each read back; on Tailscale with tailnet HTTPS the name's
//     certificate is obtained (counted in tailnet-issuances.json; skipped
//     on Headscale, which has no certificates); a client node (the reach
//     probe) must see the name reach the restored node; then the hold is
//     removed, so varlatchd listens when it starts. The dead node is never
//     closed or reopened.
//   - the handoff's state is journalled in tailnet-takeover.json (0600)
//     before each act; run again, take-name resumes it, never guessing: an
//     interrupted switch is undone (the dead node takes its name back), then
//     done again. A crash after the hold's removal and before the journal
//     said done is finished: the name, certificate and reach checked again.
//     A dead node deleted from the tailnet mid-switch leaves its name free:
//     the restored node takes it (tailhandoff's takeFreedName).

// The data directory's files of a restore's handoff.
const (
	TakeoverFile = "tailnet-takeover.json"
	IssuanceFile = "tailnet-issuances.json"
)

// deadGrace is how long ago the control plane must have last seen the
// dead node for take-name to rename it: within it, the node may be the old
// installation still running (a restart, a short cut), and a rename would
// take its name from under it. Tests shorten it against a real Headscale.
var deadGrace = 5 * time.Minute

// clockSkewLimit is how far the control plane's Date may be from this
// host's clock: the dead node is judged by the control plane's, but one
// more than this apart is refused, not trusted.
const clockSkewLimit = time.Hour

// Test hooks: Tailscale's API and its certificate (a crashpoint build's
// gate, tailnethook_crashpoint.go, or the package's tests); and the kill
// points, each journalled step's.
var (
	takeNameAPI  string
	takeNameTLS  *tls.Config
	handoffPoint = func(string) {}
	// tuneTakeName shortens the handoff's deadlines (tests).
	tuneTakeName = func(*tailhandoff.Engine) {}
)

// takeNameResult is take-name's --json.
type takeNameResult struct {
	Operation  string            `json:"operation"`
	Name       string            `json:"name"`
	Phase      tailhandoff.Phase `json:"phase"`
	DeadID     string            `json:"deadId"`
	IncomingID string            `json:"incomingId"`
	StableID   string            `json:"stableId"`
}

func runTailnetTakeName(cfg *config.Config, c nodeCmd, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "varlatchd admin tailnet take-name: "+format+"\n", args...)
		return ExitFailure
	}
	t := cfg.Tailnet
	if t == nil {
		return fail("the tailnet listener is off (tailnet = off): there is no name to take over")
	}
	isHeadscale := t.ControlURL != ""
	switch {
	case !isHeadscale && c.headscaleURL != "":
		return fail("tailnet_control_url is unset (Tailscale): give --oauth-client-file, not --headscale-url and --headscale-api-key-file; nothing was done")
	case isHeadscale && c.oauthFile != "":
		return fail("tailnet_control_url names a self-hosted control server (%s): give --headscale-url %s --headscale-api-key-file <file>, not --oauth-client-file; nothing was done", t.ControlURL, t.ControlURL)
	case isHeadscale && c.headscaleURL != t.ControlURL:
		return fail("--headscale-url (%s) does not match tailnet_control_url (%s): the API authority must be the installation's own control server; nothing was done", c.headscaleURL, t.ControlURL)
	}
	// The authority's file is checked before anything starts (a symbolic
	// link, another file type, or a mode open to group or others refused),
	// so a restore stops here rather than after its enrolment.
	authorityFile, authorityWhat := c.oauthFile, "the OAuth client file"
	if isHeadscale {
		authorityFile, authorityWhat = c.headscaleKeyFile, "the Headscale API key file"
	}
	if f, err := openSecretFile(authorityFile); err != nil {
		return fail("cannot read %s: %v; nothing was done", authorityWhat, err)
	} else {
		_ = f.Close()
	}
	// The authority given ends with the command, however it ends after the
	// checks above: on Headscale its API key (a full administrator's) is
	// expired on every exit, the ones before the handoff opened it
	// included.
	var cp tailcontrol.ControlPlane
	opened := false
	var openErr error
	if isHeadscale {
		defer func() {
			if cp == nil {
				expireUnopened(cfg, c, opened, openErr, stderr)
			}
		}()
	}
	owner, _, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail("%v; nothing was done", err)
	}
	if st, err := os.Stat(cfg.DataDir); err != nil || !st.IsDir() {
		return fail("the data directory %s does not exist; nothing was done", cfg.DataDir)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return fail("a varlatchd holds the data directory %s: the name is taken over before varlatchd starts; nothing was done", cfg.DataDir)
	}
	if err != nil {
		return fail("cannot lock the data directory %s: %v", cfg.DataDir, err)
	}
	defer unlock()
	defer giveToOwner(cfg.DataDir, owner)
	journal := &takeoverJournal{path: filepath.Join(cfg.DataDir, TakeoverFile), controlURL: t.ControlURL}
	rec, err := journal.readRecord()
	if err != nil {
		return fail("%v", err)
	}
	var prev *tailhandoff.State
	if rec != nil {
		prev = &rec.State
		// A handoff under way goes on against the control server it began
		// on only: a node's id there means nothing on another (Headscale's
		// are small integers two servers share).
		underWay := prev.Phase != tailhandoff.Done && prev.Phase != tailhandoff.Undone
		switch {
		case underWay && rec.ControlURL == "" && t.ControlURL != "":
			// No control server recorded: Tailscale's, or a journal written
			// before the control server was recorded. Either way not known
			// to be this one.
			return fail("the handoff under way (%s) records no control server (Tailscale's, or a journal from before take-name recorded it), so it is not known to have begun against this tailnet_control_url (%s): nothing was done",
				takeoverStep(prev), t.ControlURL)
		case underWay && rec.ControlURL != t.ControlURL:
			return fail("the handoff under way (%s) began against %s, not this tailnet_control_url (%s): set tailnet_control_url back to finish it; nothing was done",
				takeoverStep(prev), controlName(rec.ControlURL), controlName(t.ControlURL))
		}
	}
	hold, err := tailnet.LoadHold(cfg.DataDir)
	if err != nil {
		return fail("%v", err)
	}
	name := strings.ToLower(t.Hostname)
	if prev != nil && prev.Phase == tailhandoff.Done && hold == nil {
		// Done and opened: nothing is left to do (a Headscale key given
		// for this run is expired on the way out).
		return takeNameOut(stdout, c.asJSON, prev, "")
	}
	var op, heldAs string
	switch {
	case hold != nil:
		heldAs = hold.Hostname
		if op = heldOperation(name, heldAs); op == "" {
			return fail("the node is held as %s, not a temporary name of %s (%s-vl-<operation>-n)", heldAs, name, name)
		}
	case prev != nil && prev.Phase == tailhandoff.Switching && prev.IncomingOpened && strings.EqualFold(prev.Plan.Name, name):
		// Stopped after the open removed the hold, before the journal said
		// done: resumed below, it is checked again (finishOpen) and done.
		op = prev.Plan.Operation
		var err error
		if heldAs, err = tailcontrol.TempName(name, op, tailcontrol.RoleNew); err != nil {
			return fail("the handoff's journal names the operation %q: %v", op, err)
		}
	default:
		return fail("the node is not held for a handoff: varlatchd admin tailnet enroll --hostname <temporary name> holds it first")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, tailnet.StateDir, "tailscaled.state")); err != nil {
		return fail("the node is not enrolled: varlatchd admin tailnet enroll first")
	}
	entries, err := outbound.ParseAllow(cfg.OutboundAllow)
	if err != nil {
		return fail("outbound_allow: %v", err)
	}
	policy := outbound.New(entries, outbound.Options{TLS: takeNameTLS})
	defer policy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	opened = true
	cp, err = openTakeNameControl(ctx, cfg, c, policy)
	if err != nil {
		cp, openErr = nil, err
		return fail("%v", err)
	}
	defer closeControlPlane(cp, stderr)

	node, done, err := heldNode(ctx, cfg, heldAs)
	if err != nil {
		return fail("%v", err)
	}
	defer done()
	st, err := node.Status(ctx)
	if err != nil {
		return fail("the node's status: %v", err)
	}
	if t.AuthKeyFile == "" {
		return fail("no auth key (tailnet_auth_key_file): the reach check's probe joins with it (it must be reusable)")
	}
	b, err := os.ReadFile(t.AuthKeyFile)
	if err != nil {
		return fail("cannot read the auth key file: %v", err)
	}
	authKey := strings.TrimSpace(string(b))
	clear(b)
	if authKey == "" {
		return fail("the auth key file %s is empty: the reach check's probe joins with it (it must be reusable)", t.AuthKeyFile)
	}
	he := &tailhandoff.Engine{
		Control:   cp,
		Endpoints: restoreEndpoints{dataDir: cfg.DataDir},
		Resolver:  probeResolver{cfg: cfg, authKey: authKey},
		Journal:   journal,
	}
	tuneTakeName(he)
	// Headscale issues no HTTPS certificates: skip the certificate step and
	// the issuance count on a self-hosted control server.
	certificates := !isHeadscale && t.HTTPSPort != 0
	if certificates {
		he.Certs = nodeCerts{node: node, dataDir: cfg.DataDir, suffix: st.Suffix}
		he.Ledger = &issuanceFile{path: filepath.Join(cfg.DataDir, IssuanceFile)}
	}
	// A handoff under way goes on for the node it planned for only (by its
	// StableID, recorded with the journal: the plan's ids are the control
	// plane's own).
	if rec != nil && prev.Plan.Operation == op && prev.Phase != tailhandoff.Done && prev.Phase != tailhandoff.Undone {
		switch {
		case st.SelfID == "":
			return fail("this node reports no StableID, so the handoff under way cannot be checked as planned for it: nothing was done")
		case rec.IncomingStableID == "" && !(isHeadscale && prev.Plan.IncomingID == st.SelfID):
			// A journal from before the node was recorded: on Headscale the
			// plan's node id is the node's StableID, so it is stamped below
			// when they are the same; elsewhere it cannot be told.
			return fail("the handoff under way records no node (a journal from before take-name recorded it), so it is not known to be planned for this node (%s): nothing was done", st.SelfID)
		case rec.IncomingStableID != "" && rec.IncomingStableID != st.SelfID:
			return fail("the handoff under way planned for the node %s, not this node (%s): nothing was done", rec.IncomingStableID, st.SelfID)
		}
	}
	journal.incomingStableID = st.SelfID
	var state *tailhandoff.State
	switch {
	case prev == nil || prev.Plan.Operation != op || prev.Phase == tailhandoff.Undone:
		state, err = takeOver(ctx, he, journal, cp, op, name, st.SelfID, certificates)
	case prev.Phase == tailhandoff.Prepared:
		if err = stillDead(ctx, cp, prev.Plan.ServingID); err == nil {
			state, err = he.Switch(ctx, op)
		}
	case prev.Phase == tailhandoff.Done:
		state = prev
	default:
		// Interrupted: tailhandoff resumes it (an unfinished switch is
		// undone, the dead node taking its name back); then it is done
		// again.
		state, err = he.Resume(ctx, op)
		if state != nil && state.Phase == tailhandoff.Undone {
			state, err = takeOver(ctx, he, journal, cp, op, name, st.SelfID, certificates)
		}
	}
	if err != nil {
		return fail("%v", err)
	}
	if state == nil || state.Phase != tailhandoff.Done {
		return fail("the handoff ended %v, not done: run take-name again", state)
	}
	return takeNameOut(stdout, c.asJSON, state, st.SelfID)
}

// maxSecretFileBytes bounds a credential file read by take-name.
const maxSecretFileBytes = 64 << 10

// readSecretFile reads a credential file with secret-file checks: no
// symbolic link, regular file, mode 0600 or tighter on Unix, bounded size,
// valid UTF-8, and no NUL byte. The caller clears the returned slice.
func readSecretFile(path string) ([]byte, error) {
	f, err := openSecretFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSecretFileBytes {
		clear(raw)
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxSecretFileBytes)
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		clear(raw)
		return nil, fmt.Errorf("%s contains a NUL byte", path)
	}
	if !utf8.Valid(raw) {
		clear(raw)
		return nil, fmt.Errorf("%s is not valid UTF-8 text", path)
	}
	return raw, nil
}

// openTakeNameControl builds and opens take-name's control plane through
// the outbound policy's tailnet_control client.
func openTakeNameControl(ctx context.Context, cfg *config.Config, c nodeCmd, policy *outbound.Policy) (tailcontrol.ControlPlane, error) {
	if c.headscaleURL != "" {
		raw, err := readSecretFile(c.headscaleKeyFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the Headscale API key file: %w", err)
		}
		key := strings.TrimRight(string(raw), "\r\n")
		clear(raw)
		if key == "" || strings.ContainsAny(key, "\r\n") {
			return nil, fmt.Errorf("the Headscale API key file %s must hold one non-empty line", c.headscaleKeyFile)
		}
		hs, err := tailcontrol.NewHeadscaleAPI(tailcontrol.HeadscaleAPIConfig{
			BaseURL: c.headscaleURL,
			APIKey:  key,
			HTTP:    policy.Client(outbound.TailnetControl),
		})
		key = ""
		if err != nil {
			return nil, err
		}
		if err := hs.Open(ctx); err != nil {
			return nil, headscaleOutboundRefusal(policy, cfg.OutboundAllow, c.headscaleURL, err)
		}
		return hs, nil
	}
	raw, err := readSecretFile(c.oauthFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read the OAuth client file: %w", err)
	}
	var client struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Tailnet      string `json:"tailnet"`
	}
	jerr := json.Unmarshal(raw, &client)
	clear(raw)
	if jerr != nil || client.ClientID == "" || client.ClientSecret == "" {
		return nil, fmt.Errorf("the OAuth client file %s is not {\"clientId\": ..., \"clientSecret\": ...}", c.oauthFile)
	}
	cp, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{
		BaseURL:      takeNameAPI,
		Tailnet:      client.Tailnet,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		HTTP:         policy.Client(outbound.TailnetControl),
	})
	client.ClientSecret = ""
	if err != nil {
		return nil, err
	}
	return cp, nil
}

// closeControlPlane ends take-name's authority on a fresh bounded context
// so a Headscale API key is expired even when the handoff's context ended
// or failed.
func closeControlPlane(cp tailcontrol.ControlPlane, stderr io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cp.Close(ctx); err != nil {
		if hs, ok := cp.(*tailcontrol.HeadscaleAPI); ok && hs.KeyPrefix() != "" {
			fmt.Fprintf(stderr, "varlatchd admin tailnet take-name: warning: could not expire Headscale API key %s (%v): expire it with: headscale apikeys expire --prefix %s\n",
				hs.KeyPrefix(), err, hs.KeyPrefix())
			return
		}
		fmt.Fprintf(stderr, "varlatchd admin tailnet take-name: warning: closing control plane: %v\n", err)
	}
}

// expireUnopened expires the Headscale API key of a take-name that ended
// before its handoff used it (a refusal, or a rerun with nothing left to
// do): through the outbound policy's client, as the handoff would. tried
// says the handoff's own open already failed: then it is not tried again,
// and the operator is told how to expire the key on the control server.
func expireUnopened(cfg *config.Config, c nodeCmd, tried bool, openErr error, stderr io.Writer) {
	manual := func(why error) {
		raw, err := readSecretFile(c.headscaleKeyFile)
		if err != nil {
			return
		}
		prefix := headscaleKeyPrefix(strings.TrimSpace(string(raw)))
		clear(raw)
		if prefix == "" {
			return
		}
		fmt.Fprintf(stderr, "varlatchd admin tailnet take-name: warning: the Headscale API key %s was not expired (%v); if it is still live, expire it on the control server: headscale apikeys expire --prefix %s\n",
			prefix, why, prefix)
	}
	if tried {
		// Why the handoff's open failed: the control server unreachable,
		// or the key refused (expiring too late, already expired).
		if openErr == nil {
			openErr = errors.New("the control server could not be reached with it")
		}
		manual(openErr)
		return
	}
	entries, err := outbound.ParseAllow(cfg.OutboundAllow)
	if err != nil {
		manual(fmt.Errorf("outbound_allow: %w", err))
		return
	}
	policy := outbound.New(entries, outbound.Options{TLS: takeNameTLS})
	defer policy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cp, err := openTakeNameControl(ctx, cfg, c, policy)
	if err != nil {
		manual(err)
		return
	}
	closeControlPlane(cp, stderr)
}

// headscaleKeyPrefix is the part of a Headscale API key that Headscale
// lists and `headscale apikeys expire --prefix` takes: hskey-api-<12> for
// Headscale 0.28 and later, the part before the dot for an earlier key;
// "" for anything else. It names the key without disclosing it.
func headscaleKeyPrefix(key string) string {
	const marker = "hskey-api-"
	if rest, ok := strings.CutPrefix(key, marker); ok {
		if len(rest) > 13 && rest[12] == '-' {
			return marker + rest[:12]
		}
		return ""
	}
	if p, _, ok := strings.Cut(key, "."); ok && len(p) >= 4 && len(p) <= 16 {
		return p
	}
	return ""
}

// headscaleOutboundAllowEntry is the exact outbound_allow entry for a
// canonical self-hosted Headscale URL (https://<IP>[:port]): /32 for IPv4,
// /128 for IPv6, with the explicit port when not 443.
func headscaleOutboundAllowEntry(canonicalURL string) string {
	u, err := url.Parse(canonicalURL)
	if err != nil {
		return ""
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	prefix := "32"
	if addr.Is6() {
		prefix = "128"
	}
	port := u.Port()
	if port == "" {
		return addr.String() + "/" + prefix
	}
	if addr.Is6() {
		return "[" + addr.String() + "/" + prefix + "]:" + port
	}
	return addr.String() + "/" + prefix + ":" + port
}

// headscaleOutboundRefusal adds the exact outbound_allow line to add to
// varlatchd.conf when the outbound policy refused Headscale's IP or port.
func headscaleOutboundRefusal(policy *outbound.Policy, existingAllow, canonicalURL string, cause error) error {
	u, err := url.Parse(canonicalURL)
	if err != nil {
		return cause
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return cause
	}
	addr = addr.Unmap()
	port := 443
	if p := u.Port(); p != "" {
		if n, perr := strconv.Atoi(p); perr == nil {
			port = n
		}
	}
	v := policy.Decide(outbound.Destination{Scheme: "https:", Host: addr.String(), Port: port}, []string{addr.String()})
	if v.Allowed {
		return cause
	}
	label := outbound.Labels[v.Reason]
	if label == "" {
		label = string(v.Reason)
	}
	if v.Reason == outbound.PrivateAddress || v.Reason == outbound.HostOnlyAddress || v.Reason == outbound.PortReason {
		entry := headscaleOutboundAllowEntry(canonicalURL)
		line := "outbound_allow = " + entry
		if existing := strings.TrimSpace(existingAllow); existing != "" {
			line = "outbound_allow = " + existing + ", " + entry
		}
		return fmt.Errorf("the outbound policy refused Headscale at %s (%s): add to varlatchd.conf:\n  %s\n(%v)", canonicalURL, label, line, cause)
	}
	return fmt.Errorf("the outbound policy refused Headscale at %s (%s): %v", canonicalURL, label, cause)
}

// takeOver plans the restore handoff from the control plane's listing and
// runs it: prepared, then switched.
func takeOver(ctx context.Context, he *tailhandoff.Engine, journal *takeoverJournal, cp tailcontrol.ControlPlane, op, name, stableID string, certificates bool) (*tailhandoff.State, error) {
	if err := journal.clear(); err != nil {
		return nil, err
	}
	devices, at, err := listedAt(ctx, cp)
	if err != nil {
		return nil, err
	}
	var dead, incoming []tailcontrol.Device
	for _, d := range devices {
		if strings.EqualFold(d.Name, name) {
			dead = append(dead, d)
		}
		if d.NodeID == stableID || d.ID == stableID {
			incoming = append(incoming, d)
		}
	}
	switch {
	case len(incoming) != 1:
		return nil, fmt.Errorf("the control plane does not list the restored node %s exactly once", stableID)
	case len(dead) == 0:
		return nil, fmt.Errorf("no device is named %s: nothing to take over (the old node was deleted?); varlatchd admin tailnet open, then start varlatchd: it enrols under its own name", name)
	case len(dead) > 1:
		return nil, fmt.Errorf("%d devices are named %s: nothing is renamed", len(dead), name)
	}
	if err := checkDead(dead[0], at); err != nil {
		return nil, err
	}
	plan, err := tailhandoff.NewRestore(op, name, dead[0].ID, incoming[0].ID, certificates)
	if err != nil {
		return nil, err
	}
	if _, err := he.Prepare(ctx, plan); err != nil {
		return nil, err
	}
	if err := stillDead(ctx, cp, dead[0].ID); err != nil {
		return nil, err
	}
	return he.Switch(ctx, op)
}

// listedAt is the tailnet's devices and the listing's time by the control
// plane's clock (its answer's Date header): the dead node's last-seen time
// is the control plane's, so it is judged by that clock, never this
// host's, which may be minutes off. A listing without a usable time is
// refused.
func listedAt(ctx context.Context, cp tailcontrol.ControlPlane) ([]tailcontrol.Device, time.Time, error) {
	cl, ok := cp.(tailcontrol.ClockedLister)
	if !ok {
		return nil, time.Time{}, fmt.Errorf("the %s control plane's listing says no time, by which the old node's last-seen time is judged: nothing was renamed", cp.Kind())
	}
	devices, at, err := cl.DevicesAt(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("listing the tailnet's devices: %w", err)
	}
	if at.IsZero() {
		return nil, time.Time{}, errors.New("the control plane's listing has no Date header (or one that does not parse): the old node's last-seen time is judged by the control plane's clock, never this host's; nothing was renamed")
	}
	// A Date far from this host's clock is not the control plane's own
	// (something between rewrote it) or this host's clock is badly wrong:
	// either way, neither can judge.
	if now := time.Now(); at.Sub(now).Abs() > clockSkewLimit {
		return nil, time.Time{}, fmt.Errorf("the control plane's listing is dated %s, and this host's clock says %s: more than %s apart, so one of them is wrong (a proxy rewriting the Date, or this host's clock); set this host's clock right, or reach the control plane directly, then run take-name again; nothing was renamed",
			at.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), clockSkewLimit)
	}
	return devices, at, nil
}

// checkDead refuses a dead node the control plane does not show dead: one
// connected now, last seen within deadGrace of now (the listing's time by
// the control plane's clock), or with no last-seen time.
func checkDead(d tailcontrol.Device, now time.Time) error {
	var why string
	switch {
	case d.Online:
		why = "is connected to the tailnet now"
	case d.LastSeen.IsZero():
		why = "has no last-seen time from the control plane"
	case now.Sub(d.LastSeen) < deadGrace:
		why = fmt.Sprintf("was last seen at %s, within %s", d.LastSeen.UTC().Format(time.RFC3339), deadGrace)
	default:
		return nil
	}
	return fmt.Errorf("the device %s (%s) under the name %s %s: it may be the old installation still running, and its name is not taken from under it. Stop the old installation (or remove its device from the tailnet), then run take-name again; nothing was renamed", d.Name, d.ID, d.Name, why)
}

// stillDead checks the dead node again from a fresh listing, right before
// the first rename. A device no longer listed was deleted: the switch
// finds its name free.
func stillDead(ctx context.Context, cp tailcontrol.ControlPlane, id string) error {
	devices, at, err := listedAt(ctx, cp)
	if err != nil {
		return err
	}
	for _, d := range devices {
		if d.ID == id {
			return checkDead(d, at)
		}
	}
	return nil
}

func takeNameOut(stdout io.Writer, asJSON bool, s *tailhandoff.State, stableID string) int {
	res := takeNameResult{Operation: s.Plan.Operation, Name: s.Plan.Name, Phase: s.Phase, DeadID: s.Plan.ServingID, IncomingID: s.Plan.IncomingID, StableID: stableID}
	old := "the old node is named " + s.ServingTemp
	if s.ServingGone {
		old = "the old node's device was deleted from the tailnet"
	}
	nodeOut(stdout, asJSON, res, fmt.Sprintf("The restored node holds the tailnet name %s; %s. varlatchd's tailnet listener opens when it starts.", s.Plan.Name, old))
	return ExitOK
}

// heldOperation is the operation a held temporary name carries.
func heldOperation(name, held string) string {
	_, rest, ok := strings.Cut(held, "-vl-")
	if !ok {
		return ""
	}
	op, ok := strings.CutSuffix(rest, "-"+tailcontrol.RoleNew)
	if !ok {
		return ""
	}
	if want, err := tailcontrol.TempName(name, op, tailcontrol.RoleNew); err != nil || want != held {
		return ""
	}
	return op
}

// heldNode is the enrolled node, started in this process under its hold's
// name.
func heldNode(ctx context.Context, cfg *config.Config, hostname string) (*tailnet.TSNode, func(), error) {
	node, err := tailnet.StartNode(tailnet.NodeConfig{Dir: filepath.Join(cfg.DataDir, tailnet.StateDir), Hostname: hostname, ControlURL: nodeControl(cfg), Tags: cfg.Tailnet.Tags, KeyTags: keyTags(cfg)})
	if err != nil {
		return nil, nil, err
	}
	if err := node.Up(ctx); err != nil {
		_ = node.Close()
		return nil, nil, fmt.Errorf("the node did not join its tailnet: %w", err)
	}
	return node, func() { _ = node.Close() }, nil
}

// takeoverJournal is the handoff's journal: one state, in the data
// directory, written durably before each act, with the control server it
// runs against (controlURL: tailnet_control_url, "" for Tailscale's) and
// the incoming node's StableID.
type takeoverJournal struct{ path, controlURL, incomingStableID string }

// takeoverRecord is the journal's file: the handoff's state, its control
// server, and the node it planned for (its StableID, as the node reads
// it).
type takeoverRecord struct {
	tailhandoff.State
	ControlURL       string `json:"controlUrl,omitempty"`
	IncomingStableID string `json:"incomingStableId,omitempty"`
}

func (j *takeoverJournal) readRecord() (*takeoverRecord, error) {
	b, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r takeoverRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("the handoff's journal %s is not readable: %w", j.path, err)
	}
	return &r, nil
}

func (j *takeoverJournal) read() (*tailhandoff.State, error) {
	r, err := j.readRecord()
	if r == nil {
		return nil, err
	}
	return &r.State, nil
}

func (j *takeoverJournal) clear() error {
	err := os.Remove(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (j *takeoverJournal) Load(_ context.Context, op string) (*tailhandoff.State, error) {
	s, err := j.read()
	if err != nil || s == nil || s.Plan.Operation != op {
		return nil, err
	}
	return s, nil
}

func (j *takeoverJournal) Save(_ context.Context, s *tailhandoff.State) error {
	b, err := json.MarshalIndent(takeoverRecord{State: *s, ControlURL: j.controlURL, IncomingStableID: j.incomingStableID}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeDurably(j.path, append(b, '\n'), -1); err != nil {
		return err
	}
	handoffPoint("take-name " + takeoverStep(s))
	return nil
}

// controlName is a control server as the operator knows it.
func controlName(controlURL string) string {
	if controlURL == "" {
		return "Tailscale's control server"
	}
	return controlURL
}

// takeoverStep names what a saved state says was decided last.
func takeoverStep(s *tailhandoff.State) string {
	if s.Phase != tailhandoff.Switching {
		return string(s.Phase)
	}
	switch {
	case s.IncomingOpened:
		return "opening"
	case s.IncomingRenamed:
		return "incoming renamed"
	case s.ServingRenamed:
		return "serving renamed"
	}
	return "switching"
}

// restoreEndpoints: the dead node's installation is gone (never closed or
// reopened); the restored one opens by its hold's removal, and listens
// when varlatchd starts.
type restoreEndpoints struct{ dataDir string }

func (restoreEndpoints) CloseServing(context.Context) error  { return nil }
func (restoreEndpoints) ReopenServing(context.Context) error { return nil }
func (e restoreEndpoints) OpenIncoming(context.Context) error {
	if err := tailnet.ClearHold(e.dataDir); err != nil {
		return err
	}
	handoffPoint("take-name hold cleared")
	return nil
}

// probeResolver is the reach check: a client node joined with the node's
// auth key (tailnet.Reaches), waiting within the handoff's deadline.
type probeResolver struct {
	cfg     *config.Config
	authKey string
}

func (r probeResolver) Reaches(ctx context.Context, name, nodeID string) (bool, error) {
	wait := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl) - 5*time.Second; left < wait {
			wait = max(left, 0)
		}
	}
	dir, err := os.MkdirTemp("", reachDirPrefix)
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(dir)
	res, err := tailnet.Reaches(ctx, tailnet.ProbeConfig{Dir: dir, ControlURL: nodeControl(r.cfg), AuthKey: r.authKey, Tags: r.cfg.Tailnet.Tags, KeyTags: keyTags(r.cfg)}, name, nodeID, wait)
	return res.Reaches, err
}

// nodeCerts are the restored node's certificates (the dead node is never
// asked for one: a restore keeps no rollback window).
type nodeCerts struct {
	node    *tailnet.TSNode
	dataDir string
	suffix  string
}

func (c nodeCerts) Obtain(ctx context.Context, role tailhandoff.Role, name string) error {
	if role != tailhandoff.Incoming {
		return errors.New("a restore asks the dead node for no certificate")
	}
	_, err := obtainNodeCert(ctx, c.node, c.dataDir, name+"."+c.suffix)
	if err != nil && strings.HasPrefix(certRefusal(err).Error(), "rate-limited: ") {
		return fmt.Errorf("%w: %v", tailhandoff.ErrRateLimited, err)
	}
	return err
}

func (c nodeCerts) Expiry(_ context.Context, role tailhandoff.Role, name string) (time.Time, bool, error) {
	if role != tailhandoff.Incoming {
		return time.Time{}, false, nil
	}
	return tailnet.CachedNotAfter(c.dataDir, name+"."+c.suffix)
}

// issuanceFile is the restore's certificate issuance count (go-step6
// decision 16's), in the data directory beside the handoff's journal.
// Until the installation's certificate_issuances table is in this line
// (#344), it is kept here.
type issuanceFile struct{ path string }

type issuance struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	StartedAt time.Time           `json:"startedAt"`
	EndedAt   *time.Time          `json:"endedAt,omitempty"`
	Outcome   tailhandoff.Outcome `json:"outcome,omitempty"`
}

func (l *issuanceFile) read() ([]issuance, error) {
	b, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []issuance
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("the issuance count %s is not readable: %w", l.path, err)
	}
	return out, nil
}

func (l *issuanceFile) write(entries []issuance) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return writeDurably(l.path, append(b, '\n'), -1)
}

func (l *issuanceFile) Count(_ context.Context, name string, since time.Time) (int, error) {
	entries, err := l.read()
	n := 0
	for _, x := range entries {
		if strings.EqualFold(x.Name, name) && !x.StartedAt.Before(since) && x.Outcome != tailhandoff.Refused {
			n++
		}
	}
	return n, err
}

func (l *issuanceFile) Start(_ context.Context, name string, at time.Time) (string, error) {
	entries, err := l.read()
	if err != nil {
		return "", err
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	entries = append(entries, issuance{ID: id, Name: strings.ToLower(name), StartedAt: at.UTC()})
	return id, l.write(entries)
}

func (l *issuanceFile) End(_ context.Context, id string, outcome tailhandoff.Outcome, at time.Time) error {
	entries, err := l.read()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(entries, func(x issuance) bool { return x.ID == id })
	if i < 0 {
		return fmt.Errorf("the issuance count has no attempt %s", id)
	}
	end := at.UTC()
	entries[i].EndedAt, entries[i].Outcome = &end, outcome
	return l.write(entries)
}
