// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The node's side of a tailnet handoff (internal docs/design/go-step7.md
// decision 11, slice 7.5b): what `varlatch migrate` and the restore ask of
// this installation's node, as host commands.
//
//   - `admin tailnet enroll --hostname <temporary name> [--certificate]`,
//     offline, before varlatchd first starts: the node joins under the
//     temporary name, held (tailnet.Hold: varlatchd serves nothing on the
//     tailnet until the handoff opens it), its tailnet pinned from what it
//     observes, and, with --certificate, a certificate for that name,
//     which proves issuance works now. It reports the node's StableID and
//     MagicDNS name. Run again for the same name, it reports again; on an
//     enrolled node no handoff holds, it holds it again only while the
//     control plane names it exactly that (a handoff undone after it
//     opened).
//   - `admin tailnet certificate obtain|expiry --name <name>`: one attempt
//     at the node's certificate for <name>.<pinned suffix>, through the
//     running varlatchd's node (offline: the node started for it); or when
//     the cached one ends, read from the node's state, never issuing.
//   - `admin tailnet open`: the hold ends, and a running varlatchd starts
//     its tailnet listener (and browser endpoint) at once; offline, it
//     listens when it starts. Nothing when there is no hold.
//   - `admin tailnet reaches --name <name> --stable-id <id> [--wait <d>]`:
//     the final check, from a client node: an ephemeral probe node joins
//     with the auth key (reusable, as the restore's probe needs) and looks
//     for <name> among its peers until it is the node with that StableID,
//     or the wait has passed.
//
// None of them opens the database, so they run on the empty data
// directory a migration imports into, and under the migration's gate.
// Files they create as root are given to the data directory's owner.

// nodeCmd is a node command's arguments.
type nodeCmd struct {
	op           string // enroll, certificate, open, reaches
	action       string // certificate: obtain or expiry
	hostname     string
	name         string
	stableID     string
	certificate  bool
	asJSON       bool
	wait, budget time.Duration
}

const nodeUsage = "Usage: varlatchd admin tailnet enroll --hostname <temporary name> [--certificate] [--timeout <d>] [--json] | " +
	"varlatchd admin tailnet certificate obtain --name <name> [--timeout <d>] [--json] | varlatchd admin tailnet certificate expiry --name <name> [--json] | " +
	"varlatchd admin tailnet open [--json] | " +
	"varlatchd admin tailnet reaches --name <name> --stable-id <id> [--wait <d>] [--json]"

// stableIDShape is a node's StableID as a control plane gives it
// (Tailscale's n...CNTRL, Headscale's number).
var stableIDShape = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// isNodeCmd is whether `admin tailnet <op>` is a node command.
func isNodeCmd(rest []string) bool {
	return len(rest) > 0 && (rest[0] == "enroll" || rest[0] == "certificate" || rest[0] == "open" || rest[0] == "reaches")
}

// nodeArgs parses a node command; a non-empty message is a usage error.
func nodeArgs(rest []string) (nodeCmd, string) {
	c := nodeCmd{op: rest[0]}
	args := rest[1:]
	if c.op == "certificate" {
		if len(args) == 0 || (args[0] != "obtain" && args[0] != "expiry") {
			return nodeCmd{}, nodeUsage
		}
		c.action, args = args[0], args[1:]
	}
	value := func(i int) (string, bool) {
		if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "--") {
			return "", false
		}
		return args[i+1], true
	}
	for i := 0; i < len(args); i++ {
		var ok bool
		switch a := args[i]; {
		case a == "--json":
			c.asJSON, ok = true, true
		case a == "--certificate" && c.op == "enroll":
			c.certificate, ok = true, true
		case a == "--hostname" && c.op == "enroll":
			c.hostname, ok = value(i)
			i++
		case a == "--name" && (c.op == "certificate" || c.op == "reaches"):
			c.name, ok = value(i)
			i++
		case a == "--stable-id" && c.op == "reaches":
			c.stableID, ok = value(i)
			i++
		case (a == "--wait" && c.op == "reaches") || (a == "--timeout" && (c.op == "enroll" || c.action == "obtain")):
			var v string
			if v, ok = value(i); ok {
				d, err := time.ParseDuration(v)
				ok = err == nil && d >= 0 && d <= reachMaxWait
				if a == "--wait" {
					c.wait = d
				} else {
					c.budget = d
				}
			}
			i++
		}
		if !ok {
			return nodeCmd{}, nodeUsage
		}
	}
	switch {
	case c.op == "enroll" && !tailnet.ValidHostname(c.hostname):
		return nodeCmd{}, "varlatchd admin tailnet enroll: --hostname takes the node's temporary name (lower-case letters, digits and -, at most 63)"
	case (c.op == "certificate" || c.op == "reaches") && !tailnet.ValidHostname(strings.ToLower(c.name)):
		return nodeCmd{}, "varlatchd admin tailnet " + c.op + ": --name takes a node's name (letters, digits and -, at most 63), without the tailnet's suffix"
	case c.op == "reaches" && !stableIDShape.MatchString(c.stableID):
		return nodeCmd{}, "varlatchd admin tailnet reaches: --stable-id takes the node's StableID, as enroll reports it"
	}
	return c, ""
}

// testTailnetControl is the tailnet control server a crashpoint build's
// G5 gate points varlatchd's node at (tailnethook_crashpoint.go); empty in
// every other build, where nothing sets it.
var testTailnetControl string

// Test hooks: the control server the node commands join (testcontrol), and
// how the node obtains a certificate (a test CA, which writes the node's
// cache as tsnet does).
var (
	nodeControlURL string
	obtainNodeCert = func(ctx context.Context, n *tailnet.TSNode, dataDir, domain string) ([]byte, error) {
		certPEM, keyPEM, err := n.CertPair(ctx, domain, 0)
		clear(keyPEM)
		return certPEM, err
	}
)

func nodeControl(cfg *config.Config) string {
	if nodeControlURL != "" {
		return nodeControlURL
	}
	return cfg.Tailnet.ControlURL
}

// nodeOut writes a node command's result: the document with --json, else
// its text.
func nodeOut(stdout io.Writer, asJSON bool, doc any, text string) {
	if asJSON {
		b, _ := json.Marshal(doc)
		fmt.Fprintln(stdout, string(b))
		return
	}
	fmt.Fprintln(stdout, text)
}

// enrollResult is `admin tailnet enroll --json`.
type enrollResult struct {
	Hostname   string `json:"hostname"`
	DNSName    string `json:"dnsName"`
	StableID   string `json:"stableId"`
	Suffix     string `json:"suffix"`
	TailnetID  string `json:"tailnetId"`
	ControlURL string `json:"controlUrl"`
	// Pinned is the tailnet pinned from this enrolment (its suffix), Open
	// whether the pin holds.
	Pinned string `json:"pinned"`
	Open   bool   `json:"open"`
	Held   bool   `json:"held"`
	// CertificateNotAfter is the temporary name's certificate's end, with
	// --certificate.
	CertificateNotAfter *time.Time `json:"certificateNotAfter,omitempty"`
}

// runTailnetEnroll is `varlatchd admin tailnet enroll`: offline only,
// under the data directory's lock.
func runTailnetEnroll(cfg *config.Config, c nodeCmd, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "varlatchd admin tailnet enroll: "+format+"\n", args...)
		return ExitFailure
	}
	t := cfg.Tailnet
	if t == nil {
		return fail("the tailnet listener is off (tailnet = on in varlatchd.conf enrols a node)")
	}
	if strings.EqualFold(c.hostname, t.Hostname) {
		return fail("%s is the node's configured name: a handoff enrols it under a temporary name, and moves the name to it", c.hostname)
	}
	// A temporary name that reads back as the control plane's collision
	// suffix of the configured one (vault-1 for vault) would latch the
	// node's tailnet closed (name-suffixed).
	if tailnet.SuffixedName(c.hostname, t.Hostname) {
		return fail("%s reads as the control plane's suffix of the configured name %s: a handoff's temporary name is <name>-vl-<operation>-n", c.hostname, t.Hostname)
	}
	owner, _, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail("%v; nothing was written", err)
	}
	// The data directory is setup's (owned by varlatchd's user); one made
	// here as root would be root's.
	if st, err := os.Stat(cfg.DataDir); err != nil || !st.IsDir() {
		return fail("the data directory %s does not exist: setup (or the migration's host install) makes it; nothing was written", cfg.DataDir)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return fail("a varlatchd holds the data directory %s: the node enrols before varlatchd starts; nothing was written", cfg.DataDir)
	}
	if err != nil {
		return fail("cannot lock the data directory %s: %v", cfg.DataDir, err)
	}
	defer unlock()
	defer giveToOwner(cfg.DataDir, owner)
	dir := filepath.Join(cfg.DataDir, tailnet.StateDir)
	hold, err := tailnet.LoadHold(cfg.DataDir)
	if err != nil {
		return fail("%v", err)
	}
	_, err = os.Stat(filepath.Join(dir, "tailscaled.state"))
	enrolled := err == nil
	authKey := ""
	// An enrolled node no handoff holds is held again only when the
	// control plane still names it exactly the temporary name: a handoff
	// undone after it opened gave that name back to it.
	rehold := false
	switch {
	case hold != nil && hold.Hostname != c.hostname:
		// Enrolled or not: a hold written for another name (a run that
		// stopped after it) is that handoff's.
		return fail("the node is held under %s, not %s: one handoff at a time", hold.Hostname, c.hostname)
	case enrolled && hold == nil:
		rehold = true
	case !enrolled:
		if t.AuthKeyFile == "" {
			return fail("no auth key (tailnet_auth_key_file): the node joins with it")
		}
		raw, err := os.ReadFile(t.AuthKeyFile)
		if err != nil {
			return fail("cannot read the auth key file: %v", err)
		}
		authKey = strings.TrimSpace(string(raw))
		clear(raw)
		if authKey == "" {
			return fail("the auth key file %s is empty", t.AuthKeyFile)
		}
		// The hold first: a crash after the join leaves the node held.
		if hold == nil {
			if err := tailnet.SaveHold(cfg.DataDir, &tailnet.Hold{Hostname: c.hostname, Since: time.Now().UTC()}); err != nil {
				return fail("writing the hold: %v", err)
			}
		}
		if err := tailnet.BeginEnrolment(cfg.DataDir); err != nil {
			return fail("recording the enrolment: %v", err)
		}
	}
	budget := c.budget
	if budget == 0 {
		budget = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	controlURL := nodeControl(cfg)
	node, err := tailnet.StartNode(tailnet.NodeConfig{Dir: dir, Hostname: c.hostname, ControlURL: controlURL, AuthKey: authKey, Tags: t.Tags})
	authKey = ""
	if err != nil {
		return fail("%v", err)
	}
	defer node.Close()
	if err := node.Up(ctx); err != nil {
		return fail("the node did not join its tailnet: %v", err)
	}
	// The name first, before the pin's check: a node the control plane
	// named otherwise (its temporary name another node's: temp-1) is
	// refused before anything is recorded of it, so no name-suffixed
	// closure outlives the collision.
	st, err := node.Status(ctx)
	if err != nil {
		return fail("the node's status: %v", err)
	}
	label, _, _ := strings.Cut(st.DNSName, ".")
	if rehold && label != c.hostname {
		return fail("the node is enrolled as %s and not held for a handoff: enroll holds again only a node named %s; nothing was changed", st.DNSName, c.hostname)
	}
	if rehold {
		if err := tailnet.SaveHold(cfg.DataDir, &tailnet.Hold{Hostname: c.hostname, Since: time.Now().UTC()}); err != nil {
			return fail("writing the hold: %v", err)
		}
	}
	if label != c.hostname {
		return fail("the node joined as %s, not %s: the control plane gave it another name (one held by another node?). "+
			"Delete the node in the tailnet's admin console, then enrol again", st.DNSName, c.hostname)
	}
	m, err := tailnet.NewManager(node, controlURL, cfg.DataDir, t.Port, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		return fail("%v", err)
	}
	// While held, the read-back is of the hold's name, never the
	// configured one, which another node holds (no name-suffixed latch).
	m.SetHeldName(c.hostname)
	m.Check(ctx)
	suffix, open := m.Pinned()
	res := enrollResult{Hostname: c.hostname, DNSName: st.DNSName, StableID: st.SelfID, Suffix: st.Suffix, TailnetID: st.TailnetID,
		ControlURL: controlURL, Pinned: suffix, Open: open, Held: true}
	if res.ControlURL == "" {
		res.ControlURL = tailnet.TailscaleControlURL
	}
	if c.certificate {
		certPEM, err := obtainNodeCert(ctx, node, cfg.DataDir, st.DNSName)
		if err != nil {
			return fail("the certificate for %s: %v", st.DNSName, certRefusal(err))
		}
		notAfter, _, err := tailnet.LeafNotAfter(certPEM)
		if err != nil {
			return fail("the certificate for %s: %v", st.DNSName, err)
		}
		res.CertificateNotAfter = &notAfter
	}
	text := fmt.Sprintf("The node joined as %s (StableID %s), held: its tailnet listener stays closed until the handoff opens it.", st.DNSName, st.SelfID)
	nodeOut(stdout, c.asJSON, res, text)
	return ExitOK
}

// certRefusal names a certificate authority's rate-limit refusal, which
// the handoff never tries again.
func certRefusal(err error) error {
	m := strings.ToLower(err.Error())
	if strings.Contains(m, "ratelimited") || strings.Contains(m, "rate limit") || strings.Contains(m, "too many certificates") {
		return fmt.Errorf("rate-limited: %w", err)
	}
	return err
}

// certResult is `admin tailnet certificate obtain|expiry --json`.
type certResult struct {
	Domain   string     `json:"domain"`
	Held     bool       `json:"held"`
	NotAfter *time.Time `json:"notAfter"`
	// Refusal is why an obtain failed: rate-limited or failed.
	Refusal string `json:"refusal,omitempty"`
	Message string `json:"message,omitempty"`
}

// openResult is `admin tailnet open --json`.
type openResult struct {
	Opened  bool `json:"opened"`
	WasHeld bool `json:"wasHeld"`
	// Running is whether a running varlatchd opened its listener now
	// (false: it listens when it starts).
	Running bool `json:"running"`
}

// runTailnetNode is the certificate and open commands, in the daemon
// (env.node set) or offline under the lock (no database).
func runTailnetNode(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	c, msg := nodeArgs(rest)
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	what := "varlatchd admin tailnet " + c.op
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, what+": "+format+"\n", args...)
		return ExitFailure
	}
	cfg := env.cfg
	if cfg.Tailnet == nil {
		return fail("the tailnet listener is off (tailnet = off)")
	}
	if env.node == nil {
		owner, _, err := checkClientDir(cfg.DataDir, os.Getuid())
		if err != nil {
			return fail("%v", err)
		}
		defer giveToOwner(cfg.DataDir, owner)
	}
	hold, err := tailnet.LoadHold(cfg.DataDir)
	if err != nil {
		return fail("%v", err)
	}
	if c.op == "open" {
		res := openResult{Opened: true, WasHeld: hold != nil}
		if env.node != nil {
			res.Running = true
			if err := env.node.open(ctx); err != nil {
				return fail("%v", err)
			}
		} else if err := tailnet.ClearHold(cfg.DataDir); err != nil {
			return fail("removing the hold: %v", err)
		}
		text := "The tailnet listener is open."
		if !res.Running {
			text = "The hold is removed: varlatchd's tailnet listener opens when it starts."
		}
		nodeOut(stdout, c.asJSON, res, text)
		return ExitOK
	}
	pin, err := tailnet.LoadPin(filepath.Join(cfg.DataDir, tailnet.PinFile))
	if err != nil {
		return fail("%v", err)
	}
	if pin == nil || pin.Enrolling || pin.Suffix == "" {
		return fail("the node has no pinned tailnet yet (it has not joined): enrol it first")
	}
	domain := strings.ToLower(c.name) + "." + pin.Suffix
	res := certResult{Domain: domain, Held: hold != nil}
	if c.action == "expiry" {
		notAfter, ok, err := tailnet.CachedNotAfter(cfg.DataDir, domain)
		if err != nil {
			return fail("%v", err)
		}
		text := "The node holds no certificate for " + domain + "."
		if ok {
			res.NotAfter = &notAfter
			text = "The node's certificate for " + domain + " ends " + notAfter.UTC().Format(time.RFC3339) + "."
		}
		nodeOut(stdout, c.asJSON, res, text)
		return ExitOK
	}
	budget := c.budget
	if budget == 0 {
		budget = 170 * time.Second
	}
	octx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	node, done, err := nodeFor(octx, env)
	if err != nil {
		return fail("%v", err)
	}
	defer done()
	certPEM, err := obtainNodeCert(octx, node, cfg.DataDir, domain)
	if err == nil {
		var notAfter time.Time
		if notAfter, _, err = tailnet.LeafNotAfter(certPEM); err == nil {
			res.NotAfter = &notAfter
			if env.node != nil && env.node.cert != nil && strings.EqualFold(env.node.manager.BrowserHost(), domain) {
				// The browser endpoint takes it at once (its own name's
				// only: a held node's temporary name is not its host).
				env.node.cert.Wake()
			}
			nodeOut(stdout, c.asJSON, res, "The node's certificate for "+domain+" ends "+notAfter.UTC().Format(time.RFC3339)+".")
			return ExitOK
		}
	}
	err = certRefusal(err)
	res.Refusal, res.Message = "failed", err.Error()
	if strings.HasPrefix(res.Message, "rate-limited: ") {
		res.Refusal = "rate-limited"
	}
	if c.asJSON {
		nodeOut(stdout, true, res, "")
	}
	return fail("the certificate for %s: %v", domain, err)
}

// nodeFor is the node to ask: the running varlatchd's, or, offline, the
// enrolled node started for this command (it never enrols here).
func nodeFor(ctx context.Context, env *hostEnv) (*tailnet.TSNode, func(), error) {
	if env.node != nil {
		return env.node.node, func() {}, nil
	}
	cfg := env.cfg
	dir := filepath.Join(cfg.DataDir, tailnet.StateDir)
	if _, err := os.Stat(filepath.Join(dir, "tailscaled.state")); err != nil {
		return nil, nil, errors.New("the node is not enrolled: enrol it first")
	}
	hostname := cfg.Tailnet.Hostname
	if h, err := tailnet.LoadHold(cfg.DataDir); err == nil && h != nil {
		hostname = h.Hostname
	}
	node, err := tailnet.StartNode(tailnet.NodeConfig{Dir: dir, Hostname: hostname, ControlURL: nodeControl(cfg), Tags: cfg.Tailnet.Tags})
	if err != nil {
		return nil, nil, err
	}
	if err := node.Up(ctx); err != nil {
		_ = node.Close()
		return nil, nil, fmt.Errorf("the node did not join its tailnet: %w", err)
	}
	return node, func() { _ = node.Close() }, nil
}

// reachDirPrefix names a reach probe's state directory in the system's
// temporary directory.
const reachDirPrefix = "varlatchd-reach-"

// A probe lives at most its --wait (reachMaxWait at most) and its slack
// (the join, at most a minute, and the logout): a directory older than
// that and a margin is a killed probe's, never a running one's.
const (
	reachMaxWait    = 10 * time.Minute
	reachSlack      = 2 * time.Minute
	reachSweepAfter = reachMaxWait + reachSlack + 3*time.Minute
)

// sweepReachDirs removes the reach probes' state directories a killed
// probe left before cutoff: this user's own, directories only, never a
// link.
func sweepReachDirs(tmp string, cutoff time.Time) {
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), reachDirPrefix) {
			continue
		}
		p := filepath.Join(tmp, e.Name())
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || !ownedByMe(st) || st.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(p)
	}
}

// reachOut is `admin tailnet reaches --json`: the probe's findings and
// what they mean.
type reachOut struct {
	tailnet.ReachResult
	Message string `json:"message"`
}

// runTailnetReaches is `varlatchd admin tailnet reaches`: in this process,
// beside a running varlatchd or not; it writes nothing but the probe's
// state, removed after.
func runTailnetReaches(cfg *config.Config, c nodeCmd, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "varlatchd admin tailnet reaches: "+format+"\n", args...)
		return ExitFailure
	}
	t := cfg.Tailnet
	if t == nil {
		return fail("the tailnet listener is off (tailnet = off)")
	}
	if t.AuthKeyFile == "" {
		return fail("no auth key (tailnet_auth_key_file): the probe joins with the node's key, which must be reusable")
	}
	raw, err := os.ReadFile(t.AuthKeyFile)
	if err != nil {
		return fail("cannot read the auth key file: %v", err)
	}
	key := strings.TrimSpace(string(raw))
	clear(raw)
	// A probe stopped by a signal logs out and removes its state, as one
	// that ends; what a killed one left (its node key) is swept here.
	sweepReachDirs(os.TempDir(), time.Now().Add(-reachSweepAfter))
	dir, err := os.MkdirTemp("", reachDirPrefix)
	if err != nil {
		return fail("%v", err)
	}
	defer os.RemoveAll(dir)
	sctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(sctx, c.wait+reachSlack)
	defer cancel()
	res, err := tailnet.Reaches(ctx, tailnet.ProbeConfig{Dir: dir, ControlURL: nodeControl(cfg), AuthKey: key, Tags: t.Tags}, c.name, c.stableID, c.wait)
	if err != nil {
		return fail("%v", err)
	}
	out := reachOut{ReachResult: res}
	tags := strings.Join(t.Tags, ", ")
	switch {
	case res.Reaches:
		out.Message = fmt.Sprintf("%s reaches the node %s from a client node.", c.name, c.stableID)
	case len(res.Holders) == 0:
		// Seeing nothing is most often the access rules: the probe has the
		// node's tags, and sees only the peers those rules let it see. It
		// fails closed all the same: an unproven reach is undone.
		out.Message = fmt.Sprintf("The probe (tags %s) saw no node named %s. The tailnet's access rules must let the node's tags (%s) see each other: "+
			"a node with those tags must be allowed to reach another (in Tailscale's policy file, a grant or ACL from %s to %s). "+
			"Until it can, the name's reach cannot be proven, and the handoff is undone.", tags, c.name, tags, tags, tags)
	default:
		out.Message = fmt.Sprintf("%s does not reach the node %s from a client node yet.", c.name, c.stableID)
	}
	nodeOut(stdout, c.asJSON, out, out.Message)
	if !c.asJSON && !res.Reaches {
		return ExitFailure
	}
	return ExitOK
}
