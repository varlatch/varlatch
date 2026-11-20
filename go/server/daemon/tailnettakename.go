// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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
// `varlatchd admin tailnet take-name --oauth-client-file <file> [--json]`
// runs offline, under the data directory's lock, after `tailnet enroll`
// held the restored node under its temporary name (<name>-vl-<op>-n) and
// before varlatchd first starts:
//   - the control plane is Tailscale's API with the operator's OAuth client
//     (devices:core only, O4), read from its file, and the outbound
//     policy's client (go/server/outbound, purpose tailnet_control);
//   - the dead node is the one device under the configured name; it is
//     renamed to <name>-vl-<op>-o and the restored node to the name, each
//     read back; with tailnet HTTPS the name's certificate is obtained
//     (counted in tailnet-issuances.json); a client node (the reach probe)
//     must see the name reach the restored node; then the hold is removed,
//     so varlatchd listens when it starts. The dead node is never closed or
//     reopened.
//   - the handoff's state is journalled in tailnet-takeover.json (0600)
//     before each act; run again, take-name resumes it, never guessing: an
//     interrupted switch is undone (the dead node takes its name back), then
//     done again.

// The data directory's files of a restore's handoff.
const (
	TakeoverFile = "tailnet-takeover.json"
	IssuanceFile = "tailnet-issuances.json"
)

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
	journal := &takeoverJournal{path: filepath.Join(cfg.DataDir, TakeoverFile)}
	prev, err := journal.read()
	if err != nil {
		return fail("%v", err)
	}
	hold, err := tailnet.LoadHold(cfg.DataDir)
	if err != nil {
		return fail("%v", err)
	}
	name := strings.ToLower(t.Hostname)
	if prev != nil && prev.Phase == tailhandoff.Done && hold == nil {
		// Done and opened: nothing is left to do.
		return takeNameOut(stdout, c.asJSON, prev, "")
	}
	if hold == nil {
		return fail("the node is not held for a handoff: varlatchd admin tailnet enroll --hostname <temporary name> holds it first")
	}
	op := heldOperation(name, hold.Hostname)
	if op == "" {
		return fail("the node is held as %s, not a temporary name of %s (%s-vl-<operation>-n)", hold.Hostname, name, name)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, tailnet.StateDir, "tailscaled.state")); err != nil {
		return fail("the node is not enrolled: varlatchd admin tailnet enroll first")
	}
	raw, err := os.ReadFile(c.oauthFile)
	if err != nil {
		return fail("cannot read the OAuth client file: %v", err)
	}
	var client struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Tailnet      string `json:"tailnet"`
	}
	jerr := json.Unmarshal(raw, &client)
	clear(raw)
	if jerr != nil || client.ClientID == "" || client.ClientSecret == "" {
		return fail("the OAuth client file %s is not {\"clientId\": ..., \"clientSecret\": ...}", c.oauthFile)
	}
	entries, err := outbound.ParseAllow(cfg.OutboundAllow)
	if err != nil {
		return fail("outbound_allow: %v", err)
	}
	policy := outbound.New(entries, outbound.Options{TLS: takeNameTLS})
	defer policy.Close()
	cp, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: takeNameAPI, Tailnet: client.Tailnet, ClientID: client.ClientID,
		ClientSecret: client.ClientSecret, HTTP: policy.Client(outbound.TailnetControl)})
	client.ClientSecret = ""
	if err != nil {
		return fail("%v", err)
	}
	defer func() { _ = cp.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	node, done, err := heldNode(ctx, cfg, hold.Hostname)
	if err != nil {
		return fail("%v", err)
	}
	defer done()
	st, err := node.Status(ctx)
	if err != nil {
		return fail("the node's status: %v", err)
	}
	authKey := ""
	if t.AuthKeyFile != "" {
		if b, err := os.ReadFile(t.AuthKeyFile); err == nil {
			authKey = strings.TrimSpace(string(b))
			clear(b)
		}
	}
	if authKey == "" {
		return fail("no auth key (tailnet_auth_key_file): the reach check's probe joins with it (it must be reusable)")
	}
	he := &tailhandoff.Engine{
		Control:   cp,
		Endpoints: restoreEndpoints{dataDir: cfg.DataDir},
		Resolver:  probeResolver{cfg: cfg, authKey: authKey},
		Journal:   journal,
	}
	tuneTakeName(he)
	certificates := t.HTTPSPort != 0
	if certificates {
		he.Certs = nodeCerts{node: node, dataDir: cfg.DataDir, suffix: st.Suffix}
		he.Ledger = &issuanceFile{path: filepath.Join(cfg.DataDir, IssuanceFile)}
	}
	var state *tailhandoff.State
	switch {
	case prev == nil || prev.Plan.Operation != op || prev.Phase == tailhandoff.Undone:
		state, err = takeOver(ctx, he, journal, cp, op, name, st.SelfID, certificates)
	case prev.Phase == tailhandoff.Prepared:
		state, err = he.Switch(ctx, op)
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

// takeOver plans the restore handoff from the control plane's listing and
// runs it: prepared, then switched.
func takeOver(ctx context.Context, he *tailhandoff.Engine, journal *takeoverJournal, cp tailcontrol.ControlPlane, op, name, stableID string, certificates bool) (*tailhandoff.State, error) {
	if err := journal.clear(); err != nil {
		return nil, err
	}
	devices, err := cp.Devices(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing the tailnet's devices: %w", err)
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
	plan, err := tailhandoff.NewRestore(op, name, dead[0].ID, incoming[0].ID, certificates)
	if err != nil {
		return nil, err
	}
	if _, err := he.Prepare(ctx, plan); err != nil {
		return nil, err
	}
	return he.Switch(ctx, op)
}

func takeNameOut(stdout io.Writer, asJSON bool, s *tailhandoff.State, stableID string) int {
	res := takeNameResult{Operation: s.Plan.Operation, Name: s.Plan.Name, Phase: s.Phase, DeadID: s.Plan.ServingID, IncomingID: s.Plan.IncomingID, StableID: stableID}
	nodeOut(stdout, asJSON, res, fmt.Sprintf("The restored node holds the tailnet name %s; the old node is named %s. varlatchd's tailnet listener opens when it starts.", s.Plan.Name, s.ServingTemp))
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
	node, err := tailnet.StartNode(tailnet.NodeConfig{Dir: filepath.Join(cfg.DataDir, tailnet.StateDir), Hostname: hostname, ControlURL: nodeControl(cfg), Tags: cfg.Tailnet.Tags})
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
// directory, written durably before each act.
type takeoverJournal struct{ path string }

func (j *takeoverJournal) read() (*tailhandoff.State, error) {
	b, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s tailhandoff.State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("the handoff's journal %s is not readable: %w", j.path, err)
	}
	return &s, nil
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
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeDurably(j.path, append(b, '\n'), -1); err != nil {
		return err
	}
	handoffPoint("take-name " + takeoverStep(s))
	return nil
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
	return tailnet.ClearHold(e.dataDir)
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
	res, err := tailnet.Reaches(ctx, tailnet.ProbeConfig{Dir: dir, ControlURL: nodeControl(r.cfg), AuthKey: r.authKey, Tags: r.cfg.Tailnet.Tags}, name, nodeID, wait)
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
