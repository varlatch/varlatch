// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// StatusNode is the part of a node the manager reads.
type StatusNode interface {
	Status(ctx context.Context) (Status, error)
}

// Files of the tailnet in the data directory.
const (
	// PinFile is the pin; StateDir the node's state (secret, never in a
	// backup); ListenersFile the last listeners report, for host commands
	// (the TypeScript server's LISTENERS_STATUS_FILE).
	PinFile       = "tailnet-pin.json"
	StateDir      = "tailnet"
	ListenersFile = "tailnet-listeners.json"
)

// CheckEvery is how often the manager reads the node (observe.ts).
const CheckEvery = time.Minute

// refreshFile: the listeners file is rewritten when a check changes, and at
// least this often, so a reader can tell a stale one.
const refreshFile = 5 * time.Minute

// Manager keeps the pin and what varlatchd last observed of its tailnet
// listener (ADR-0046, Listener metadata): never reachability, which only a
// client can find out.
type Manager struct {
	node       StatusNode
	controlURL string
	dataDir    string
	port       int
	log        *slog.Logger
	now        func() time.Time

	mu        sync.Mutex
	pin       *Pin
	verdict   string // Pin.Check's, "" while it holds
	observed  *Observed
	status    *Status
	statusErr bool
	listening *bool
	checkedAt *time.Time
	persisted struct {
		json string
		at   time.Time
	}
}

// NewManager loads the pin from dataDir; controlURL is the configured one
// ("" for Tailscale's), port the tailnet listener's.
func NewManager(node StatusNode, controlURL, dataDir string, port int, log *slog.Logger, now func() time.Time) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	pin, err := LoadPin(filepath.Join(dataDir, PinFile))
	if err != nil {
		return nil, err
	}
	return &Manager{node: node, controlURL: controlURL, dataDir: dataDir, port: port, log: log, now: now, pin: pin}, nil
}

// Pinned is the pinned suffix and whether tailnet access is open: a pin
// recorded, and holding for what the node last said.
func (m *Manager) Pinned() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pin == nil || m.observed == nil || m.verdict != "" {
		return "", false
	}
	return m.pin.Suffix, true
}

// Closed is why tailnet access is closed ("" while open): no pin yet, or
// the pin no longer holding.
func (m *Manager) Closed() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.pin == nil:
		return "not-enrolled"
	case m.observed == nil:
		return PinUnknown
	}
	return m.verdict
}

// Listening records whether the tailnet listener bound its port.
func (m *Manager) Listening(ok bool) {
	m.mu.Lock()
	m.listening = &ok
	m.mu.Unlock()
}

// Check reads the node: on the first Running status with a tailnet, the
// pin is recorded (enrolment); after that it is checked, and a change
// closes tailnet access. Then the report is rebuilt and, when it changed,
// written to the data directory.
func (m *Manager) Check(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	st, err := m.node.Status(cctx)
	cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.checkedAt = &now
	if err != nil {
		if !m.statusErr {
			m.log.Warn("tailnet listener check: the node's status failed", "error", err)
		}
		m.status, m.statusErr = nil, true
		m.persistLocked()
		return
	}
	m.status, m.statusErr = &st, false
	if st.BackendState != "Running" || st.Suffix == "" {
		m.persistLocked()
		return
	}
	o := Observed{ControlURL: m.controlURL, TailnetID: st.TailnetID, Suffix: normalize(st.Suffix)}
	m.observed = &o
	if m.pin == nil {
		p := &Pin{ControlURL: o.ControlURL, TailnetID: o.TailnetID, Suffix: o.Suffix, PinnedAt: now.UTC().Format(time.RFC3339)}
		if err := SavePin(filepath.Join(m.dataDir, PinFile), p); err != nil {
			m.log.Error("could not record the tailnet pin; tailnet access stays closed", "error", err)
		} else {
			m.pin = p
			m.log.Info("pinned the tailnet at enrolment", "suffix", p.Suffix, "tailnetId", p.TailnetID, "controlUrl", p.ControlURL)
		}
	}
	if m.pin != nil {
		verdict := m.pin.Check(o)
		if verdict != m.verdict && verdict != "" {
			m.log.Error("the tailnet no longer matches its pin; tailnet access is closed until it is re-pinned on the host",
				"reason", verdict, "pinnedSuffix", m.pin.Suffix, "observedSuffix", o.Suffix, "pinnedTailnetId", m.pin.TailnetID, "observedTailnetId", o.TailnetID)
		}
		m.verdict = verdict
	}
	m.persistLocked()
}

// RepinView is what a re-pin shows the operator.
type RepinView struct {
	Pinned   *Pin
	Observed *Observed
	// Reason is Pin.Check's, "" when nothing changed.
	Reason string
	// Offered is whether a re-pin may take observed.
	Offered bool
}

// RepinView is the pinned and the observed tailnet, from a fresh check.
func (m *Manager) RepinView(ctx context.Context) RepinView {
	m.Check(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	v := RepinView{Pinned: m.pin, Observed: m.observed}
	if m.pin != nil && m.observed != nil {
		v.Reason = m.pin.Check(*m.observed)
		v.Offered = v.Reason == PinSuffix
	}
	return v
}

// ErrNothingToRepin: no pin, or the node does not know its tailnet.
var ErrNothingToRepin = errors.New("tailnet: there is no pin and observed tailnet to compare: is the node enrolled and running?")

// Repin takes the observed suffix as the pin's, when the suffix is the
// only change (Pin.Repin), and reopens tailnet access. It returns the old
// and the new pin. Only the host calls it (`varlatchd admin tailnet
// repin`, which step 6's `varlatch tailnet repin` runs).
func (m *Manager) Repin(ctx context.Context) (*Pin, *Pin, error) {
	m.Check(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pin == nil || m.observed == nil {
		return nil, nil, ErrNothingToRepin
	}
	next, err := m.pin.Repin(*m.observed, m.now())
	if err != nil || next == nil {
		return m.pin, nil, err
	}
	if err := SavePin(filepath.Join(m.dataDir, PinFile), next); err != nil {
		return m.pin, nil, err
	}
	old := m.pin
	m.pin, m.verdict = next, ""
	m.log.Warn("re-pinned the tailnet on the host", "from", old.Suffix, "to", next.Suffix, "tailnetId", next.TailnetID)
	m.persistLocked()
	return old, next, nil
}

// Report is the listeners report (TailnetListenerReport), as GET
// /v1/installation/listeners answers it.
func (m *Manager) Report() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reportLocked()
}

var (
	// observe.ts's checks of the node's own details: a field that does not
	// pass is left out, never guessed.
	dnsName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	tagName  = regexp.MustCompile(`^tag:[A-Za-z][A-Za-z0-9-]*$`)
	stableID = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

func check(status, reason string) jsvalue.Object {
	o := jsvalue.Object{{Key: "status", Value: status}}
	if reason != "" {
		o = append(o, jsvalue.Member{Key: "reason", Value: reason})
	}
	return o
}

func (m *Manager) reportLocked() jsvalue.Object {
	unchecked := check("unknown", "NOT_CHECKED")
	tailnetName := ""
	if m.pin != nil {
		tailnetName = m.pin.Suffix
	}
	configured := jsvalue.Object{{Key: "tailnet", Value: tailnetName}, {Key: "listenerPort", Value: m.port}, {Key: "browserEndpoint", Value: nil}}
	listener, localAPI, node := unchecked, unchecked, unchecked
	switch {
	case m.listening == nil:
	case *m.listening:
		listener = check("pass", "")
	default:
		listener = check("fail", "NOT_LISTENING")
	}
	var details jsvalue.Object
	switch {
	case m.statusErr:
		localAPI = check("fail", "LOCALAPI_UNAVAILABLE")
	case m.status != nil:
		localAPI = check("pass", "")
		st := m.status
		switch {
		case st.BackendState != "Running":
			node = check("fail", "NOT_RUNNING")
		case m.pin == nil || m.verdict != "" || normalize(st.Suffix) != m.pin.Suffix:
			node = check("fail", "OTHER_TAILNET")
		default:
			node = check("pass", "")
		}
		details = observedNode(st)
	}
	var checkedAt any
	if m.checkedAt != nil {
		checkedAt = audit.ISOTime(m.checkedAt.UnixMicro())
	}
	observed := jsvalue.Object{{Key: "checkedAt", Value: checkedAt}, {Key: "checks", Value: jsvalue.Object{
		{Key: "listener", Value: listener}, {Key: "localApi", Value: localAPI}, {Key: "node", Value: node},
	}}}
	if len(details) > 0 {
		observed = append(observed, jsvalue.Member{Key: "node", Value: details})
	}
	return jsvalue.Object{{Key: "configured", Value: configured}, {Key: "observed", Value: observed}}
}

// observedNode is observe.ts's observedNode: each field checked, one that
// does not pass left out.
func observedNode(st *Status) jsvalue.Object {
	var o jsvalue.Object
	if dnsName.MatchString(st.DNSName) && len(st.DNSName) <= 253 {
		host, _, _ := strings.Cut(st.DNSName, ".")
		o = append(o, jsvalue.Member{Key: "name", Value: host}, jsvalue.Member{Key: "dnsName", Value: st.DNSName})
	}
	if s := normalize(st.Suffix); dnsName.MatchString(s) && len(s) <= 253 {
		o = append(o, jsvalue.Member{Key: "tailnet", Value: s})
	}
	if all(st.Tags, tagName.MatchString) {
		o = append(o, jsvalue.Member{Key: "tags", Value: tags(st.Tags)})
	}
	if all(st.Addresses, func(a string) bool { _, err := netip.ParseAddr(a); return err == nil }) {
		o = append(o, jsvalue.Member{Key: "addresses", Value: tags(st.Addresses)})
	}
	if stableID.MatchString(st.SelfID) {
		o = append(o, jsvalue.Member{Key: "nodeId", Value: st.SelfID})
	}
	return o
}

// all is a non-empty list whose every entry passes: a partial list would
// read as complete.
func all(list []string, ok func(string) bool) bool {
	if len(list) == 0 {
		return false
	}
	for _, s := range list {
		if !ok(s) {
			return false
		}
	}
	return true
}

// persistLocked writes the report for host commands, when its checks or
// node changed, or the file is older than refreshFile.
func (m *Manager) persistLocked() {
	report := m.reportLocked()
	observed, _ := report.Get("observed")
	checks, _ := observed.(jsvalue.Object).Get("checks")
	node, _ := observed.(jsvalue.Object).Get("node")
	key := string(jsvalue.Stringify(jsvalue.Object{{Key: "checks", Value: checks}, {Key: "node", Value: node}, {Key: "pin", Value: m.verdict}}))
	now := m.now()
	if m.persisted.json == key && now.Sub(m.persisted.at) < refreshFile {
		return
	}
	b := append(jsvalue.Stringify(report), '\n')
	path := filepath.Join(m.dataDir, ListenersFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		m.log.Warn("could not record the tailnet listener status", "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		m.log.Warn("could not record the tailnet listener status", "error", err)
		return
	}
	m.persisted.json, m.persisted.at = key, now
}

// MarshalJSON lets a view print as JSON (the host command's --json).
func (v RepinView) MarshalJSON() ([]byte, error) {
	type view struct {
		Pinned   *Pin      `json:"pinned"`
		Observed *Observed `json:"observed"`
		Reason   string    `json:"reason"`
		Offered  bool      `json:"offered"`
	}
	return json.Marshal(view(v))
}
