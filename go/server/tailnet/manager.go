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
//
// Tailnet access is open only while a pin is recorded and not closed, and
// the last check of the node succeeded on the pinned tailnet. Every time
// access closes, the admission context of every request admitted while it
// was open is cancelled, and the resolutions made then stop counting
// (Admit, Valid): a generation number tells the open periods apart.
type Manager struct {
	node       StatusNode
	controlURL string
	dataDir    string
	port       int
	log        *slog.Logger
	now        func() time.Time

	// checking serializes checks and re-pins: a slower, older reading of
	// the node never overwrites a newer one.
	checking sync.Mutex

	mu  sync.Mutex
	pin *Pin
	// missing: no pin file, but the node was enrolled before; closed until
	// the host adopts (Repin with adopt).
	missing bool
	// observed is what the last check saw; nil after a check that failed
	// or found the node not running on a tailnet.
	observed  *Observed
	verdict   string // Pin.Check's on observed, "" while it holds
	status    *Status
	statusErr bool
	listening *bool
	checkedAt *time.Time
	persisted struct {
		json string
		at   time.Time
	}
	// The open period: whether access is open, its generation, and the
	// cancellation of every request admitted in it.
	open     bool
	gen      uint64
	admitted map[*admission]struct{}
}

type admission struct{ cancel context.CancelFunc }

// PinMissing is why access is closed for an enrolled node without a pin.
const PinMissing = "pin-missing"

// NewManager loads the pin from dataDir; controlURL is the configured one
// ("" for Tailscale's), port the tailnet listener's. Without a pin file
// the node is taken as enrolled before, and access stays closed until the
// host adopts its tailnet: a new node's pin file is BeginEnrolment's.
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
	m := &Manager{node: node, controlURL: controlURL, dataDir: dataDir, port: port, log: log, now: now, pin: pin, missing: pin == nil}
	m.admitted = map[*admission]struct{}{}
	if m.missing {
		log.Error("the tailnet node has no pin but was enrolled before; tailnet access is closed until the host adopts its tailnet (varlatchd admin tailnet repin)")
	} else if pin.Closed != nil {
		log.Error("tailnet access is closed since the tailnet stopped matching its pin; re-pin on the host to reopen it", "reason", pin.Closed.Reason, "since", pin.Closed.Since)
	}
	return m, nil
}

// openLocked is whether tailnet access is open now.
func (m *Manager) openLocked() bool {
	return m.pin != nil && !m.pin.Enrolling && m.pin.Closed == nil && !m.missing && m.observed != nil && m.verdict == ""
}

// settleLocked starts a new open period when access opened or closed: the
// old period's admitted requests are cancelled before it returns, its
// resolutions void.
func (m *Manager) settleLocked() {
	if open := m.openLocked(); open != m.open {
		m.open = open
		for a := range m.admitted {
			a.cancel()
		}
		clear(m.admitted)
		m.gen++
	}
}

// Pinned is the pinned suffix and whether tailnet access is open.
func (m *Manager) Pinned() (string, bool) {
	suffix, _, open := m.Current()
	return suffix, open
}

// Current is the pinned suffix, the open period's generation, and whether
// tailnet access is open.
func (m *Manager) Current() (string, uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.open {
		return "", m.gen, false
	}
	return m.pin.Suffix, m.gen, true
}

// Valid is whether access is still open in the period gen was taken in.
func (m *Manager) Valid(gen uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.open && m.gen == gen
}

// Admit admits a request on a tailnet listener while access is open: its
// context is cancelled the moment access closes (release ends the tie).
// While access is closed every request is refused.
func (m *Manager) Admit(ctx context.Context) (context.Context, func(), bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.open {
		return nil, nil, false
	}
	rctx, cancel := context.WithCancel(ctx)
	a := &admission{cancel: cancel}
	m.admitted[a] = struct{}{}
	return rctx, func() {
		m.mu.Lock()
		delete(m.admitted, a)
		m.mu.Unlock()
		cancel()
	}, true
}

// Closed is why tailnet access is closed ("" while open): not enrolled
// yet, the pin missing, the closure latched (the tailnet changed), the
// tailnet not known now, or the pin not holding.
func (m *Manager) Closed() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.missing:
		return PinMissing
	case m.pin == nil || m.pin.Enrolling:
		return "not-enrolled"
	case m.pin.Closed != nil:
		return m.pin.Closed.Reason
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

// Check reads the node: on the first Running status with a tailnet of an
// enrolling node, the pin is recorded; after that it is checked, and a
// mismatch closes tailnet access and is latched. A check that fails, or
// finds the node not running on a tailnet, closes access too, until a
// check succeeds. Then the report is rebuilt and, when it changed, written
// to the data directory.
func (m *Manager) Check(ctx context.Context) {
	m.checking.Lock()
	defer m.checking.Unlock()
	m.checkLocked(ctx)
}

func (m *Manager) checkLocked(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	st, err := m.node.Status(cctx)
	cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.settleLocked()
	now := m.now()
	m.checkedAt = &now
	// Trust rests on this reading only.
	m.observed, m.verdict = nil, ""
	if err != nil {
		if !m.statusErr {
			m.log.Warn("tailnet listener check: the node's status failed; tailnet access is closed until it answers", "error", err)
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
	if m.pin != nil && m.pin.Enrolling {
		p := &Pin{ControlURL: o.ControlURL, TailnetID: o.TailnetID, Suffix: o.Suffix, PinnedAt: now.UTC().Format(time.RFC3339)}
		if err := SavePin(filepath.Join(m.dataDir, PinFile), p); err != nil {
			m.log.Error("could not record the tailnet pin; tailnet access stays closed", "error", err)
			m.persistLocked()
			return
		}
		m.pin = p
		m.log.Info("pinned the tailnet at enrolment", "suffix", p.Suffix, "tailnetId", p.TailnetID, "controlUrl", p.ControlURL)
	}
	if m.pin == nil {
		m.persistLocked()
		return
	}
	m.verdict = m.pin.Check(o)
	if m.verdict != "" && m.pin.Closed == nil {
		m.log.Error("the tailnet no longer matches its pin; tailnet access is closed until it is re-pinned on the host",
			"reason", m.verdict, "pinnedSuffix", m.pin.Suffix, "observedSuffix", o.Suffix, "pinnedTailnetId", m.pin.TailnetID, "observedTailnetId", o.TailnetID)
		closed := *m.pin
		closed.Closed = &Closure{Reason: m.verdict, Since: now.UTC().Format(time.RFC3339), Observed: o}
		// Latched in memory whatever happens to the file.
		if err := SavePin(filepath.Join(m.dataDir, PinFile), &closed); err != nil {
			m.log.Error("could not record the tailnet pin's closure; it holds until varlatchd stops", "error", err)
		}
		m.pin = &closed
	}
	m.persistLocked()
}

// RepinView is what a re-pin shows the operator.
type RepinView struct {
	Pinned   *Pin
	Observed *Observed
	// Reason is Pin.Check's on what the node is on now, "" when it holds.
	Reason string
	// Closed is the latched closure's reason, "" when none.
	Closed string
	// Missing: the node was enrolled before but its pin is missing; only
	// an adoption pins it.
	Missing bool
	// Offered is whether a re-pin (or, when Missing, an adoption) may take
	// the observed tailnet.
	Offered bool
}

// RepinView is the pinned and the observed tailnet, from a fresh check.
func (m *Manager) RepinView(ctx context.Context) RepinView {
	m.checking.Lock()
	defer m.checking.Unlock()
	m.checkLocked(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked()
}

func (m *Manager) viewLocked() RepinView {
	v := RepinView{Pinned: m.pin, Observed: m.observed, Reason: m.verdict, Missing: m.missing}
	if m.pin != nil && m.pin.Closed != nil {
		v.Closed = m.pin.Closed.Reason
	}
	switch {
	case m.observed == nil:
	case m.missing:
		v.Offered = true
	case m.pin != nil && !m.pin.Enrolling:
		v.Offered = v.Reason == PinSuffix || v.Reason == "" && v.Closed != ""
	}
	return v
}

var (
	// ErrNothingToRepin: the node's tailnet is not known now.
	ErrNothingToRepin = errors.New("tailnet: the node's tailnet is not known now (is it enrolled and running?); nothing is re-pinned without a current observation")
	// ErrPinMissing: an enrolled node without a pin, and no adoption asked.
	ErrPinMissing = errors.New("tailnet: the pin is missing for a node enrolled before; tailnet access stays closed until the host adopts the tailnet the node is on (--adopt)")
)

// Repin re-pins from a fresh, successful check, and reopens tailnet
// access: the observed suffix when it is the only change, or the same pin
// when the tailnet changed back (Pin.Repin); with adopt, the observed
// tailnet when the pin is missing. It returns the old and the new pin (old
// nil on an adoption; new nil when there was nothing to do). Only the host
// calls it (`varlatchd admin tailnet repin`, which step 6's `varlatch
// tailnet repin` runs).
func (m *Manager) Repin(ctx context.Context, adopt bool) (*Pin, *Pin, error) {
	m.checking.Lock()
	defer m.checking.Unlock()
	m.checkLocked(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.observed == nil {
		return m.pin, nil, ErrNothingToRepin
	}
	now := m.now()
	var next *Pin
	switch {
	case m.missing && !adopt:
		return nil, nil, ErrPinMissing
	case m.missing:
		o := *m.observed
		next = &Pin{ControlURL: o.ControlURL, TailnetID: o.TailnetID, Suffix: o.Suffix, PinnedAt: now.UTC().Format(time.RFC3339)}
	case m.pin.Enrolling:
		return m.pin, nil, nil
	default:
		var err error
		if next, err = m.pin.Repin(*m.observed, now); err != nil || next == nil {
			return m.pin, nil, err
		}
	}
	if err := SavePin(filepath.Join(m.dataDir, PinFile), next); err != nil {
		return m.pin, nil, err
	}
	old := m.pin
	m.pin, m.missing, m.verdict = next, false, next.Check(*m.observed)
	if old == nil {
		m.log.Warn("adopted the tailnet on the host as the pin", "suffix", next.Suffix, "tailnetId", next.TailnetID)
	} else {
		m.log.Warn("re-pinned the tailnet on the host", "from", old.Suffix, "to", next.Suffix, "tailnetId", next.TailnetID)
	}
	m.settleLocked()
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
		case !m.open:
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
	key := string(jsvalue.Stringify(jsvalue.Object{{Key: "checks", Value: checks}, {Key: "node", Value: node}, {Key: "pin", Value: m.verdict}, {Key: "open", Value: m.open}}))
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
		Closed   string    `json:"closed"`
		Missing  bool      `json:"missing"`
		Offered  bool      `json:"offered"`
	}
	return json.Marshal(view(v))
}
