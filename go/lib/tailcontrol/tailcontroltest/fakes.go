// SPDX-License-Identifier: Apache-2.0

// Package tailcontroltest serves fakes of the two control planes
// tailcontrol speaks to, for tests: Tailscale's API (OAuth token exchange,
// device listing, rename) and Headscale's API and CLI (key listing and
// expiry, node listing, rename).
//
// They follow the behaviour ADR-0059 Decision 9 records from the spikes:
// Tailscale silently rewrites a requested name that is not canonical
// (lowercase, other characters made hyphens) and refuses a name another
// device holds; Headscale keeps a name as given, so it accepts a case
// variant ("VAULT" beside "vault"), and refuses only the exact name. They
// are fakes, not the real control planes: the real APIs are checked by
// hand against the owner's throwaway tailnet and Headscale (O6) in 7.5b.
// Every credential they accept is made at random when they start; none is
// a literal.
package tailcontroltest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Node is a device in a fake's tailnet.
type Node struct {
	ID       string // Tailscale's device id; Headscale's node id (a number)
	NodeID   string // Tailscale's stable node id
	Name     string // the machine name (Tailscale) or given name (Headscale)
	Online   bool
	Expires  time.Time // zero: never
	LastSeen time.Time
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Tailscale is a fake of Tailscale's API for one tailnet.
type Tailscale struct {
	*httptest.Server
	ClientID, ClientSecret string
	// Scope is what a token exchange reports; "devices:core" by default.
	Scope string
	// Suffix is the tailnet's MagicDNS suffix, as device names carry it.
	Suffix string
	// RewriteRename, when set, turns a requested name into the one stored:
	// a rename the control plane accepts but does not apply as asked.
	RewriteRename func(string) string
	// EchoCredentials makes every error answer quote the request's
	// credentials, to show that tailcontrol never repeats them.
	EchoCredentials bool
	// Unavailable makes every request fail with 503, as a control server
	// restarting or out of reach answers.
	Unavailable bool
	// EchoScope makes a token exchange answer a scope that quotes the
	// client secret and the token issued.
	EchoScope bool
	// LagRenames makes a rename show only from the second listing after
	// it: a control plane that lists the old name for a moment.
	LagRenames bool
	// AfterRename, when set, runs after each rename the fake applied, with
	// the fake's lock held: set changes another device's name (a third
	// device taking a name the rename freed, say).
	AfterRename func(id, name string, set func(id, name string))
	pending     map[string]string // device id -> name a lagged rename sets

	mu        sync.Mutex
	nodes     []*Node
	tokens    map[string]bool // live tokens
	Exchanges int             // token exchanges made
	Used      map[string]int  // requests made with each token
}

// NewTailscale serves a fake with these nodes; Close stops it.
func NewTailscale(nodes ...Node) *Tailscale {
	f := &Tailscale{ClientID: "k" + random(8), ClientSecret: "tskey-client-" + random(16), Scope: "devices:core", Suffix: "tail" + random(3) + ".ts.net", tokens: map[string]bool{}, Used: map[string]int{}}
	for _, n := range nodes {
		n := n
		f.nodes = append(f.nodes, &n)
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	return f
}

// SetName renames a device directly, as another actor on the tailnet
// would.
func (f *Tailscale) SetName(id, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.ID == id {
			n.Name = name
		}
	}
}

// Delete removes a device from the tailnet, as its admin console would.
func (f *Tailscale) Delete(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes = slices.DeleteFunc(f.nodes, func(n *Node) bool { return n.ID == id })
}

// Nodes is a copy of the tailnet's devices.
func (f *Tailscale) Nodes() []Node {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Node, len(f.nodes))
	for i, n := range f.nodes {
		out[i] = *n
	}
	return out
}

// canonicalTailscale is how Tailscale stores a machine name it is given.
func canonicalTailscale(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func (f *Tailscale) fail(w http.ResponseWriter, r *http.Request, status int, message string) {
	if f.EchoCredentials {
		message += fmt.Sprintf(" (you sent %q, %q, %q)", r.Header.Get("Authorization"), r.PostFormValue("client_secret"), r.PostFormValue("client_id"))
	}
	writeJSON(w, status, map[string]string{"message": message})
}

// SetUnavailable switches the fake down or back up.
func (f *Tailscale) SetUnavailable(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Unavailable = down
}

func (f *Tailscale) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Unavailable {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "service unavailable"})
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v2/oauth/token" {
		if r.PostFormValue("grant_type") != "client_credentials" || r.PostFormValue("client_id") != f.ClientID || r.PostFormValue("client_secret") != f.ClientSecret {
			f.fail(w, r, http.StatusUnauthorized, "invalid client credentials")
			return
		}
		tok := "tskey-api-" + random(16)
		f.tokens[tok] = true
		f.Exchanges++
		scope := f.Scope
		if f.EchoScope {
			// A misbehaving control plane quoting the request in a field
			// tailcontrol reports.
			scope += " " + r.PostFormValue("client_secret") + " " + tok
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "scope": scope})
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !f.tokens[tok] {
		f.fail(w, r, http.StatusUnauthorized, "API token invalid")
		return
	}
	f.Used[tok]++
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/tailnet/") && strings.HasSuffix(r.URL.Path, "/devices"):
		// A lagged rename shows from the second listing: this one shows the
		// old name and arms the next.
		for id, name := range f.pending {
			if strings.HasPrefix(name, "\x00") {
				for _, n := range f.nodes {
					if n.ID == id {
						n.Name = strings.TrimPrefix(name, "\x00")
					}
				}
				delete(f.pending, id)
			} else {
				f.pending[id] = "\x00" + name
			}
		}
		devices := []map[string]any{}
		for _, n := range f.nodes {
			d := map[string]any{"id": n.ID, "nodeId": n.NodeID, "name": n.Name + "." + f.Suffix, "hostname": "host-of-" + n.ID,
				"connectedToControl": n.Online, "keyExpiryDisabled": n.Expires.IsZero(), "lastSeen": n.LastSeen.UTC().Format(time.RFC3339)}
			if !n.Expires.IsZero() {
				d["expires"] = n.Expires.UTC().Format(time.RFC3339)
			}
			devices = append(devices, d)
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/device/") && strings.HasSuffix(r.URL.Path, "/name"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/device/"), "/name")
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			f.fail(w, r, http.StatusBadRequest, "name required")
			return
		}
		var target *Node
		for _, n := range f.nodes {
			if n.ID == id {
				target = n
			}
		}
		if target == nil {
			f.fail(w, r, http.StatusNotFound, "device not found")
			return
		}
		stored := canonicalTailscale(body.Name)
		if f.RewriteRename != nil {
			stored = f.RewriteRename(stored)
		}
		for _, n := range f.nodes {
			if n != target && strings.EqualFold(n.Name, stored) {
				f.fail(w, r, http.StatusConflict, "machine name already in use")
				return
			}
		}
		if f.LagRenames {
			if f.pending == nil {
				f.pending = map[string]string{}
			}
			f.pending[target.ID] = stored
		} else {
			target.Name = stored
		}
		if f.AfterRename != nil {
			f.AfterRename(target.ID, stored, func(id, name string) {
				for _, n := range f.nodes {
					if n.ID == id {
						n.Name = name
					}
				}
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	default:
		f.fail(w, r, http.StatusNotFound, "not found")
	}
}

// Headscale is a fake of Headscale for one tailnet: its API, and the CLI
// (Run) on the same state.
type Headscale struct {
	*httptest.Server
	// Key is an API key the fake knows, with Prefix as Headscale lists it:
	// hskey-api-<prefix>-<secret>, listed hskey-api-<prefix>-*** (0.28 and
	// later, as the pinned 0.29.7), or <prefix>.<secret> (Legacy).
	Key, Prefix string
	// KeyExpires is when Key expires.
	KeyExpires time.Time
	// RewriteRename, when set, turns a requested name into the one stored.
	RewriteRename func(string) string
	// DateSkew moves the listing's Date header off this host's clock; NoDate
	// omits the Date header.
	DateSkew time.Duration
	NoDate   bool

	mu          sync.Mutex
	nodes       []*Node
	expired     bool
	unavailable bool
	Renames     int
}

// SetUnavailable switches the fake down (every request and CLI call fails)
// or back up.
func (f *Headscale) SetUnavailable(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unavailable = down
}

// NewHeadscale serves a fake whose key expires after keyLife, in the key
// format of Headscale 0.28 and later.
func NewHeadscale(keyLife time.Duration, nodes ...Node) *Headscale {
	prefix := strings.ToLower(random(9))[:12]
	f := newHeadscale(keyLife, nodes...)
	f.Prefix, f.Key = "hskey-api-"+prefix+"-***", "hskey-api-"+prefix+"-"+random(24)
	return f
}

// NewHeadscaleLegacy is NewHeadscale with an earlier Headscale's keys.
func NewHeadscaleLegacy(keyLife time.Duration, nodes ...Node) *Headscale {
	prefix := random(5)
	f := newHeadscale(keyLife, nodes...)
	f.Prefix, f.Key = prefix, prefix+"."+random(16)
	return f
}

func newHeadscale(keyLife time.Duration, nodes ...Node) *Headscale {
	f := &Headscale{KeyExpires: time.Now().Add(keyLife)}
	for _, n := range nodes {
		n := n
		f.nodes = append(f.nodes, &n)
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	return f
}

// Nodes is a copy of the tailnet's nodes.
func (f *Headscale) Nodes() []Node {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Node, len(f.nodes))
	for i, n := range f.nodes {
		out[i] = *n
	}
	return out
}

// KeyExpired reports whether the key was expired through the API.
func (f *Headscale) KeyExpired() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.expired
}

// SetPresence updates a node's online flag and last-seen time.
func (f *Headscale) SetPresence(id string, online bool, lastSeen time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.ID == id {
			n.Online, n.LastSeen = online, lastSeen
		}
	}
}

func (f *Headscale) node(n *Node, camel bool) map[string]any {
	idKey, given, seen := "id", "givenName", "lastSeen"
	if !camel {
		given, seen = "given_name", "last_seen"
	}
	if !camel {
		// The CLI's JSON (0.29.7) writes timestamps as protobuf
		// Timestamps, an unset one as null.
		ts := func(t time.Time) any {
			if t.IsZero() {
				return nil
			}
			return map[string]any{"seconds": t.Unix(), "nanos": t.Nanosecond()}
		}
		return map[string]any{idKey: n.ID, "name": "host-" + n.ID, given: n.Name, "online": n.Online, "expiry": ts(n.Expires), seen: ts(n.LastSeen)}
	}
	expiry := "0001-01-01T00:00:00Z"
	if !n.Expires.IsZero() {
		expiry = n.Expires.UTC().Format(time.RFC3339)
	}
	return map[string]any{idKey: n.ID, "name": "host-" + n.ID, given: n.Name, "online": n.Online, "expiry": expiry, seen: n.LastSeen.UTC().Format(time.RFC3339)}
}

// rename applies Headscale's rule: the exact name of another node is
// refused, anything else is kept as given (a case variant included).
func (f *Headscale) rename(id, name string) (int, string) {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return http.StatusBadRequest, "invalid node id"
	}
	var target *Node
	for _, n := range f.nodes {
		if n.ID == id {
			target = n
		}
	}
	if target == nil {
		return http.StatusNotFound, "node not found"
	}
	stored := name
	if f.RewriteRename != nil {
		stored = f.RewriteRename(stored)
	}
	for _, n := range f.nodes {
		if n != target && n.Name == stored {
			return http.StatusConflict, "a node with this name already exists"
		}
	}
	target.Name = stored
	f.Renames++
	return http.StatusOK, ""
}

func (f *Headscale) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unavailable {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "unavailable"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.Key || f.expired || time.Now().After(f.KeyExpires) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/apikey":
		writeJSON(w, http.StatusOK, map[string]any{"apiKeys": []map[string]any{
			{"id": "1", "prefix": "other" + random(2), "expiration": time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)},
			{"id": "2", "prefix": f.Prefix, "expiration": f.KeyExpires.UTC().Format(time.RFC3339Nano)},
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apikey/expire":
		// By the key's prefix as listed, or by its id (0.28 and later).
		var body struct {
			Prefix string `json:"prefix"`
			ID     string `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !(body.Prefix == f.Prefix || body.ID == "2" && strings.HasSuffix(f.Prefix, "***")) {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "api key not found"})
			return
		}
		f.expired = true
		writeJSON(w, http.StatusOK, map[string]any{})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/node":
		if f.NoDate {
			w.Header()["Date"] = nil
		} else if f.DateSkew != 0 {
			w.Header().Set("Date", time.Now().Add(f.DateSkew).UTC().Format(http.TimeFormat))
		}
		nodes := []map[string]any{}
		for _, n := range f.nodes {
			nodes = append(nodes, f.node(n, true))
		}
		writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/node/") && strings.Contains(r.URL.Path, "/rename/"):
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/node/")
		id, name, _ := strings.Cut(rest, "/rename/")
		if status, msg := f.rename(id, name); status != http.StatusOK {
			writeJSON(w, status, map[string]string{"message": msg})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node": map[string]any{}})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
	}
}

// Run is the headscale CLI on the fake's state: `nodes list --output json`
// and `nodes rename --identifier <id> -- <name>`, as tailcontrol.HeadscaleCLI
// runs them.
func (f *Headscale) Run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unavailable {
		return nil, fmt.Errorf("headscale: cannot reach the server: connection refused")
	}
	switch {
	case len(args) == 4 && args[0] == "nodes" && args[1] == "list" && args[2] == "--output" && args[3] == "json":
		nodes := []map[string]any{}
		for _, n := range f.nodes {
			nodes = append(nodes, f.node(n, false))
		}
		return json.Marshal(nodes)
	case len(args) == 6 && args[0] == "nodes" && args[1] == "rename" && args[2] == "--identifier" && args[4] == "--":
		if status, msg := f.rename(args[3], args[5]); status != http.StatusOK {
			return nil, fmt.Errorf("headscale nodes rename: exit status 1: %s", msg)
		}
		return []byte("Node renamed\n"), nil
	}
	return nil, fmt.Errorf("headscale: unknown command %q", strings.Join(args, " "))
}
