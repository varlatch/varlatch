// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/logtail"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
)

// NodeConfig is how varlatchd's tsnet node joins its tailnet (ADR-0059
// Decision 5).
type NodeConfig struct {
	// Dir is the node's state directory: its keys, so secret, never in a
	// backup.
	Dir string
	// Hostname is fixed at enrolment: on Tailscale the node's name follows
	// it until an admin sets one.
	Hostname string
	// ControlURL is the coordination server; "" is Tailscale's.
	ControlURL string
	// AuthKey enrols the node the first time; once its state exists it is
	// not needed.
	AuthKey string
	// Tags the node advertises (it is always tagged).
	Tags []string
	// KeyTags: the node's tags come from its auth key, and it advertises
	// none. A self-hosted control server (Headscale) refuses a node that
	// registers with a pre-auth key and advertises tags: its tags are the
	// tagged key's, which must be Tags.
	KeyTags bool
	// Logf receives tsnet's logs; nil discards them.
	Logf func(format string, args ...any)
}

// Status is what the node says about itself.
type Status struct {
	// BackendState is "Running" once it is on the tailnet.
	BackendState string
	// SelfID is its StableID.
	SelfID string
	// DNSName is its MagicDNS name, lower case, without the trailing dot.
	DNSName string
	// Suffix is its tailnet's MagicDNS suffix, lower case.
	Suffix string
	// TailnetID is the tailnet's StableID; "" where the control server has
	// none (Headscale).
	TailnetID string
	Tags      []string
	// Addresses are its tailnet addresses.
	Addresses []string
	// CertDomains are the names its control plane's map lets it obtain
	// certificates for, as the map writes them: tsnet refuses every other.
	CertDomains []string
	// AuthNeeded: somebody must log it in or approve it at its control
	// server before it can join.
	AuthNeeded bool
	// HaveNodeKey: a control server has registered it, now or ever: it has
	// an identity, which its state directory holds.
	HaveNodeKey bool
}

// TSNode is varlatchd's node, in process: tsnet.
type TSNode struct {
	srv *tsnet.Server
	lc  *local.Client
	dir string
	// closed is closed by Close.
	closed    chan struct{}
	closeOnce sync.Once
}

// TailscaleControlURL is Tailscale's coordination server: the node's,
// given explicitly, when the configuration names none.
const TailscaleControlURL = ipn.DefaultControlURL

// tsnetEnv are the environment variables tsnet reads in place of a field
// left empty: a control server, an auth key, OAuth or workload identity
// credentials, a forced login. varlatchd's node takes all of that from
// varlatchd.conf alone, so it refuses to start while one is set.
var tsnetEnv = []string{"TS_CONTROL_URL", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_CLIENT_ID", "TS_ID_TOKEN", "TS_AUDIENCE", "TSNET_FORCE_LOGIN"}

// newServer is the node's tsnet server for cfg, not started.
func newServer(cfg NodeConfig) (*tsnet.Server, error) {
	if len(cfg.Tags) == 0 {
		return nil, errors.New("tailnet: the node must be tagged")
	}
	for _, name := range tsnetEnv {
		if _, set := os.LookupEnv(name); set {
			return nil, fmt.Errorf("tailnet: %s is set in varlatchd's environment; the node takes its control server and enrolment from varlatchd.conf only. Unset it", name)
		}
	}
	controlURL := cfg.ControlURL
	if controlURL == "" {
		// Never left empty: tsnet would read TS_CONTROL_URL.
		controlURL = TailscaleControlURL
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	// tsnet logs the control server's answers. It calls a Logf once for a
	// whole message (nothing here is an io.Writer that could be handed a key
	// in two pieces; its own log buffer takes nothing, logtail being
	// disabled), so each message is looked at whole.
	say := logf
	logf = func(format string, args ...any) { say("%s", withoutKey(fmt.Sprintf(format, args...), cfg.AuthKey)) }
	advertise := slices.Clone(cfg.Tags)
	if cfg.KeyTags {
		advertise = nil
	}
	return &tsnet.Server{
		Dir: cfg.Dir, Hostname: cfg.Hostname, ControlURL: controlURL, AuthKey: cfg.AuthKey,
		Ephemeral: false, AdvertiseTags: advertise, Logf: logf, UserLogf: logf,
	}, nil
}

// netmapCacheEnv is tsnet's switch for its network map cache. With it on
// (its default), tsnet is, at its next start, Running on the map it last
// wrote to its state directory, before it has spoken to the control plane:
// a node renamed, retagged or moved since reads back as it was, and trust
// would rest on it. Off, no map is read from there at a start, and none
// with the node's peers is written. The node's own (its name, tags and
// addresses, no peer) may still be, whatever the switch: tsnet writes it at
// each change of the node's home DERP region and drops it at the next whole
// map, and has no hook to prevent that. So what is there is never read, and
// is removed when the node starts and when it closes (dropNetmapCache).
const netmapCacheEnv = "TS_USE_CACHED_NETMAP"

// prepareTsnet sets what every tsnet node in this process starts with:
// network-namespace binding off (userspace tsnet has no TUN device, and the
// binding makes every control connection hang on a host without a default
// route), nothing to Tailscale's log service, and no cached network map:
// what a node says of itself is the control plane's answer to this start.
func prepareTsnet() {
	netns.SetEnabled(false)
	envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	envknob.Setenv(netmapCacheEnv, "false")
	logtail.Disable()
}

// dropNetmapCache removes a network map tsnet wrote to the node's state
// directory (this start's, one that was killed, or a varlatchd's before the
// cache was off). Only below dir, never through a link out of it; what
// cannot be removed is not read either.
func dropNetmapCache(dir string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer root.Close()
	profiles, err := fs.ReadDir(root.FS(), ipnlocal.ProfileDataDir)
	if err != nil {
		return
	}
	for _, p := range profiles {
		if p.IsDir() {
			_ = root.RemoveAll(filepath.Join(ipnlocal.ProfileDataDir, p.Name(), netmapCacheDir))
		}
	}
}

// netmapCacheDir is the cache's directory in a tsnet profile's data.
const netmapCacheDir = "netmap-cache"

// StartNode starts the node: tagged, never ephemeral, its control server
// explicit, and tsnet as prepareTsnet sets it. It returns at once; Up waits
// for the tailnet.
func StartNode(cfg NodeConfig) (*TSNode, error) {
	srv, err := newServer(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	prepareTsnet()
	dropNetmapCache(cfg.Dir)
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("tailnet: starting the node: %w", keyless(err, cfg.AuthKey))
	}
	lc, err := srv.LocalClient()
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	return &TSNode{srv: srv, lc: lc, dir: cfg.Dir, closed: make(chan struct{})}, nil
}

// Listen accepts tailnet connections on port, on the node's own
// addresses only: the tailnet listener and the public one stay separate.
func (n *TSNode) Listen(port int) (net.Listener, error) {
	return n.srv.Listen("tcp", fmt.Sprintf(":%d", port))
}

// Close leaves the tailnet; the node is never logged out, so it keeps its
// identity across restarts. No network map of it stays on disk.
func (n *TSNode) Close() error {
	n.closeOnce.Do(func() { close(n.closed) })
	err := n.srv.Close()
	dropNetmapCache(n.dir)
	return err
}

// WhoIs is the local API's WhoIs, in process.
func (n *TSNode) WhoIs(ctx context.Context, remote string) (Peer, error) {
	who, err := n.lc.WhoIs(ctx, remote)
	if errors.Is(err, local.ErrPeerNotFound) {
		return Peer{}, ErrUnknownPeer
	}
	if err != nil {
		return Peer{}, err
	}
	if who == nil || who.Node == nil {
		return Peer{}, errors.New("tailnet: WhoIs answered without a node")
	}
	p := Peer{StableID: string(who.Node.StableID), Name: who.Node.Name, Tags: slices.Clone(who.Node.Tags), Sharer: int64(who.Node.Sharer)}
	if who.UserProfile != nil {
		p.LoginName = who.UserProfile.LoginName
	}
	return p, nil
}

// SelfID is the node's own StableID.
func (n *TSNode) SelfID(ctx context.Context) (string, error) {
	st, err := n.Status(ctx)
	if err != nil {
		return "", err
	}
	if st.SelfID == "" {
		return "", errors.New("tailnet: the node does not know its own identity yet")
	}
	return st.SelfID, nil
}

// DERPHosts are the host names of the DERP servers the node's current
// DERP map (its control server's) lists.
func (n *TSNode) DERPHosts(ctx context.Context) ([]string, error) {
	m, err := n.lc.CurrentDERPMap(ctx)
	if err != nil || m == nil {
		return nil, err
	}
	var hosts []string
	for _, r := range m.Regions {
		if r == nil {
			continue
		}
		for _, nd := range r.Nodes {
			if nd != nil && nd.HostName != "" {
				hosts = append(hosts, nd.HostName)
			}
		}
	}
	return hosts, nil
}

// Status is the node's status, without its peers.
func (n *TSNode) Status(ctx context.Context) (Status, error) {
	st, err := n.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{BackendState: st.BackendState, CertDomains: slices.Clone(st.CertDomains), HaveNodeKey: st.HaveNodeKey}
	// Without a network map, NeedsLogin is also a first registration still
	// under way (or a control server that does not answer it).
	out.AuthNeeded = st.AuthURL != "" || st.BackendState == ipn.NeedsMachineAuth.String() ||
		st.BackendState == ipn.NeedsLogin.String() && st.CurrentTailnet != nil
	if st.Self != nil {
		out.SelfID = string(st.Self.ID)
		out.DNSName = strings.ToLower(strings.TrimSuffix(st.Self.DNSName, "."))
		if st.Self.Tags != nil {
			out.Tags = st.Self.Tags.AsSlice()
		}
		for _, a := range st.Self.TailscaleIPs {
			out.Addresses = append(out.Addresses, a.String())
		}
		slices.SortStableFunc(out.Addresses, func(a, b string) int { return family(a) - family(b) })
	}
	if st.CurrentTailnet != nil {
		out.Suffix = strings.ToLower(strings.TrimSuffix(st.CurrentTailnet.MagicDNSSuffix, "."))
		out.TailnetID = string(st.CurrentTailnet.StableID)
	}
	if out.Suffix == "" {
		out.Suffix = strings.ToLower(strings.TrimSuffix(st.MagicDNSSuffix, "."))
	}
	return out, nil
}

// Label is the first label of the node's MagicDNS name.
func (s Status) Label() string {
	label, _, _ := strings.Cut(s.DNSName, ".")
	return label
}

// awaitEvery is how often AwaitStatus reads the node.
const awaitEvery = 200 * time.Millisecond

// AwaitStatus reads the node's status until it is as expected, for wait at
// most, or until ctx ends; each read has lookupTimeout, and none that ends
// after the wait counts. It answers the last status read, and whether it
// was as expected: what is expected is never relaxed, only waited for, so a
// caller refuses when it was not. Everything expected is found in that one
// status, never pieced together from several. An error is a node whose
// status could not be read at all.
func (n *TSNode) AwaitStatus(ctx context.Context, wait time.Duration, expected func(Status) bool) (Status, bool, error) {
	return awaitStatus(ctx, wait, n.Status, expected)
}

func awaitStatus(ctx context.Context, wait time.Duration, read func(context.Context) (Status, error), expected func(Status) bool) (Status, bool, error) {
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	tick := time.NewTicker(awaitEvery)
	defer tick.Stop()
	var last Status
	var known bool
	for {
		rctx, rcancel := context.WithTimeout(wctx, lookupTimeout)
		st, err := read(rctx)
		rcancel()
		if err == nil {
			last, known = st, true
			if wctx.Err() == nil && expected(st) {
				return st, true, nil
			}
		}
		select {
		case <-wctx.Done():
			if !known {
				return Status{}, false, fmt.Errorf("the node answered no status in %s: %w", wait, cmp.Or(err, wctx.Err()))
			}
			return last, false, nil
		case <-tick.C:
		}
	}
}

// family is 4 or 6, for ordering IPv4 first.
func family(addr string) int {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is4() {
		return 4
	}
	return 6
}
