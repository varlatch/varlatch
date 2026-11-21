// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
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
}

// TSNode is varlatchd's node, in process: tsnet.
type TSNode struct {
	srv *tsnet.Server
	lc  *local.Client
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
	advertise := slices.Clone(cfg.Tags)
	if cfg.KeyTags {
		advertise = nil
	}
	return &tsnet.Server{
		Dir: cfg.Dir, Hostname: cfg.Hostname, ControlURL: controlURL, AuthKey: cfg.AuthKey,
		Ephemeral: false, AdvertiseTags: advertise, Logf: logf, UserLogf: logf,
	}, nil
}

// StartNode starts the node: tagged, never ephemeral, its control server
// explicit, network-namespace binding off (userspace tsnet has no TUN
// device, and the binding makes every control connection hang on a host
// without a default route), and tsnet's log uploads off. It returns at
// once; Up waits for the tailnet.
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
	netns.SetEnabled(false)
	// Nothing about this node goes to Tailscale's log service.
	envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	logtail.Disable()
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("tailnet: starting the node: %w", err)
	}
	lc, err := srv.LocalClient()
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	return &TSNode{srv: srv, lc: lc}, nil
}

// Up waits until the node is on the tailnet.
func (n *TSNode) Up(ctx context.Context) error {
	_, err := n.srv.Up(ctx)
	return err
}

// Listen accepts tailnet connections on port, on the node's own
// addresses only: the tailnet listener and the public one stay separate.
func (n *TSNode) Listen(port int) (net.Listener, error) {
	return n.srv.Listen("tcp", fmt.Sprintf(":%d", port))
}

// Close leaves the tailnet; the node is never logged out, so it keeps its
// identity across restarts.
func (n *TSNode) Close() error { return n.srv.Close() }

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

// Status is the node's status, without its peers.
func (n *TSNode) Status(ctx context.Context) (Status, error) {
	st, err := n.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{BackendState: st.BackendState}
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

// family is 4 or 6, for ordering IPv4 first.
func family(addr string) int {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is4() {
		return 4
	}
	return 6
}
