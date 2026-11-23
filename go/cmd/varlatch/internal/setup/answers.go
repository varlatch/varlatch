// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
)

// Answers are setup's answers: one per question, each with its flag (the
// JSON name is the answers file's, the flag the same words with dashes).
// Nothing in them is secret: a key is never an answer, and the tailnet's
// auth key is a file's path.
type Answers struct {
	// Ingress is how people reach Varlatch: public (varlatchd serves HTTPS
	// with ACME), proxy (your own reverse proxy in front of the plain
	// listener), localhost (this machine only) or tailnet.
	Ingress   string `json:"ingress,omitempty"`
	PublicURL string `json:"publicUrl,omitempty"`
	// Listen is the plain listener (127.0.0.1:8686 by default).
	Listen         string `json:"listen,omitempty"`
	TrustedProxies string `json:"trustedProxies,omitempty"`
	// Public HTTPS (ingress public).
	ListenHTTPS        string `json:"listenHttps,omitempty"`
	ListenHTTPRedirect string `json:"listenHttpRedirect,omitempty"`
	ACMEEmail          string `json:"acmeEmail,omitempty"`
	ACMECA             string `json:"acmeCa,omitempty"`
	ACMECARoot         string `json:"acmeCaRoot,omitempty"`
	// The tailnet (ingress tailnet).
	TailnetHostname    string `json:"tailnetHostname,omitempty"`
	TailnetTags        string `json:"tailnetTags,omitempty"`
	TailnetPort        string `json:"tailnetPort,omitempty"`
	TailnetAuthKeyFile string `json:"tailnetAuthKeyFile,omitempty"`
	// TailscaleOAuthClientFile is a restore's authority over the tailnet
	// (an OAuth client with the devices:core scope only, go-step7 O4): the
	// restored node takes the dead one's name over, by rename, rather than
	// waiting for it to be deleted. A path; varlatchd reads it.
	TailscaleOAuthClientFile string `json:"tailscaleOAuthClientFile,omitempty"`
	// TailnetControlURL is a self-hosted control server's URL (Headscale:
	// https://<its IP>[:port], tailnet_control_url), canonical; "" for
	// Tailscale's. A restore's only, for now.
	TailnetControlURL string `json:"tailnetControlUrl,omitempty"`
	// HeadscaleAPIKeyFile is a restore's authority over a self-hosted
	// control server: a Headscale API key expiring within the hour, in a
	// file (0600); varlatchd reads it, takes the dead node's name over and
	// expires the key.
	HeadscaleAPIKeyFile string `json:"headscaleApiKeyFile,omitempty"`
	// Backups: where archives go (Decision 7). Backups is "host" (this
	// host only) or "bucket" (a destinations file the operator wrote);
	// Varlatch's hosted backups are not available yet (O5).
	Backups                string `json:"backups,omitempty"`
	BackupDestinationsFile string `json:"backupDestinationsFile,omitempty"`
	BackupDestination      string `json:"backupDestination,omitempty"`
}

// Flag is one answer's flag.
type Flag struct {
	Name string // as on the command line, without the dashes
	Set  func(a *Answers, v string)
	Get  func(a *Answers) string
}

// Flags are the answers' flags, in the order the questions come.
var Flags = []Flag{
	{"ingress", func(a *Answers, v string) { a.Ingress = v }, func(a *Answers) string { return a.Ingress }},
	{"public-url", func(a *Answers, v string) { a.PublicURL = v }, func(a *Answers) string { return a.PublicURL }},
	{"listen", func(a *Answers, v string) { a.Listen = v }, func(a *Answers) string { return a.Listen }},
	{"trusted-proxies", func(a *Answers, v string) { a.TrustedProxies = v }, func(a *Answers) string { return a.TrustedProxies }},
	{"listen-https", func(a *Answers, v string) { a.ListenHTTPS = v }, func(a *Answers) string { return a.ListenHTTPS }},
	{"listen-http-redirect", func(a *Answers, v string) { a.ListenHTTPRedirect = v }, func(a *Answers) string { return a.ListenHTTPRedirect }},
	{"acme-email", func(a *Answers, v string) { a.ACMEEmail = v }, func(a *Answers) string { return a.ACMEEmail }},
	{"acme-ca", func(a *Answers, v string) { a.ACMECA = v }, func(a *Answers) string { return a.ACMECA }},
	{"acme-ca-root", func(a *Answers, v string) { a.ACMECARoot = v }, func(a *Answers) string { return a.ACMECARoot }},
	{"tailnet-hostname", func(a *Answers, v string) { a.TailnetHostname = v }, func(a *Answers) string { return a.TailnetHostname }},
	{"tailnet-tags", func(a *Answers, v string) { a.TailnetTags = v }, func(a *Answers) string { return a.TailnetTags }},
	{"tailnet-port", func(a *Answers, v string) { a.TailnetPort = v }, func(a *Answers) string { return a.TailnetPort }},
	{"tailnet-auth-key-file", func(a *Answers, v string) { a.TailnetAuthKeyFile = v }, func(a *Answers) string { return a.TailnetAuthKeyFile }},
	{"tailscale-oauth-client-file", func(a *Answers, v string) { a.TailscaleOAuthClientFile = v }, func(a *Answers) string { return a.TailscaleOAuthClientFile }},
	{"tailnet-control-url", func(a *Answers, v string) { a.TailnetControlURL = v }, func(a *Answers) string { return a.TailnetControlURL }},
	{"headscale-api-key-file", func(a *Answers, v string) { a.HeadscaleAPIKeyFile = v }, func(a *Answers) string { return a.HeadscaleAPIKeyFile }},
	{"backups", func(a *Answers, v string) { a.Backups = v }, func(a *Answers) string { return a.Backups }},
	{"backup-destinations-file", func(a *Answers, v string) { a.BackupDestinationsFile = v }, func(a *Answers) string { return a.BackupDestinationsFile }},
	{"backup-destination", func(a *Answers, v string) { a.BackupDestination = v }, func(a *Answers) string { return a.BackupDestination }},
}

// FlagNamed is the flag of that name.
func FlagNamed(name string) (Flag, bool) {
	for _, f := range Flags {
		if f.Name == name {
			return f, true
		}
	}
	return Flag{}, false
}

// Ingress modes.
const (
	Public    = "public"
	Proxy     = "proxy"
	Localhost = "localhost"
	Tailnet   = "tailnet"
)

// Defaults.
const (
	DefaultListen          = "127.0.0.1:8686"
	DefaultLocalhostURL    = "http://localhost:8686"
	DefaultTrustedProxies  = "127.0.0.1,::1"
	DefaultListenHTTPS     = ":443"
	DefaultTailnetHostname = "varlatch"
	DefaultTailnetTags     = "tag:varlatch"
	DefaultTailnetPort     = "8687"
	DefaultDestination     = "offsite"
)

// Merge fills what a is missing from b, and says which answers of b differ
// from a's (a set answer is kept: the journal's answers are final).
func (a *Answers) Merge(b Answers) (differ []string) {
	for _, f := range Flags {
		got, given := f.Get(a), f.Get(&b)
		switch {
		case given == "":
		case got == "":
			f.Set(a, given)
		case got != given:
			differ = append(differ, f.Name)
		}
	}
	return differ
}

// Missing is the first question without an answer that the answers so far
// call for, "" when every one is answered.
func (a *Answers) Missing() string {
	if a.Ingress == "" {
		return "ingress"
	}
	switch a.Ingress {
	case Public, Proxy:
		if a.PublicURL == "" {
			return "public-url"
		}
	case Tailnet:
		if a.TailnetAuthKeyFile == "" {
			return "tailnet-auth-key-file"
		}
	}
	if a.Backups == "" {
		return "backups"
	}
	if a.Backups == "bucket" && a.BackupDestinationsFile == "" {
		return "backup-destinations-file"
	}
	return ""
}

// Defaults fills the answers that have a default.
func (a *Answers) Defaults() {
	if a.Listen == "" {
		a.Listen = DefaultListen
	}
	switch a.Ingress {
	case Localhost:
		if a.PublicURL == "" {
			a.PublicURL = "http://localhost:" + portOf(a.Listen)
		}
	case Proxy:
		if a.TrustedProxies == "" {
			a.TrustedProxies = DefaultTrustedProxies
		}
	case Public:
		if a.ListenHTTPS == "" {
			a.ListenHTTPS = DefaultListenHTTPS
		}
	case Tailnet:
		if a.TailnetHostname == "" {
			a.TailnetHostname = DefaultTailnetHostname
		}
		if a.TailnetTags == "" {
			a.TailnetTags = DefaultTailnetTags
		}
		if a.TailnetPort == "" {
			a.TailnetPort = DefaultTailnetPort
		}
	}
	if a.Backups == "bucket" && a.BackupDestination == "" {
		a.BackupDestination = DefaultDestination
	}
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return "8686"
}

// isLoopback: localhost or a loopback address (an empty host is every
// address).
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var (
	dnsName  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Check is the answers' own checks (varlatchd checks the configuration they
// make, too): a usage error names the flag. Nothing in an error repeats a
// URL's user name or password.
func (a *Answers) Check() error {
	bad := func(flag, msg string) error { return fmt.Errorf("--%s: %s", flag, msg) }
	switch a.Ingress {
	case Public, Proxy, Localhost, Tailnet:
	default:
		return bad("ingress", "must be public, proxy, localhost or tailnet")
	}
	if a.PublicURL != "" {
		u, err := url.Parse(a.PublicURL)
		if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return bad("public-url", "must be an origin such as https://varlatch.example.com, without a user name, password, path or query")
		}
		host := strings.ToLower(u.Hostname())
		loopback := isLoopback(host)
		switch {
		case a.Ingress == Localhost && (u.Scheme != "http" || !loopback):
			return bad("public-url", "with ingress localhost, must be http://localhost:<port>")
		case a.Ingress != Localhost && u.Scheme != "https":
			return bad("public-url", "must be https")
		case a.Ingress == Public && (net.ParseIP(host) != nil || !dnsName.MatchString(host)):
			return bad("public-url", "with ingress public, must name a DNS name a certificate can hold")
		}
	}
	for _, l := range []struct{ flag, v string }{{"listen", a.Listen}, {"listen-https", a.ListenHTTPS}} {
		if l.v == "" {
			continue
		}
		if _, p, err := net.SplitHostPort(l.v); err != nil || p == "" {
			return bad(l.flag, "must be host:port, such as 127.0.0.1:8686")
		}
	}
	if r := a.ListenHTTPRedirect; r != "" && r != "off" {
		if _, _, err := net.SplitHostPort(r); err != nil {
			return bad("listen-http-redirect", "must be host:port or off")
		}
	}
	if a.Ingress == Tailnet {
		if !hostName.MatchString(a.TailnetHostname) {
			return bad("tailnet-hostname", "must be a host name (lower-case letters, digits and -)")
		}
		if n, err := strconv.Atoi(a.TailnetPort); err != nil || n < 1 || n > 65535 {
			return bad("tailnet-port", "must be a port from 1 to 65535")
		}
		if !strings.HasPrefix(a.TailnetAuthKeyFile, "/") {
			return bad("tailnet-auth-key-file", "must be an absolute path (the key is read by varlatchd, never by setup)")
		}
	}
	if a.TailscaleOAuthClientFile != "" {
		if a.Ingress != Tailnet {
			return bad("tailscale-oauth-client-file", "goes with ingress tailnet only: it takes the old node's tailnet name over")
		}
		if !strings.HasPrefix(a.TailscaleOAuthClientFile, "/") {
			return bad("tailscale-oauth-client-file", "must be an absolute path (the client is read by varlatchd, never by setup)")
		}
		if a.TailnetControlURL != "" {
			return bad("tailscale-oauth-client-file", "is Tailscale's authority, and --tailnet-control-url names a self-hosted control server: give --headscale-api-key-file instead")
		}
	}
	if a.TailnetControlURL != "" {
		if a.Ingress != Tailnet {
			return bad("tailnet-control-url", "goes with ingress tailnet only")
		}
		canonical, why := tailcontrol.CanonicalControlURL(a.TailnetControlURL)
		if why != "" {
			return bad("tailnet-control-url", why)
		}
		if canonical != a.TailnetControlURL {
			return bad("tailnet-control-url", "is written "+canonical+" (as varlatchd and varlatch migrate spell it)")
		}
	}
	if a.HeadscaleAPIKeyFile != "" {
		if a.TailnetControlURL == "" {
			return bad("headscale-api-key-file", "goes with --tailnet-control-url: it is a self-hosted control server's authority (Tailscale's is --tailscale-oauth-client-file)")
		}
		if !strings.HasPrefix(a.HeadscaleAPIKeyFile, "/") {
			return bad("headscale-api-key-file", "must be an absolute path (the key is read by varlatchd, never by setup)")
		}
	}
	for _, p := range []struct{ flag, v string }{{"acme-ca-root", a.ACMECARoot}, {"backup-destinations-file", a.BackupDestinationsFile}} {
		if p.v != "" && !strings.HasPrefix(p.v, "/") {
			return bad(p.flag, "must be an absolute path")
		}
	}
	switch a.Backups {
	case "host", "bucket":
	case "hosted":
		return bad("backups", "Varlatch's hosted backups are not available yet; choose host or bucket")
	default:
		return bad("backups", "must be host or bucket")
	}
	if a.Ingress == Localhost {
		// This machine only: the listener on a loopback address, and no
		// proxy in front of it to trust.
		if host, _, err := net.SplitHostPort(a.Listen); a.Listen != "" && err == nil && !isLoopback(host) {
			return bad("listen", "with ingress localhost, must be on a loopback address, such as 127.0.0.1:8686")
		}
		if a.TrustedProxies != "" {
			return bad("trusted-proxies", "is for --ingress proxy, not localhost")
		}
	}
	if a.Ingress != Public && (a.ListenHTTPS != "" || a.ACMEEmail != "" || a.ACMECA != "" || a.ACMECARoot != "" || a.ListenHTTPRedirect != "") {
		return errors.New("--listen-https, --listen-http-redirect and --acme-* are for --ingress public")
	}
	return nil
}
