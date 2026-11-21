// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config reads varlatchd's configuration file,
// /etc/varlatch/varlatchd.conf (ADR-0059 Decision 8; the format is
// described in go/install/varlatchd.conf.example).
//
// The file holds no secrets: the Root KEK comes from a file of its own
// (root_kek_file, by default the systemd credential root-kek).
//
// Every error Parse returns is a *Error, a configuration problem no retry
// can fix (exit 78; the unit's RestartPreventExitStatus=78). Reading the
// file is the caller's business: a file that cannot be read touches the
// disk, and may be fixed by the time the unit restarts.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/clientaddr"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// DefaultPath is where the unit and setup keep the file.
const DefaultPath = "/etc/varlatch/varlatchd.conf"

// Defaults for settings the file may leave out.
const (
	DefaultListen  = "127.0.0.1:8686"
	DefaultDataDir = "/var/lib/varlatch"
	// DatabaseFile is the database's name in the data directory.
	DatabaseFile = "varlatch.db"
)

// SyncPlatforms are the outbound sync adapters (ADR-0031), in the order
// /v1/meta lists them when sync_adapters is not set
// (packages/sync/src/types.ts PLATFORMS).
var SyncPlatforms = []string{"github-actions", "coolify", "convex"}

// Config is varlatchd's configuration.
type Config struct {
	// Listen is the HTTP listener's address, host:port.
	Listen string
	// PublicURL is the origin people reach Varlatch at (VARLATCH_PUBLIC_URL
	// today); nil when not set.
	PublicURL *url.URL
	// DataDir holds the database (DatabaseFile).
	DataDir string
	// RootKEKFile is the file the Root KEK is read from.
	RootKEKFile string
	// TrustedProxies is the trusted_proxies value, validated
	// (VARLATCH_TRUSTED_PROXIES today); empty when no proxy is trusted.
	TrustedProxies string
	// OutboundAllow is the outbound policy's allow list (ADR-0057;
	// VARLATCH_OUTBOUND_ALLOW today), validated; empty when nothing beyond
	// public https destinations is allowed.
	OutboundAllow string
	// AccessLog is where the access log goes: a file path, "stdout", or
	// "off".
	AccessLog string
	// Sync is false when the installation switch is off (VARLATCH_SYNC).
	Sync bool
	// AuditExport is false when the audit export is off on this
	// installation (audit_export, VARLATCH_AUDIT_EXPORT; ADR-0056
	// Decision 6): no export can be created or changed, only read and
	// removed.
	AuditExport bool
	// SyncAdapters narrows the adapters (VARLATCH_SYNC_ADAPTERS); nil means
	// all of SyncPlatforms.
	SyncAdapters []string

	// Backups (ADR-0059 Decision 7). BackupKeyFile is the Backup Encryption
	// Key's file (32 bytes, hex or base64): backup_key_file, else the
	// unit's backup-key credential when it exists; without one, varlatchd
	// makes no scheduled backup.
	BackupKeyFile string
	// BackupInterval is how often a scheduled backup runs; 0 is off.
	BackupInterval time.Duration
	// BackupKeep is how many archives stay in the data directory.
	BackupKeep int
	// BackupDestinationsFile is the destinations file (packages/backup's
	// format); empty keeps archives on this host only.
	BackupDestinationsFile string
	// BackupDestination names the destination archives are uploaded to.
	BackupDestination string
	// Tailnet is the tailnet listener (ADR-0059 Decision 5); nil when off.
	Tailnet *Tailnet
	// PublicHTTPS is the public HTTPS listener with its ACME certificate
	// (ADR-0059 Decision 5, step 6's decision 4); nil when off, which
	// leaves every other listener exactly as it is.
	PublicHTTPS *PublicHTTPS
}

// PublicHTTPS is varlatchd's own public HTTPS: a certificate for the
// public URL's host, obtained and renewed over ACME, served on Listen.
type PublicHTTPS struct {
	// Host is the certificate's name: public_url's host.
	Host string
	// Listen is the HTTPS listener's address (listen_https).
	Listen string
	// RedirectListen is the plain HTTP listener's (listen_http_redirect):
	// ACME HTTP-01 challenges and a redirect to HTTPS, nothing else; ""
	// when off (TLS-ALPN-01 only).
	RedirectListen string
	// Email is the ACME account's contact (acme_email); "" for none.
	Email string
	// CA is the ACME directory URL (acme_ca); Let's Encrypt by default.
	CA string
	// CARootFile is a PEM file of roots trusted for the CA's own API
	// (acme_ca_root): a private CA's; "" for the system's.
	CARootFile string
}

// LetsEncryptDirectory is acme_ca's default.
const LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// Tailnet is varlatchd's own tailnet node and its listener.
type Tailnet struct {
	// Hostname is the node's, fixed at enrolment.
	Hostname string
	// Tags the node advertises; it is always tagged.
	Tags []string
	// Port is the tailnet listener's, on the node's addresses only.
	Port int
	// ControlURL is the coordination server; "" is Tailscale's.
	ControlURL string
	// AuthKeyFile holds the auth key that enrols the node the first time
	// (tailnet_auth_key_file, or the unit's tailnet-auth-key credential);
	// "" when there is none.
	AuthKeyFile string
	// HTTPSPort is the browser endpoint's (ADR-0046), on the node's
	// addresses with its Tailscale certificate; 0 when it is off.
	HTTPSPort int
	// BrowserOrigins are the exact dashboard origins the browser endpoint
	// lets read cross-origin: an https (or loopback http) public_url's,
	// and tailnet_browser_origins.
	BrowserOrigins []string
}

// TailscaleControlURL is Tailscale's coordination server, the default.
const TailscaleControlURL = "https://controlplane.tailscale.com"

var (
	tailnetHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Tailscale's own rule for a tag (tailcfg.CheckTag).
	tailnetTag = regexp.MustCompile(`^tag:[A-Za-z][A-Za-z0-9-]*$`)
)

// LoopbackHost reports whether a URL's host name (URL.Hostname: an IPv6
// address without its brackets) is one a plain-http public URL may name:
// localhost, 127.0.0.1 or ::1.
func LoopbackHost(hostname string) bool {
	switch strings.ToLower(hostname) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// DatabasePath is the database file in the data directory.
func (c *Config) DatabasePath() string { return filepath.Join(c.DataDir, DatabaseFile) }

// Error is a configuration error no retry can fix.
type Error struct {
	Line    int // 0 when the error is about the file as a whole
	Message string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("configuration line %d: %s", e.Line, e.Message)
	}
	return "configuration: " + e.Message
}

// Env is how Parse reads the environment (os.Getenv in production).
type Env func(string) string

var keys = []string{"listen", "public_url", "data_dir", "root_kek_file", "trusted_proxies", "outbound_allow", "access_log", "sync", "sync_adapters", "audit_export",
	"backup_key_file", "backup_interval", "backup_keep", "backup_destinations_file", "backup_destination",
	"tailnet", "tailnet_hostname", "tailnet_tags", "tailnet_port", "tailnet_control_url", "tailnet_auth_key_file",
	"tailnet_https_port", "tailnet_browser_origins",
	"listen_https", "listen_http_redirect", "acme_email", "acme_ca", "acme_ca_root"}

// Backup defaults: a day between backups, seven archives kept (the
// TypeScript host backup's LOCAL_KEEP), the destination named offsite
// (its DESTINATION).
const (
	DefaultBackupInterval    = 24 * time.Hour
	DefaultBackupKeep        = 7
	DefaultBackupDestination = "offsite"
)

// Parse reads the configuration from r.
//
// The format: one setting per line, `name = value`. Blank lines and lines
// whose first non-blank character is # are ignored. Names are those in
// varlatchd.conf.example; an unknown name, a name given twice, or a line
// without = is an error. The value is the rest of the line with surrounding
// blanks removed, taken literally (no quotes, escapes or inline comments);
// an empty value means the default.
//
// env supplies CREDENTIALS_DIRECTORY (systemd's credentials, the default
// home of the Root KEK) and STATE_DIRECTORY (the unit's state directory,
// the default data directory when set).
func Parse(r io.Reader, env Env) (*Config, error) {
	values := map[string]string{}
	lines := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, &Error{n, fmt.Sprintf("expected name = value, got %q", line)}
		}
		name = strings.TrimSpace(name)
		if !slices.Contains(keys, name) {
			return nil, &Error{n, fmt.Sprintf("unknown setting %q (known: %s)", name, strings.Join(keys, ", "))}
		}
		if first, dup := lines[name]; dup {
			return nil, &Error{n, fmt.Sprintf("%s is already set on line %d", name, first)}
		}
		lines[name] = n
		values[name] = strings.TrimSpace(value)
	}
	if err := sc.Err(); err != nil {
		return nil, &Error{0, fmt.Sprintf("line %d: %v", n+1, err)}
	}
	at := func(name, msg string, args ...any) error {
		return &Error{lines[name], fmt.Sprintf(name+": "+msg, args...)}
	}

	c := &Config{Listen: DefaultListen, DataDir: DefaultDataDir, AccessLog: "stdout", Sync: true, AuditExport: true}
	if dir := env("STATE_DIRECTORY"); dir != "" {
		// The unit's StateDirectory; systemd may list several, separated by ':'.
		c.DataDir, _, _ = strings.Cut(dir, ":")
	}
	if v := values["listen"]; v != "" {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			return nil, at("listen", "%q is not host:port (%v)", v, err)
		}
		// Port 0 takes any free port, which varlatchd logs (tests).
		if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
			return nil, at("listen", "%q: the port must be 0 to 65535", v)
		}
		if host != "" && net.ParseIP(host) == nil {
			return nil, at("listen", "%q: the host must be an IP address (or empty for every address)", v)
		}
		c.Listen = v
	}
	if v := values["public_url"]; v != "" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, at("public_url", "%q is not an http or https URL such as https://varlatch.example.com", v)
		}
		// Plain http only on this machine (ADR-0059 Decision 6: the
		// browser session's cookies are Secure everywhere else).
		if u.Scheme == "http" && !LoopbackHost(u.Hostname()) {
			return nil, at("public_url", "%q uses plain http on a host other than this machine; use an https URL (plain http is allowed only for localhost, 127.0.0.1 and [::1])", v)
		}
		c.PublicURL = u
	}
	if v := values["data_dir"]; v != "" {
		if !filepath.IsAbs(v) {
			return nil, at("data_dir", "%q is not an absolute path", v)
		}
		c.DataDir = filepath.Clean(v)
	}
	switch v := values["root_kek_file"]; {
	case v != "":
		if !filepath.IsAbs(v) {
			return nil, at("root_kek_file", "%q is not an absolute path", v)
		}
		c.RootKEKFile = filepath.Clean(v)
	case env("CREDENTIALS_DIRECTORY") != "":
		c.RootKEKFile = filepath.Join(env("CREDENTIALS_DIRECTORY"), "root-kek")
	default:
		return nil, &Error{0, "no Root KEK: set root_kek_file, or run varlatchd under its unit, which hands it the root-kek credential"}
	}
	if v := values["trusted_proxies"]; v != "" {
		if _, err := clientaddr.ParseTrustedProxies(v); err != nil {
			return nil, at("trusted_proxies", "%v", err)
		}
		c.TrustedProxies = v
	}
	if v := values["outbound_allow"]; v != "" {
		if _, err := outbound.ParseAllow(v); err != nil {
			return nil, at("outbound_allow", "%v", err)
		}
		c.OutboundAllow = v
	}
	switch v := values["access_log"]; {
	case v == "" || v == "stdout":
	case v == "off":
		c.AccessLog = "off"
	case filepath.IsAbs(v):
		c.AccessLog = filepath.Clean(v)
	default:
		return nil, at("access_log", "%q must be an absolute path, stdout or off", v)
	}
	switch v := values["sync"]; v {
	case "", "on":
	case "off":
		c.Sync = false
	default:
		return nil, at("sync", "%q must be on or off", v)
	}
	switch v := values["audit_export"]; v {
	case "", "on":
	case "off":
		c.AuditExport = false
	default:
		return nil, at("audit_export", "%q must be on or off", v)
	}
	if v := values["sync_adapters"]; v != "" {
		var adapters []string
		for _, a := range strings.Split(v, ",") {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			if !slices.Contains(SyncPlatforms, a) {
				return nil, at("sync_adapters", "unknown adapter %q (known: %s)", a, strings.Join(SyncPlatforms, ", "))
			}
			adapters = append(adapters, a)
		}
		c.SyncAdapters = adapters
	}
	for _, name := range []string{"backup_key_file", "backup_destinations_file"} {
		if v := values[name]; v != "" && !filepath.IsAbs(v) {
			return nil, at(name, "%q is not an absolute path", v)
		}
	}
	switch v := values["backup_key_file"]; {
	case v != "":
		c.BackupKeyFile = filepath.Clean(v)
	case env("CREDENTIALS_DIRECTORY") != "":
		// The unit's backup-key credential, as root_kek_file's: setup
		// writes both keys beside the configuration, and the unit loads
		// them (varlatchd.service, LoadCredential). Only when it is there:
		// without one, no scheduled backup, as before.
		if p := filepath.Join(env("CREDENTIALS_DIRECTORY"), "backup-key"); fileExists(p) {
			c.BackupKeyFile = p
		}
	}
	c.BackupInterval = DefaultBackupInterval
	switch v := values["backup_interval"]; v {
	case "":
	case "off":
		c.BackupInterval = 0
	default:
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Hour || d > 31*24*time.Hour {
			return nil, at("backup_interval", "%q must be a duration from 1h to 744h (such as 24h or 12h), or off", v)
		}
		c.BackupInterval = d
	}
	c.BackupKeep = DefaultBackupKeep
	if v := values["backup_keep"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return nil, at("backup_keep", "%q must be a number of archives from 1 to 1000", v)
		}
		c.BackupKeep = n
	}
	if v := values["backup_destinations_file"]; v != "" {
		c.BackupDestinationsFile = filepath.Clean(v)
	}
	c.BackupDestination = DefaultBackupDestination
	if v := values["backup_destination"]; v != "" {
		if !backupDestinationName.MatchString(v) {
			return nil, at("backup_destination", "%q is not a destination name (letters, digits, - and _)", v)
		}
		c.BackupDestination = v
	}
	t, err := parseTailnet(values, at, c, env)
	if err != nil {
		return nil, err
	}
	c.Tailnet = t
	p, err := parsePublicHTTPS(values, at, c)
	if err != nil {
		return nil, err
	}
	c.PublicHTTPS = p
	return c, nil
}

// listenAddress checks a host:port listener setting: an IP address or
// nothing (every address), and a port from 1 (from 0 when zero is true:
// any free port). Public HTTPS's listeners need a real port: the ACME
// challenges are answered on the ports the CA connects to.
func listenAddress(name, v string, zero bool, at func(string, string, ...any) error) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return at(name, "%q is not host:port (%v)", v, err)
	}
	low := 1
	if zero {
		low = 0
	}
	if p, err := strconv.Atoi(port); err != nil || p < low || p > 65535 {
		return at(name, "%q: the port must be %d to 65535", v, low)
	}
	if host != "" && net.ParseIP(host) == nil {
		return at(name, "%q: the host must be an IP address (or empty for every address)", v)
	}
	return nil
}

// loopbackIP is whether host is a loopback IP address (127.0.0.0/8, ::1).
func loopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// publicDNSName is a host name a public certificate can name: two labels
// at least, letters, digits and hyphens.
var publicDNSName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// emailAddress is an ACME contact's address, loosely.
var emailAddress = regexp.MustCompile(`^[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+$`)

// parsePublicHTTPS reads listen_https and the settings that only apply
// with it. Without listen_https, none of them may be set, and nothing
// changes: the plain listener, own-proxy and tailnet ingress are as they
// were.
func parsePublicHTTPS(values map[string]string, at func(string, string, ...any) error, c *Config) (*PublicHTTPS, error) {
	v := values["listen_https"]
	if v == "" || v == "off" {
		for _, name := range []string{"listen_http_redirect", "acme_email", "acme_ca", "acme_ca_root"} {
			if values[name] != "" {
				return nil, at(name, "is set, but listen_https is not; set listen_https (such as :443) to serve public HTTPS")
			}
		}
		return nil, nil
	}
	if err := listenAddress("listen_https", v, false, at); err != nil {
		return nil, err
	}
	p := &PublicHTTPS{Listen: v, CA: LetsEncryptDirectory}
	u := c.PublicURL
	if u == nil || u.Scheme != "https" {
		return nil, at("listen_https", "needs an https public_url: its host name is the certificate's")
	}
	host := strings.ToLower(u.Hostname())
	if LoopbackHost(host) || net.ParseIP(host) != nil || !publicDNSName.MatchString(host) {
		return nil, at("listen_https", "needs public_url to name a DNS name a public certificate can hold, such as varlatch.example.com (not %q)", host)
	}
	p.Host = host
	switch r := values["listen_http_redirect"]; r {
	case "":
		// Port 80 on the HTTPS listener's address.
		h, _, _ := net.SplitHostPort(v)
		p.RedirectListen = net.JoinHostPort(h, "80")
	case "off":
	default:
		if err := listenAddress("listen_http_redirect", r, false, at); err != nil {
			return nil, err
		}
		if r == v {
			return nil, at("listen_http_redirect", "must differ from listen_https")
		}
		p.RedirectListen = r
	}
	if v == c.Listen || p.RedirectListen != "" && p.RedirectListen == c.Listen {
		return nil, at("listen_https", "and listen_http_redirect must differ from listen, the plain listener")
	}
	// The plain listener stays on this machine: with public HTTPS, the
	// API and the dashboard are never served in plain text beyond it (a
	// proxy in front of the plain listener runs on this host).
	if lh, _, _ := net.SplitHostPort(c.Listen); !loopbackIP(lh) {
		return nil, at("listen", "%q: with listen_https, the plain listener must be on a loopback address (such as 127.0.0.1:8686), so nothing is served in plain text beyond this machine", c.Listen)
	}
	if e := values["acme_email"]; e != "" {
		if !emailAddress.MatchString(e) {
			return nil, at("acme_email", "%q is not an email address", e)
		}
		p.Email = e
	}
	if ca := values["acme_ca"]; ca != "" {
		cu, err := url.Parse(ca)
		if err != nil || cu.Scheme != "https" || cu.Host == "" || cu.User != nil || cu.Fragment != "" {
			// The value is not repeated: it may hold a user name and password.
			return nil, at("acme_ca", "is not an https ACME directory URL without a user name or password, such as %s", LetsEncryptDirectory)
		}
		p.CA = ca
	}
	if r := values["acme_ca_root"]; r != "" {
		if !filepath.IsAbs(r) {
			return nil, at("acme_ca_root", "%q is not an absolute path", r)
		}
		p.CARootFile = filepath.Clean(r)
	}
	return p, nil
}

// parseTailnet reads the tailnet_* settings: with tailnet = on, a hostname,
// at least one tag and a port are required.
func parseTailnet(values map[string]string, at func(string, string, ...any) error, c *Config, env Env) (*Tailnet, error) {
	switch v := values["tailnet"]; v {
	case "", "off":
		for _, name := range []string{"tailnet_hostname", "tailnet_tags", "tailnet_port", "tailnet_control_url", "tailnet_auth_key_file", "tailnet_https_port", "tailnet_browser_origins"} {
			if values[name] != "" {
				return nil, at(name, "is set, but tailnet is off; set tailnet = on to start the tailnet listener")
			}
		}
		return nil, nil
	case "on":
	default:
		return nil, at("tailnet", "%q must be on or off", v)
	}
	t := &Tailnet{}
	switch v := values["tailnet_hostname"]; {
	case v == "":
		return nil, at("tailnet", "on needs tailnet_hostname, the node's name, fixed at enrolment")
	case !tailnetHostname.MatchString(v):
		return nil, at("tailnet_hostname", "%q is not a host name (lower-case letters, digits and -, at most 63)", v)
	default:
		t.Hostname = v
	}
	for _, tag := range strings.Split(values["tailnet_tags"], ",") {
		if tag = strings.TrimSpace(tag); tag == "" {
			continue
		}
		if !tailnetTag.MatchString(tag) {
			return nil, at("tailnet_tags", "%q is not a tag such as tag:varlatch", tag)
		}
		t.Tags = append(t.Tags, tag)
	}
	if len(t.Tags) == 0 {
		return nil, at("tailnet", "on needs tailnet_tags: the node is always tagged (the tags its auth key grants, such as tag:varlatch)")
	}
	p, err := strconv.Atoi(values["tailnet_port"])
	if err != nil || p < 1 || p > 65535 {
		return nil, at("tailnet", "on needs tailnet_port, the tailnet listener's port (1 to 65535)")
	}
	t.Port = p
	switch v := values["tailnet_control_url"]; v {
	case "", TailscaleControlURL:
		// Tailscale's, given or not: the pin records it as "".
	default:
		u, msg := selfHostedControlURL(v)
		if msg != "" {
			return nil, at("tailnet_control_url", "%q: %s", v, msg)
		}
		t.ControlURL = u
	}
	switch v := values["tailnet_auth_key_file"]; {
	case v != "":
		if !filepath.IsAbs(v) {
			return nil, at("tailnet_auth_key_file", "%q is not an absolute path", v)
		}
		t.AuthKeyFile = filepath.Clean(v)
	case env("CREDENTIALS_DIRECTORY") != "":
		t.AuthKeyFile = filepath.Join(env("CREDENTIALS_DIRECTORY"), "tailnet-auth-key")
	}
	return t, parseBrowserEndpoint(values, at, c, t)
}

// selfHostedControlURL is a self-hosted control server's URL (Headscale),
// as the node is given it and the pin records it: lib/tailcontrol's rule
// (CanonicalControlURL), which varlatch migrate shares, so a server is
// spelled one way on both sides. msg says why v is refused, "" when it is
// not.
func selfHostedControlURL(v string) (string, string) { return tailcontrol.CanonicalControlURL(v) }

// parseBrowserEndpoint reads tailnet_https_port and tailnet_browser_origins
// (config.ts's tailnetBrowser): the browser endpoint is off unless the
// port is set, and then needs a port of its own and at least one origin.
// Its host is tailnet_hostname in the pinned tailnet, known at enrolment.
func parseBrowserEndpoint(values map[string]string, at func(string, string, ...any) error, c *Config, t *Tailnet) error {
	raw := values["tailnet_https_port"]
	if raw != "" && t.ControlURL != "" {
		// The browser endpoint serves the node's Tailscale certificate,
		// which only Tailscale's coordination server issues.
		return at("tailnet_https_port", "the browser endpoint serves a Tailscale certificate, which a self-hosted control server (tailnet_control_url) does not issue: "+
			"leave tailnet_https_port unset with a self-hosted control server")
	}
	if raw == "" {
		if values["tailnet_browser_origins"] != "" {
			return at("tailnet_browser_origins", "is set, but the browser endpoint is off; set tailnet_https_port to serve it")
		}
		return nil
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p < 1 || p > 65535 {
		return at("tailnet_https_port", "%q is not a port (1 to 65535)", raw)
	}
	if p == t.Port {
		return at("tailnet_https_port", "must differ from tailnet_port")
	}
	t.HTTPSPort = p
	// The dashboard's own origin by default, but only over HTTPS: a page
	// served in plain text could be altered on the way to an approved
	// device.
	seen := map[string]bool{}
	add := func(o string) {
		if !seen[o] {
			seen[o] = true
			t.BrowserOrigins = append(t.BrowserOrigins, o)
		}
	}
	if u := c.PublicURL; u != nil && (u.Scheme == "https" || loopbackOrigin[u.Hostname()] || loopbackOrigin["["+u.Hostname()+"]"]) {
		host := strings.ToLower(u.Host)
		if p := u.Port(); u.Scheme == "https" && p == "443" || u.Scheme == "http" && p == "80" {
			host = strings.TrimSuffix(host, ":"+p)
		}
		add(u.Scheme + "://" + host)
	}
	for _, entry := range strings.Split(values["tailnet_browser_origins"], ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		o, msg := browserOrigin(entry)
		if msg != "" {
			return at("tailnet_browser_origins", "%s", msg)
		}
		add(o)
	}
	if len(t.BrowserOrigins) == 0 {
		return at("tailnet_https_port", "needs a dashboard origin it may serve: an https public_url, or exact origins in tailnet_browser_origins")
	}
	return nil
}

// loopbackOrigin are the hosts plain http is allowed on.
var loopbackOrigin = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true}

// originHost is a DNS name or IPv4 address (lower case, as the URL parser
// leaves it), or a bracketed IPv6 address.
var originHost = regexp.MustCompile(`^(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)$`)

// browserOrigin is config.ts's browserOrigin: an origin exactly as a
// browser sends it (scheme, host and port, nothing else), https or plain
// http on loopback, never null or a wildcard. A non-empty message says
// why not.
func browserOrigin(raw string) (string, string) {
	if raw == "*" || raw == "null" {
		return "", fmt.Sprintf("%q is never allowed; list exact origins", raw)
	}
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		return "", fmt.Sprintf("%q is not an origin such as https://varlatch.example.com", raw)
	}
	hostname := u.Host
	if strings.HasPrefix(hostname, "[") {
		hostname = hostname[:strings.IndexByte(hostname, ']')+1]
	} else if i := strings.LastIndexByte(hostname, ':'); i >= 0 {
		hostname = hostname[:i]
	}
	if !(u.Protocol == "https:" || u.Protocol == "http:" && loopbackOrigin[hostname]) {
		return "", fmt.Sprintf("%q must use https (plain http only on localhost)", raw)
	}
	if origin := u.Protocol + "//" + u.Host; origin != raw {
		return "", fmt.Sprintf("%q must be exactly an origin, written %s", raw, origin)
	}
	if !originHost.MatchString(hostname) {
		return "", fmt.Sprintf("%q must name one host; wildcards are never allowed", raw)
	}
	return raw, ""
}

// backupDestinationName is a destinations file's key (destinationsSchema).
var backupDestinationName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Load reads and parses the file at path. A file that cannot be read is
// returned as the read error (not an *Error): it touches the disk.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, os.Getenv)
}

// fileExists is whether path names something (a credential's file).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
