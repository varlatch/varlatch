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
	// Key's file (32 bytes, hex or base64); without one, varlatchd makes no
	// scheduled backup.
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
}

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
	"backup_key_file", "backup_interval", "backup_keep", "backup_destinations_file", "backup_destination"}

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
	if v := values["backup_key_file"]; v != "" {
		c.BackupKeyFile = filepath.Clean(v)
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
	return c, nil
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
