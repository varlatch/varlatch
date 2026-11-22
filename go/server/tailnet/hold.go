// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// A tailnet handoff (internal docs/design/go-step7.md decision 11, slice
// 7.5b) enrols this installation's node under a temporary name before the
// name moves to it, and keeps its tailnet listener closed until the handoff
// opens it: `varlatchd admin tailnet enroll` writes the hold, a varlatchd
// started under it joins the tailnet under the temporary name and serves
// nothing on it, and `varlatchd admin tailnet open` removes it, then
// listens. The hold is written before the node first joins, so a crash
// after the join still leaves the node held.

// HoldFile is the hold's file in the data directory.
const HoldFile = "tailnet-handoff.json"

// Hold is a node enrolled for a handoff, not yet opened.
type Hold struct {
	// Hostname is the temporary name the node enrolled under: varlatchd
	// starts the node with it while the hold stands, so the node never
	// announces its configured name (which another node holds) before the
	// handoff renames it.
	Hostname string    `json:"hostname"`
	Since    time.Time `json:"since"`
}

// LoadHold reads the data directory's hold; nil (and no error) when there
// is none.
func LoadHold(dataDir string) (*Hold, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, HoldFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h Hold
	if err := json.Unmarshal(b, &h); err != nil || !ValidHostname(h.Hostname) {
		return nil, fmt.Errorf("tailnet: the handoff's hold %s is not readable: remove it only if no handoff is running", filepath.Join(dataDir, HoldFile))
	}
	return &h, nil
}

// SaveHold writes the hold durably (0600, renamed into place, the
// directory synced).
func SaveHold(dataDir string, h *Hold) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return writeDurably(filepath.Join(dataDir, HoldFile), append(b, '\n'))
}

// ClearHold removes the hold durably; nothing when there is none.
func ClearHold(dataDir string) error {
	err := os.Remove(filepath.Join(dataDir, HoldFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(dataDir)
}

// hostnameLabel is a node's name as varlatchd.conf takes it.
var hostnameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname is whether name is a node's name: lower-case letters,
// digits and -, at most 63.
func ValidHostname(name string) bool { return hostnameLabel.MatchString(name) }

// CertFile is where the node caches its certificate for domain: tsnet's
// ACME store, in the node's state directory (certs/<domain>.crt).
func CertFile(dataDir, domain string) string {
	return filepath.Join(dataDir, StateDir, "certs", strings.ToLower(domain)+".crt")
}

// CachedNotAfter is when the node's cached certificate for domain ends,
// read from its state directory without asking for one: false when it
// holds none.
func CachedNotAfter(dataDir, domain string) (time.Time, bool, error) {
	b, err := os.ReadFile(CertFile(dataDir, domain))
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return LeafNotAfter(b)
}

// LeafNotAfter is the first certificate's NotAfter in a PEM chain.
func LeafNotAfter(certPEM []byte) (time.Time, bool, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, false, errors.New("tailnet: the cached certificate is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false, err
	}
	return c.NotAfter, true, nil
}

// writeDurably writes b to path through a temporary file in its directory
// (0600), renamed into place, the directory synced.
func writeDurably(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hold-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
