// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The pin (ADR-0059 Decision 5): the tailnet varlatchd trusts, recorded at
// enrolment. It is the control URL plus a stable tailnet identifier: on
// Tailscale the tailnet's StableID, with the MagicDNS suffix recorded
// beside it; on Headscale, which has no tailnet identifier, the
// base_domain, which is the MagicDNS suffix. The tailnet's display name is
// never a pin. Every peer's name must end in the pinned suffix.
//
// A changed pin closes tailnet access (fail closed) until the operator
// re-pins on the host. Only a changed suffix is ever re-pinned in place:
// under the same StableID on Tailscale, under the same control URL on
// Headscale. A different StableID or control URL is a different tailnet,
// never re-pinned: that means enrolling again.

// Pin is the recorded tailnet.
type Pin struct {
	// ControlURL is the coordination server the node enrolled with ("" is
	// Tailscale's).
	ControlURL string `json:"controlUrl"`
	// TailnetID is Tailscale's tailnet StableID; "" on Headscale.
	TailnetID string `json:"tailnetId"`
	// Suffix is the MagicDNS suffix (Headscale's base_domain).
	Suffix string `json:"suffix"`
	// PinnedAt is when it was recorded or last re-pinned (RFC 3339).
	PinnedAt string `json:"pinnedAt"`
	// History lists every earlier pin, oldest first: a re-pin's record.
	History []Repinned `json:"history,omitempty"`
}

// Repinned is one re-pin: what was pinned before, and when it changed.
type Repinned struct {
	Suffix string `json:"suffix"`
	Until  string `json:"until"`
}

// Observed is what the node says it is on now.
type Observed struct {
	ControlURL string `json:"controlUrl"`
	TailnetID  string `json:"tailnetId"`
	Suffix     string `json:"suffix"`
}

// The ways a pin no longer holds.
const (
	// PinControlURL: the node is configured for another control server.
	PinControlURL = "control-url-changed"
	// PinTailnet: the tailnet's StableID is another one.
	PinTailnet = "tailnet-changed"
	// PinSuffix: the MagicDNS suffix changed under the same tailnet: the
	// one change a re-pin accepts.
	PinSuffix = "suffix-changed"
	// PinUnknown: the node does not know its tailnet yet.
	PinUnknown = "tailnet-unknown"
)

// Check is "" when the pin holds for observed, else the way it does not.
func (p *Pin) Check(o Observed) string {
	switch {
	case o.ControlURL != p.ControlURL:
		return PinControlURL
	case o.Suffix == "":
		return PinUnknown
	case p.TailnetID != o.TailnetID:
		return PinTailnet
	case o.Suffix != p.Suffix:
		return PinSuffix
	}
	return ""
}

// ErrNotRepinnable is a re-pin of a change that is a different tailnet.
var ErrNotRepinnable = errors.New("tailnet: this is a different tailnet, which is never re-pinned in place: enrol the node again")

// Repin is the pin with observed's suffix, when the only change is the
// suffix; otherwise ErrNotRepinnable (or nil, when nothing changed).
func (p *Pin) Repin(o Observed, now time.Time) (*Pin, error) {
	switch p.Check(o) {
	case "":
		return nil, nil
	case PinSuffix:
	default:
		return nil, ErrNotRepinnable
	}
	next := *p
	next.History = append(append([]Repinned{}, p.History...), Repinned{Suffix: p.Suffix, Until: now.UTC().Format(time.RFC3339)})
	next.Suffix, next.PinnedAt = o.Suffix, now.UTC().Format(time.RFC3339)
	return &next, nil
}

// normalize is a suffix as compared: lower case, no trailing dot.
func normalize(suffix string) string { return strings.ToLower(strings.TrimSuffix(suffix, ".")) }

// LoadPin reads the pin at path; nil (and no error) when there is none.
func LoadPin(path string) (*Pin, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pin
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("tailnet: the pin %s is not readable: %w", path, err)
	}
	if p.Suffix == "" {
		return nil, fmt.Errorf("tailnet: the pin %s names no tailnet", path)
	}
	return &p, nil
}

// SavePin writes the pin to path durably: a new file, synced, renamed over
// the old one, the directory synced.
func SavePin(path string, p *Pin) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pin-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
