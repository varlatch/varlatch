// SPDX-License-Identifier: Apache-2.0

// Package tailcontrol is what a tailnet handoff (ADR-0059 Decision 9 phase
// 5; internal docs/design/go-step7.md decision 11, slice 7.5a) asks of the
// tailnet's control plane: list its devices, rename one, and read the name
// back. One interface, two backends:
//
//   - Tailscale's API, with an OAuth client the operator created with the
//     devices:core scope only (O4). A token is exchanged for each
//     operation and dropped after it; nothing keeps one.
//   - Headscale, through its CLI on the control server or its API with a
//     key that expires within the hour, expired when the work ends (Close).
//
// On top of either: canonical temporary names (TempName), the
// case-insensitive collision checks made before a handoff (CheckNames), and
// a rename that counts only once the control plane reports the exact name
// (RenameAndReadBack). Errors name the operation and the device, never a
// credential (OpError, scrub).
//
// The handoffs themselves (forward, reverse, restore, their undo and
// deadline) are slice 7.5b.
package tailcontrol

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Device is one node of the tailnet as its control plane lists it.
type Device struct {
	// ID is the control plane's own identifier, the one a rename takes:
	// Tailscale's device id, Headscale's node id.
	ID string
	// NodeID is Tailscale's stable node id (nodeId); empty on Headscale.
	NodeID string
	// Name is the node's machine name, the first label of its MagicDNS
	// name, as the control plane reports it (case kept).
	Name string
	// Online is whether the node is connected to the control plane now.
	Online bool
	// Expired is whether its key has expired (it holds its name still).
	Expired bool
	// LastSeen is when the control plane last saw it, if it says.
	LastSeen time.Time
}

// State is how a device is described in an error: online, offline or
// expired.
func (d Device) State() string {
	switch {
	case d.Expired:
		return "expired"
	case d.Online:
		return "online"
	default:
		return "offline"
	}
}

func (d Device) String() string { return fmt.Sprintf("%s (%s, %s)", d.Name, d.ID, d.State()) }

// ControlPlane is one tailnet's control plane.
type ControlPlane interface {
	// Kind is "tailscale" or "headscale".
	Kind() string
	// Devices lists every device, offline and expired ones included.
	Devices(ctx context.Context) ([]Device, error)
	// Rename asks the control plane to give the device with this ID the
	// name. It does not say what name the device ended up with:
	// RenameAndReadBack does.
	Rename(ctx context.Context, deviceID, name string) error
	// Close ends the authority given for the work: a Headscale API key is
	// expired; nothing is kept for Tailscale.
	Close(ctx context.Context) error
}

// OpError is a failed control-plane operation: which operation, on which
// device (empty for a listing), and why. Its text never holds a
// credential.
type OpError struct {
	Plane  string // "tailscale" or "headscale"
	Op     string // "list devices", "rename", "read back", "token", "check key", "close"
	Device string // the device's ID or name, when there is one
	Err    error
}

func (e *OpError) Error() string {
	if e.Device == "" {
		return fmt.Sprintf("%s control plane: %s: %v", e.Plane, e.Op, e.Err)
	}
	return fmt.Sprintf("%s control plane: %s %s: %v", e.Plane, e.Op, e.Device, e.Err)
}

func (e *OpError) Unwrap() error { return e.Err }

// ErrNameTaken is a rename the control plane refused because the name is
// another device's.
var ErrNameTaken = errors.New("the name is another device's")

// ReadBackError is a rename the control plane accepted but did not apply as
// asked: it reports another name for the device (a rewritten name, a
// suffix), or no longer lists it.
type ReadBackError struct {
	Want, Got string
	Missing   bool
}

func (e *ReadBackError) Error() string {
	if e.Missing {
		return fmt.Sprintf("the device is no longer listed after it was renamed to %q", e.Want)
	}
	return fmt.Sprintf("the control plane reports the name %q, not %q", e.Got, e.Want)
}

// MaxNameLen is a machine name's longest form in bytes: one DNS label.
const MaxNameLen = 63

// Canonical reports whether name is a machine name in canonical form: 1 to
// 63 bytes of lowercase a-z, 0-9 and hyphens, neither first nor last a
// hyphen. Tailscale silently rewrites anything else (ADR-0059 Decision 9),
// so only canonical names are ever asked for.
func Canonical(name string) bool {
	if len(name) == 0 || len(name) > MaxNameLen || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Roles of a temporary name: the new node's, or the old one's.
const (
	RoleNew = "n"
	RoleOld = "o"
)

// NewOperationID is a handoff's identifier, as its temporary names carry it:
// 10 characters of lowercase base32, random.
func NewOperationID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return string(b[:]), nil
}

// TempName is a handoff's temporary name for one role (decision 11):
// <name>-vl-<operation id>-n for the new node, -o for the old one, in
// canonical form. When the whole would pass 63 bytes, <name> is cut, never
// the operation id or the role, so the names of two operations or two
// roles never meet.
func TempName(name, operationID, role string) (string, error) {
	if !Canonical(name) {
		return "", fmt.Errorf("tailnet name %q is not in canonical form", name)
	}
	if operationID == "" || !Canonical(operationID) || strings.Contains(operationID, "-") {
		return "", fmt.Errorf("operation id %q is not lowercase letters and digits", operationID)
	}
	if role != RoleNew && role != RoleOld {
		return "", fmt.Errorf("unknown role %q", role)
	}
	suffix := "-vl-" + operationID + "-" + role
	if len(suffix) >= MaxNameLen {
		return "", fmt.Errorf("operation id %q leaves no room for the name", operationID)
	}
	base := name
	if len(base)+len(suffix) > MaxNameLen {
		base = strings.TrimRight(base[:MaxNameLen-len(suffix)], "-")
	}
	if base == "" {
		return "", fmt.Errorf("tailnet name %q leaves nothing once cut", name)
	}
	return base + suffix, nil
}

// NamePlan is what a handoff needs of the tailnet's names before it starts.
type NamePlan struct {
	// Name is the tailnet name the handoff moves.
	Name string
	// Holder is the ID of the device that must hold Name now, exactly;
	// empty when no device may hold it (a restore after the dead node was
	// deleted).
	Holder string
	// Temporary are the names the handoff will use, each of which must be
	// free.
	Temporary []string
}

// CheckNames checks a plan against every device the control plane lists,
// offline and expired ones included, comparing names case-insensitively:
// Headscale accepts a case variant ("VAULT" beside "vault") and the variant
// takes over the name's resolution (ADR-0059 Decision 9). It reports every
// problem at once.
func CheckNames(devices []Device, p NamePlan) error {
	var problems []string
	for _, n := range append([]string{p.Name}, p.Temporary...) {
		if !Canonical(n) {
			problems = append(problems, fmt.Sprintf("%q is not in canonical form", n))
		}
	}
	held := false
	for _, d := range devices {
		if !strings.EqualFold(d.Name, p.Name) {
			continue
		}
		switch {
		case p.Holder != "" && d.ID == p.Holder && d.Name == p.Name:
			held = true
		case p.Holder != "" && d.ID == p.Holder:
			problems = append(problems, fmt.Sprintf("the expected holder %s holds %q only as a case variant", d, p.Name))
		default:
			problems = append(problems, fmt.Sprintf("%q is held by %s, not the expected device", p.Name, d))
		}
	}
	if p.Holder != "" && !held {
		problems = append(problems, fmt.Sprintf("the expected holder %s does not hold %q", p.Holder, p.Name))
	}
	for _, t := range p.Temporary {
		for _, d := range devices {
			if strings.EqualFold(d.Name, t) {
				problems = append(problems, fmt.Sprintf("the temporary name %q is held by %s", t, d))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the tailnet's names do not allow the handoff: %s", strings.Join(problems, "; "))
	}
	return nil
}

// RenameAndReadBack renames a device and then reads its name back from the
// control plane: the rename counts only when the device is listed under
// exactly that name (ADR-0059 Decision 9: anything else is a failure, and
// starts the undo). The name must be canonical.
func RenameAndReadBack(ctx context.Context, cp ControlPlane, deviceID, name string) (Device, error) {
	if !Canonical(name) {
		return Device{}, &OpError{Plane: cp.Kind(), Op: "rename", Device: deviceID, Err: fmt.Errorf("%q is not in canonical form", name)}
	}
	if err := cp.Rename(ctx, deviceID, name); err != nil {
		return Device{}, err
	}
	devices, err := cp.Devices(ctx)
	if err != nil {
		return Device{}, err
	}
	for _, d := range devices {
		if d.ID != deviceID {
			continue
		}
		if d.Name != name {
			return d, &OpError{Plane: cp.Kind(), Op: "read back", Device: deviceID, Err: &ReadBackError{Want: name, Got: d.Name}}
		}
		return d, nil
	}
	return Device{}, &OpError{Plane: cp.Kind(), Op: "read back", Device: deviceID, Err: &ReadBackError{Want: name, Missing: true}}
}

// scrub replaces every credential in text with [redacted]: an error built
// from a control plane's answer can echo what it was sent.
func scrub(text string, secrets ...string) string {
	for _, s := range secrets {
		if len(s) >= 4 {
			text = strings.ReplaceAll(text, s, "[redacted]")
		}
	}
	return text
}
