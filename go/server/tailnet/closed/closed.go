// SPDX-License-Identifier: AGPL-3.0-or-later

// Package closed names why tailnet access is closed (tailnet.Manager's
// Closed): a leaf package, so that the tailnet package and its readers
// (doctor) share the same values without doctor importing tsnet.
package closed

// The ways a pin no longer holds (tailnet.Pin.Check).
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

// PinMissing is why access is closed for an enrolled node without a pin.
const PinMissing = "pin-missing"

// NameSuffixed is why access is closed for a node the control plane named
// its configured hostname with a suffix (varlatch-1): the name is still held
// by another node, as after a restore while the old installation's node is
// not deleted (internal docs/design/go-step6.md decision 16).
const NameSuffixed = "name-suffixed"

// TagsDiffer is why tailnet access is closed while a node on a self-hosted
// control server does not carry exactly tailnet_tags (ADR-0059 amendment
// 11): never latched, checked again at every check.
const TagsDiffer = "tags-differ"

// NotEnrolled is why access is closed for a node that has not been on its
// tailnet yet: its pin is recorded the first time it is.
const NotEnrolled = "not-enrolled"

// Why a node that has not joined its tailnet since varlatchd started keeps
// access closed (tailnet.Manager's SetJoin).
const (
	// WaitingForControl: the control server does not answer, or puts the
	// node off; it joins, and the listener opens, when the server does.
	WaitingForControl = "waiting-for-control"
	// LoginNeeded: the node must be logged in or approved at its control
	// server; it joins, and the listener opens, once it is.
	LoginNeeded = "login-needed"
	// JoinRefused: the control server refused the node; the listener stays
	// closed until varlatchd starts again.
	JoinRefused = "join-refused"
)
