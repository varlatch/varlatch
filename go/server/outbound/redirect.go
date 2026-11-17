// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !conformance

package outbound

// redirect is the conformance build's host override (redirect_conformance.go).
// A release has none: every destination is resolved as it is named.
func (p *Policy) redirect(d Destination) (Destination, string, bool) { return d, "", false }
