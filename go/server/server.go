// SPDX-License-Identifier: AGPL-3.0-or-later

// Package server is the root of varlatchd's own packages (ADR-0059). Code
// under go/server/ is AGPL-3.0-or-later; nothing Apache-licensed may import
// it (see go/licensing_test.go).
package server

// Name is the daemon's name, as it reports itself.
const Name = "varlatchd"
