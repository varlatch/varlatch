// SPDX-License-Identifier: Apache-2.0

//go:build conformance

package main

// conformanceTrustedRoot is the trusted root verify-release uses when none
// is given, set at link time (-X main.conformanceTrustedRoot=<file>) by the
// conformance harness, which builds this CLI to be served by varlatchd's
// serve_cli and signs it with a test Sigstore. A release build has no
// conformance tag: there it is the empty constant of
// verify_release_release.go.
var conformanceTrustedRoot string
