// SPDX-License-Identifier: Apache-2.0

//go:build !conformance

package main

// conformanceTrustedRoot: none outside the conformance build
// (verify_release_conformance.go). A constant, so nothing can set it.
const conformanceTrustedRoot = ""
