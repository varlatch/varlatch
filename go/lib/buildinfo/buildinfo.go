// SPDX-License-Identifier: Apache-2.0

// Package buildinfo holds the version both binaries report. Release builds
// set it with -ldflags "-X github.com/varlatch/varlatch/go/lib/buildinfo.Version=<version>".
package buildinfo

// Version is the release version, or a development marker.
var Version = "0.50.0-dev"
