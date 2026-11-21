// SPDX-License-Identifier: Apache-2.0

//go:build !crashpoint

package migrate

// crashPoint marks a point G5's interruption gate kills varlatch migrate
// at (crashpoint.go, a build with the crashpoint tag); in every other build
// it does nothing, and the compiler removes the calls.
func crashPoint(string) {}
