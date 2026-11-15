// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !g9a

package stages

import "context"

// Mark is a stage's start: nothing outside the g9a build.
type Mark struct{}

// Start reads no clock outside the g9a build.
func Start() Mark { return Mark{} }

// Since records nothing outside the g9a build.
func Since(context.Context, string, Mark) {}

// Admitted records nothing outside the g9a build.
func Admitted(context.Context) {}
