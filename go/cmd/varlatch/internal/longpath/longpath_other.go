// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package longpath

// Of is path: only Windows limits a path's length this way.
func Of(path string) string { return path }
