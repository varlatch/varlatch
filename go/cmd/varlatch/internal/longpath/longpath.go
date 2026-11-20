// SPDX-License-Identifier: Apache-2.0

// Package longpath is a path as a direct Windows API call takes it at any
// length. The os package lifts the 260-character limit for its own calls
// (its internal fixLongPath); a syscall the CLI makes itself (CreateFile in
// the no-follow open and in find-files' link count) gets nothing, so a
// long path there fails. Of gives such a path the `\\?\` prefix. Elsewhere
// it is the path itself.
package longpath
