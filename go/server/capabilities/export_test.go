// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities

// SetAfterBatch sets what each repair batch reports (tests); nil stops it.
func SetAfterBatch(f func(n int)) { afterBatch = f }
