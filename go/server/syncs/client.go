// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"net/http"
)

// UseClient makes s send the platforms' requests through c instead of the
// outbound policy's clients: tests, with fake platforms. Base identities
// are still checked by the policy.
func UseClient(s *Service, c *http.Client) { s.client = c }

// OnCommit makes s call hook with the name of every converge commit
// (CONVERGE.md), right after it committed: crash and fence tests. A hook
// that panics with Crash stops the engine there, as a process that died.
func OnCommit(s *Service, hook func(point string)) { s.commitHook = hook }

// ScanTriggers runs the engine's trigger scan alone (scanSyncTriggers):
// tests.
func ScanTriggers(ctx context.Context, s *Service) error { return s.scanTriggers(ctx) }

// ScanBatches sets how many batches of 500 events one pass's trigger scan
// reads at most (tests; the engine's is 200).
func ScanBatches(s *Service, n int) { s.scanBatches = n }
