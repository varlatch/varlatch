// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"context"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// PruneInterval is how often RunPruneLoop prunes the uses of tokens
// exchanged once.
const PruneInterval = time.Hour

// pruneBatch is how many uses PruneOidcTokenUses removes at most in one
// write job.
const pruneBatch = 500

// PruneTokenUses removes the uses of tokens no longer accepted (their exp,
// ClockSkew and useKept past), a bounded number per write job so the single
// writer is never held for long: how many it removed. A limited exchange
// prunes a batch as it records its own use; this prunes the rest, also
// when no exchange follows.
func (s *Service) PruneTokenUses(ctx context.Context) (int64, error) {
	var total int64
	for {
		var n int64
		err := s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
			var err error
			n, err = query.New(tx).PruneOidcTokenUses(ctx, s.now().UnixMicro())
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < pruneBatch {
			return total, nil
		}
	}
}

// RunPruneLoop is PruneTokenUses at once, then every interval until ctx
// ends, each pass inside admit (the maintenance admission) when set.
func (s *Service) RunPruneLoop(ctx context.Context, interval time.Duration, admit func() (leave func(), ok bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		func() {
			if admit != nil {
				leave, ok := admit()
				if !ok {
					return
				}
				defer leave()
			}
			if _, err := s.PruneTokenUses(ctx); err != nil && ctx.Err() == nil {
				s.log().Error("cannot prune the uses of OIDC tokens exchanged once; tried again later", "error", err)
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
