// SPDX-License-Identifier: AGPL-3.0-or-later

package entry

import (
	"sync"
	"time"
)

// The unknown tokens an address may ask for: beyond that it waits. A token
// has 256 random bits, so nobody finds one by trying, and each try costs one
// read of an index at most; this says so to whoever tries. It stops no token
// that is a link's: many people share an address, and whoever is one of them
// could stop all the others.
const (
	maxUnknown    = 20
	unknownWindow = 10 * time.Minute
	maxAddresses  = 10_000
)

type attempts struct {
	until time.Time
	n     int
}

// limiter counts unknown tokens by client address, in the process.
type limiter struct {
	mu sync.Mutex
	by map[string]*attempts
}

// blocked is how long the address still has to wait, 0 when it has not.
func (l *limiter) blocked(client string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.by[client]
	if a == nil || !a.until.After(now) || a.n < maxUnknown {
		return 0
	}
	return a.until.Sub(now)
}

// unknown counts one.
func (l *limiter) unknown(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.by == nil {
		l.by = map[string]*attempts{}
	}
	a := l.by[client]
	if a == nil || !a.until.After(now) {
		if len(l.by) >= maxAddresses {
			for k, v := range l.by {
				if !v.until.After(now) {
					delete(l.by, k)
				}
			}
			if len(l.by) >= maxAddresses {
				// Full of live ones: the request window is what is left.
				return
			}
		}
		a = &attempts{until: now.Add(unknownWindow)}
		l.by[client] = a
	}
	a.n++
}
