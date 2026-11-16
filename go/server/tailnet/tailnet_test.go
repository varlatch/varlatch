// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// fakeNode answers WhoIs from a table, and its own StableID.
type fakeNode struct {
	peers   map[string]Peer
	whoErr  error
	self    func() (string, error)
	selfies atomic.Int32
}

func (n *fakeNode) WhoIs(_ context.Context, remote string) (Peer, error) {
	if n.whoErr != nil {
		return Peer{}, n.whoErr
	}
	p, ok := n.peers[remote]
	if !ok {
		return Peer{}, ErrUnknownPeer
	}
	return p, nil
}

func (n *fakeNode) SelfID(context.Context) (string, error) {
	n.selfies.Add(1)
	if n.self != nil {
		return n.self()
	}
	return "nSelf", nil
}

// The ADR-0014 rules, as whois.ts applies them: each refusal's reason,
// and the context of a recognized device (tags only for a tagged one).
func TestResolve(t *testing.T) {
	node := &fakeNode{peers: map[string]Peer{
		"100.64.0.1:1": {StableID: "nTag", Name: "build-1.corp.ts.net.", Tags: []string{"tag:prod"}, LoginName: "tagged-devices"},
		"100.64.0.2:1": {StableID: "nUser", Name: "laptop.corp.ts.net", LoginName: "alice@example.com"},
		"100.64.0.3:1": {StableID: "nShared", Name: "laptop.corp.ts.net", Sharer: 7},
		"100.64.0.4:1": {StableID: "nOther", Name: "box.other.ts.net"},
		"100.64.0.5:1": {StableID: "nSelf", Name: "varlatch.corp.ts.net"},
		"100.64.0.6:1": {StableID: "", Name: "x.corp.ts.net"},
		"100.64.0.7:1": {StableID: "nNoName"},
		"100.64.0.8:1": {StableID: "nBare", Name: "bare"},
	}}
	r := NewResolver(node, "corp.ts.net", nil)
	for remote, want := range map[string]string{
		"100.64.0.1:1": `{"tailnet":"corp.ts.net","nodeId":"nTag","nodeName":"build-1","tags":["tag:prod"]}`,
		"100.64.0.2:1": `{"tailnet":"corp.ts.net","nodeId":"nUser","nodeName":"laptop","tags":[],"userLogin":"alice@example.com"}`,
		"100.64.0.3:1": `{"refused":"shared"}`,
		"100.64.0.4:1": `{"refused":"other-tailnet"}`,
		"100.64.0.5:1": `{"refused":"self"}`,
		"100.64.0.6:1": `{"refused":"resolver-unavailable"}`,
		"100.64.0.7:1": `{"refused":"resolver-unavailable"}`,
		"100.64.0.8:1": `{"refused":"other-tailnet"}`,
		"100.64.0.9:1": `{"refused":"unrecognized"}`,
	} {
		if got := string(jsvalue.Stringify(r.Resolve(context.Background(), remote).JSValue())); got != want {
			t.Errorf("%s: %s, want %s", remote, got, want)
		}
	}
	node.whoErr = errors.New("local API down")
	if got := r.Resolve(context.Background(), "100.64.0.1:1"); got.Refused != ResolverUnavailable {
		t.Errorf("a failing WhoIs: %+v", got)
	}
	node.whoErr = nil
	node.self = func() (string, error) { return "", errors.New("status down") }
	if got := r.Resolve(context.Background(), "100.64.0.1:1"); got.Refused != ResolverUnavailable {
		t.Errorf("an unknown self: %+v", got)
	}
}

// The node's own StableID is read for every caller with a read that began
// after the caller arrived: one in flight when a caller arrives is not
// reused; callers arriving together share the next one.
func TestSelfReadsAreFreshAndShared(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 10)
	var reads atomic.Int32
	node := &fakeNode{self: func() (string, error) {
		n := reads.Add(1)
		started <- struct{}{}
		<-release
		return "id" + string(rune('0'+n)), nil
	}}
	s := &selfReader{node: node, log: NewResolver(node, "x", nil).self.log}
	first := make(chan string, 1)
	go func() { first <- s.get(context.Background()) }()
	<-started // read 1 is in flight
	var wg sync.WaitGroup
	later := make([]string, 5)
	for i := range later {
		wg.Add(1)
		go func() { defer wg.Done(); later[i] = s.get(context.Background()) }()
	}
	time.Sleep(50 * time.Millisecond) // the five queue behind read 1
	release <- struct{}{}             // read 1 ends
	<-started                         // read 2 starts, for the five
	release <- struct{}{}
	wg.Wait()
	if got := <-first; got != "id1" {
		t.Fatalf("the first caller: %q", got)
	}
	for _, got := range later {
		if got != "id2" {
			t.Fatalf("a caller that arrived during read 1 got %q, want read 2's", got)
		}
	}
	if n := reads.Load(); n != 2 {
		t.Fatalf("%d reads, want 2", n)
	}
}
