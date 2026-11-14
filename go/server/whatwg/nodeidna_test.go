// SPDX-License-Identifier: AGPL-3.0-or-later

package whatwg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var raceEnabled bool

// Every code point, in fifteen labels, gives Node's answer
// (testdata/node-idna.json: a hash of Node's url.domainToASCII answers per
// block of 256 code points, from testdata/nodeidna.mjs). Pure computation,
// so it is skipped under the race detector, where it takes minutes.
func TestDomainToASCIIMatchesNodeForEveryCodePoint(t *testing.T) {
	if raceEnabled {
		t.Skip("pure computation; covered by the ordinary run")
	}
	raw, err := os.ReadFile("testdata/node-idna.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Node      string      `json:"node"`
		Templates [][2]string `json:"templates"`
		Blocks    []string    `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Node != nodeVersion {
		t.Fatalf("node-idna.json is from Node %s, nodeidna_table.go from %s: regenerate both", v.Node, nodeVersion)
	}
	// Block 0 covers U+0020 to U+00FF, then one block per 256.
	block := func(b int) (lo, hi rune) {
		if b == 0 {
			return 0x20, 0xff
		}
		return rune(b) * 256, rune(b)*256 + 255
	}
	if want := 0x110000 / 256; len(v.Blocks) != want {
		t.Fatalf("%d blocks, want %d", len(v.Blocks), want)
	}
	got := make([]string, len(v.Blocks))
	var wg sync.WaitGroup
	next := make(chan int)
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for b := range next {
				h := sha256.New()
				lo, hi := block(b)
				for cp := lo; cp <= hi; cp++ {
					if cp >= 0xd800 && cp <= 0xdfff {
						continue
					}
					x := string(cp)
					outs := make([]string, len(v.Templates))
					for i, tpl := range v.Templates {
						outs[i] = DomainToASCII(tpl[0] + x + tpl[1])
					}
					h.Write([]byte(strings.Join(outs, "|") + "\n"))
				}
				got[b] = hex.EncodeToString(h.Sum(nil))[:16]
			}
		})
	}
	for b := range v.Blocks {
		next <- b
	}
	close(next)
	wg.Wait()
	bad := 0
	for b := range v.Blocks {
		if got[b] != v.Blocks[b] {
			lo, hi := block(b)
			if bad < 20 {
				t.Errorf("U+%04X..U+%04X: answers differ from Node's", lo, hi)
			}
			bad++
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d blocks differ", bad, len(v.Blocks))
	}
}
