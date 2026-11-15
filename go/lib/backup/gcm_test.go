// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// The streaming GCM gives crypto/cipher's ciphertext and tag for every
// length around block boundaries, any additional data, and any way the
// message is split into writes; opening it back checks the tag and fails
// on any change.
func TestStreamingGCMIsGCM(t *testing.T) {
	key, nonce := make([]byte, 32), make([]byte, 12)
	lengths := []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 4096, 65_537, 1 << 20}
	for _, aadLen := range []int{0, 1, 16, 36, 100} {
		for _, n := range lengths {
			rand.Read(key)
			rand.Read(nonce)
			aad, plain := make([]byte, aadLen), make([]byte, n)
			rand.Read(aad)
			rand.Read(plain)
			block, _ := aes.NewCipher(key)
			gcm, _ := cipher.NewGCM(block)
			want := gcm.Seal(nil, nonce, plain, aad)

			for _, chunk := range []int{1, 7, 16, 1000, n + 1} {
				s, err := newGCMStream(key, nonce, aad, false)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 0, n+gcmTagSize)
				for off := 0; off < n; off += chunk {
					end := min(off+chunk, n)
					out := make([]byte, end-off)
					if err := s.xor(out, plain[off:end]); err != nil {
						t.Fatal(err)
					}
					got = append(got, out...)
				}
				tag := s.tag()
				got = append(got, tag[:]...)
				if !bytes.Equal(got, want) {
					t.Fatalf("aad %d, length %d, writes of %d: differs from crypto/cipher", aadLen, n, chunk)
				}
			}

			o, _ := newGCMStream(key, nonce, aad, true)
			back := make([]byte, n)
			if err := o.xor(back, want[:n]); err != nil {
				t.Fatal(err)
			}
			if !o.verify(want[n:]) || !bytes.Equal(back, plain) {
				t.Fatalf("aad %d, length %d: does not open", aadLen, n)
			}
			if n >= 2*gcmBlockSize {
				// Two ciphertext blocks swapped: the tag catches the order.
				swapped := bytes.Clone(want)
				copy(swapped[:gcmBlockSize], want[gcmBlockSize:2*gcmBlockSize])
				copy(swapped[gcmBlockSize:2*gcmBlockSize], want[:gcmBlockSize])
				if !bytes.Equal(swapped[:2*gcmBlockSize], want[:2*gcmBlockSize]) {
					o, _ := newGCMStream(key, nonce, aad, true)
					_ = o.xor(make([]byte, n), swapped[:n])
					if o.verify(swapped[n:]) {
						t.Fatalf("aad %d, length %d: swapped blocks still verify", aadLen, n)
					}
				}
			}
			if n > 0 {
				bad := bytes.Clone(want)
				bad[n/2] ^= 1
				o, _ := newGCMStream(key, nonce, aad, true)
				_ = o.xor(make([]byte, n), bad[:n])
				if o.verify(bad[n:]) {
					t.Fatalf("aad %d, length %d: a changed byte still verifies", aadLen, n)
				}
			}
		}
	}
}

func BenchmarkStreamingGCM(b *testing.B) {
	key, nonce := make([]byte, 32), make([]byte, 12)
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	s, _ := newGCMStream(key, nonce, nil, false)
	for b.Loop() {
		_ = s.xor(buf, buf)
	}
}

// One message holds at most maxMessageBlocks blocks (the 32-bit counter
// starts at 2 and must not wrap): the last block is accepted, a byte more
// is refused, sealing and opening alike.
func TestGCMBlockLimit(t *testing.T) {
	key, nonce := make([]byte, 32), make([]byte, 12)
	for _, open := range []bool{false, true} {
		s, err := newGCMStream(key, nonce, nil, open)
		if err != nil {
			t.Fatal(err)
		}
		// As if all but the last block had been processed.
		s.ctLen = (maxMessageBlocks - 1) * gcmBlockSize
		if err := s.xor(make([]byte, gcmBlockSize), make([]byte, gcmBlockSize)); err != nil {
			t.Fatalf("open %v: the last block: %v", open, err)
		}
		if err := s.xor(make([]byte, 1), make([]byte, 1)); err != errGCMTooLong {
			t.Fatalf("open %v: a byte beyond the limit: %v", open, err)
		}
		// A partial block counts as a block.
		s2, _ := newGCMStream(key, nonce, nil, open)
		s2.ctLen = maxMessageBlocks*gcmBlockSize - 1
		if err := s2.xor(make([]byte, 1), make([]byte, 1)); err != nil {
			t.Fatalf("open %v: the last byte: %v", open, err)
		}
		if err := s2.xor(make([]byte, 1), make([]byte, 1)); err != errGCMTooLong {
			t.Fatalf("open %v: the byte after the last: %v", open, err)
		}
	}
	if maxMessageBlocks*gcmBlockSize < MaxBytes+1<<20 {
		t.Fatal("the archive limit is not below one message's")
	}
}
