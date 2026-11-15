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
