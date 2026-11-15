// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// A streaming AES-256-GCM with a 96-bit nonce (NIST SP 800-38D): one GCM
// message over the whole archive, as Node's createCipheriv("aes-256-gcm")
// seals it (packages/backup sealArchive), so archives cross between the
// servers in both directions. crypto/cipher's GCM needs the whole message
// in memory; an archive is up to 60 GiB. The output equals crypto/cipher's
// for the same key, nonce, data and plaintext (gcm_test.go).
//
// The counter: GCM increments only the low 32 bits of the counter block
// (inc32); cipher.NewCTR increments all 128. They agree while the low word
// does not wrap, which maxMessageBlocks guarantees: the block counter
// starts at 2.

const (
	gcmBlockSize = 16
	gcmNonceSize = 12
	gcmTagSize   = 16
	// maxMessageBlocks keeps the 32-bit counter from wrapping: 2^32 - 2
	// blocks, about 64 GiB (the archive limit is 60 GiB).
	maxMessageBlocks = 1<<32 - 2
)

var errGCMTooLong = errors.New("backup: message too long for one AES-GCM message")

// fieldElement is an element of GF(2^128) in GCM's bit order: low holds
// the first eight bytes of a block, big-endian.
type fieldElement struct{ low, high uint64 }

// ghash computes GCM's universal hash with 4-bit tables (Shoup's method).
type ghash struct {
	table [16]fieldElement
	y     fieldElement
	buf   [gcmBlockSize]byte
	n     int // bytes in buf
}

// double multiplies x by the field's generator: a right shift in GCM's
// reflected bit order, reduced by x^128 + x^7 + x^2 + x + 1.
func double(x fieldElement) fieldElement {
	carry := x.high&1 == 1
	d := fieldElement{low: x.low >> 1, high: x.high>>1 | x.low<<63}
	if carry {
		d.low ^= 0xe100000000000000
	}
	return d
}

// reverse4 reverses the order of a nibble's four bits.
func reverse4(i int) int {
	return (i&1)<<3 | (i&2)<<1 | (i&4)>>1 | (i&8)>>3
}

// reduction4 is the reduction of each of the 16 values shifted out by a
// 4-bit step, already positioned in the high 16 bits of low.
var reduction4 = [16]uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

func newGHASH(h []byte) *ghash {
	g := &ghash{}
	x := fieldElement{low: binary.BigEndian.Uint64(h[:8]), high: binary.BigEndian.Uint64(h[8:])}
	// The table holds i*H for every nibble i, indexed by the nibble's bits
	// reversed (the multiplication below reads words from their low end).
	g.table[reverse4(1)] = x
	for i := 2; i < 16; i += 2 {
		g.table[reverse4(i)] = double(g.table[reverse4(i/2)])
		t := g.table[reverse4(i)]
		g.table[reverse4(i+1)] = fieldElement{low: t.low ^ x.low, high: t.high ^ x.high}
	}
	return g
}

// mul sets y to y*H.
func (g *ghash) mul(y *fieldElement) {
	var z fieldElement
	for _, word := range [2]uint64{y.high, y.low} {
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high = z.high>>4 | z.low<<60
			z.low = z.low>>4 ^ uint64(reduction4[msw])<<48
			t := g.table[word&0xf]
			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}
	*y = z
}

func (g *ghash) block(b []byte) {
	g.y.low ^= binary.BigEndian.Uint64(b[:8])
	g.y.high ^= binary.BigEndian.Uint64(b[8:16])
	g.mul(&g.y)
}

// write hashes p as part of a zero-padded run (call pad to end the run).
func (g *ghash) write(p []byte) {
	if g.n > 0 {
		k := copy(g.buf[g.n:], p)
		g.n += k
		p = p[k:]
		if g.n < gcmBlockSize {
			return
		}
		g.block(g.buf[:])
		g.n = 0
	}
	for len(p) >= gcmBlockSize {
		g.block(p[:gcmBlockSize])
		p = p[gcmBlockSize:]
	}
	g.n = copy(g.buf[:], p)
}

// pad ends a run: its last partial block is hashed zero-padded.
func (g *ghash) pad() {
	if g.n > 0 {
		clear(g.buf[g.n:])
		g.block(g.buf[:])
		g.n = 0
	}
}

// gcmStream is one GCM message being sealed or opened.
type gcmStream struct {
	ctr     cipher.Stream
	hash    *ghash
	tagMask [gcmBlockSize]byte
	aadLen  uint64
	ctLen   uint64
	open    bool // opening: the hash covers the input, not the output
	scratch []byte
}

func newGCMStream(key, nonce, aad []byte, open bool) (*gcmStream, error) {
	if len(key) != 32 {
		return nil, errors.New("backup: an AES-256-GCM key is 32 bytes")
	}
	if len(nonce) != gcmNonceSize {
		return nil, errors.New("backup: the GCM nonce is 12 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var h [gcmBlockSize]byte
	block.Encrypt(h[:], h[:])
	var j0 [gcmBlockSize]byte
	copy(j0[:], nonce)
	j0[15] = 1
	s := &gcmStream{hash: newGHASH(h[:]), open: open}
	block.Encrypt(s.tagMask[:], j0[:])
	j0[15] = 2
	s.ctr = cipher.NewCTR(block, j0[:])
	s.hash.write(aad)
	s.hash.pad()
	s.aadLen = uint64(len(aad))
	return s, nil
}

// xor encrypts or decrypts src into dst (the same length), hashing the
// ciphertext.
func (s *gcmStream) xor(dst, src []byte) error {
	if (s.ctLen+uint64(len(src))+gcmBlockSize-1)/gcmBlockSize > maxMessageBlocks {
		return errGCMTooLong
	}
	if s.open {
		s.hash.write(src)
		s.ctr.XORKeyStream(dst, src)
	} else {
		s.ctr.XORKeyStream(dst, src)
		s.hash.write(dst)
	}
	s.ctLen += uint64(len(src))
	return nil
}

// tag ends the message and returns its authentication tag.
func (s *gcmStream) tag() [gcmTagSize]byte {
	s.hash.pad()
	s.hash.y.low ^= s.aadLen * 8
	s.hash.y.high ^= s.ctLen * 8
	s.hash.mul(&s.hash.y)
	var t [gcmTagSize]byte
	binary.BigEndian.PutUint64(t[:8], s.hash.y.low)
	binary.BigEndian.PutUint64(t[8:], s.hash.y.high)
	subtle.XORBytes(t[:], t[:], s.tagMask[:])
	return t
}

// verify compares the message's tag with the one received, in constant
// time.
func (s *gcmStream) verify(received []byte) bool {
	t := s.tag()
	return subtle.ConstantTimeCompare(t[:], received) == 1
}
