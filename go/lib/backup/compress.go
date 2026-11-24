// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// An archive's compression (a VLTBAK02 header names it): one zstd frame
// holds the components, one after the other, and nothing follows it. The
// frame is read only after the whole archive is authenticated, and is held
// to what the manifest declares before a byte of it is decompressed.

// compressionZstd is the one compression this release reads and writes.
const compressionZstd = 1

const (
	// zstdWindow is the window an archive is written with. Measured on a
	// database of 568 MB, most of it an audit history: 31 MB at 1 MiB and at
	// 8 MiB, at 230 and 71 MB/s of a CPU; a higher level was no smaller.
	zstdWindow = 1 << 20
	// maxWindow is the largest window read: what decompressing costs in
	// memory.
	maxWindow = 8 << 20
	// minContentSize is the smallest size a frame's header states: zstd has
	// no field for a smaller one.
	minContentSize = 256
)

var (
	// ErrCompression is an archive of a compression this release does not
	// read (a later release's).
	ErrCompression = &Error{"This release does not read the archive's compression"}
	// errCompressed is an authenticated archive whose compressed components
	// are not one frame of the manifest's size.
	errCompressed = &Error{"The archive's compressed components are not what its manifest declares"}
)

// newCompressor compresses what is written to it, size bytes, as one frame
// on w. One goroutine's work at a time, a window's memory.
func newCompressor(w io.Writer, size int64) (*zstd.Encoder, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(zstdWindow),
		zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true), zstd.WithZeroFrames(true))
	if err != nil {
		return nil, err
	}
	enc.ResetContentSize(w, size)
	return enc, nil
}

// decompressor reads a frame checkFrame accepted; what zstd refuses in it
// is errCompressed.
type decompressor struct{ z *zstd.Decoder }

func newDecompressor(r io.Reader) (decompressor, error) {
	z, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(maxWindow))
	return decompressor{z}, err
}

func (d decompressor) Read(p []byte) (int, error) {
	n, err := d.z.Read(p)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("%w: %w", errCompressed, err)
	}
	return n, err
}

// checkFrame holds the size bytes of r to what newCompressor writes for
// content bytes, without decompressing them: one frame, with no dictionary
// and a window of at most maxWindow, that states content as its size, and
// ends where r does. Decompressing it then gives no other number of bytes
// (zstd holds a frame to the size it states).
func checkFrame(r io.ReaderAt, size, content int64) error {
	head := make([]byte, min(size, zstd.HeaderMaxSize))
	if _, err := r.ReadAt(head, 0); err != nil && err != io.EOF {
		return err
	}
	var h zstd.Header
	if h.Decode(head) != nil || h.Skippable || h.DictionaryID != 0 || !h.HasCheckSum || h.WindowSize > maxWindow ||
		h.SingleSegment && h.FrameContentSize > maxWindow {
		return errCompressed
	}
	if h.HasFCS && h.FrameContentSize != uint64(content) || !h.HasFCS && content >= minContentSize {
		return errCompressed
	}
	// The blocks: three bytes of header each, of the block's length.
	const checksum = 4
	at := int64(h.HeaderSize)
	for last := false; !last; {
		var b [4]byte
		if n, _ := r.ReadAt(b[:3], at); n < 3 || at+3 > size {
			return errCompressed
		}
		v := binary.LittleEndian.Uint32(b[:])
		last = v&1 != 0
		length := int64(v >> 3)
		if v>>1&3 == 1 { // one byte, repeated
			length = 1
		}
		if at += 3 + length; at > size {
			return errCompressed
		}
	}
	if at+checksum != size {
		return errCompressed
	}
	return nil
}
