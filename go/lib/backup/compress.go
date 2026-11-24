// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bufio"
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
	// minContentSize is the size from which a frame always states its own
	// (zstd's field for a smaller one exists in some frames only).
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

// decompressor reads a frame checkFrame accepted. What zstd refuses in it is
// errCompressed; an error of its input's own (a read's, the beat's) stays
// that error. The beat is called at each read of the input, so that a stop
// ends it however little comes out.
type decompressor struct {
	z  *zstd.Decoder
	in *beating
}

func newDecompressor(r io.Reader, beat func() error) (*decompressor, error) {
	in := &beating{r: r, beat: beat}
	z, err := zstd.NewReader(in, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(maxWindow))
	return &decompressor{z, in}, err
}

func (d *decompressor) Read(p []byte) (int, error) {
	n, err := d.z.Read(p)
	if err != nil && err != io.EOF {
		if d.in.err != nil {
			return n, d.in.err
		}
		err = fmt.Errorf("%w: %w", errCompressed, err)
	}
	return n, err
}

// beating is a reader that calls beat before each read, and keeps its error.
type beating struct {
	r    io.Reader
	beat func() error
	err  error
}

func (b *beating) Read(p []byte) (int, error) {
	if b.err == nil {
		b.err = b.beat()
	}
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// beatBytes is how far checkFrame reads between two beats.
const beatBytes = 16 << 20

// checkFrame holds the size bytes of r to what newCompressor writes for
// content bytes, without decompressing them: one frame, with no dictionary
// and a window of at most maxWindow, that states content as its size (a
// frame of fewer than minContentSize bytes may state none), and ends where
// r does. Decompressing it then gives no other number of bytes (zstd holds
// a frame to the size it states; the reader, to the manifest's). beat is
// called now and then; an error from it ends the check.
func checkFrame(r io.Reader, size, content int64, beat func() error) error {
	in := bufio.NewReaderSize(io.LimitReader(r, size), 1<<16)
	head, err := in.Peek(int(min(size, zstd.HeaderMaxSize)))
	if err != nil && err != io.EOF {
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
	// skip is n bytes of the frame, which must be there.
	var at, beaten int64
	skip := func(n int) error {
		k, err := in.Discard(n)
		if at += int64(k); err == io.EOF || err == nil && at > size {
			return errCompressed
		}
		return err
	}
	if err := skip(h.HeaderSize); err != nil {
		return err
	}
	// The blocks: three bytes of header each, then what the header says.
	for last := false; !last; {
		b, err := in.Peek(3)
		if err == io.EOF {
			return errCompressed
		}
		if err != nil {
			return err
		}
		v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		last = v&1 != 0
		length, kind := int(v>>3), v>>1&3
		// A block of nothing (only the last, and stored), and one of a kind
		// zstd has none of.
		if length == 0 && (!last || kind != 0) || kind == 3 {
			return errCompressed
		}
		if kind == 1 { // one byte, repeated length times
			length = 1
		}
		if err := skip(3 + length); err != nil {
			return err
		}
		if at-beaten >= beatBytes {
			beaten = at
			if err := beat(); err != nil {
				return err
			}
		}
	}
	const checksum = 4
	if err := skip(checksum); err != nil {
		return err
	}
	if at != size {
		return errCompressed
	}
	return nil
}
