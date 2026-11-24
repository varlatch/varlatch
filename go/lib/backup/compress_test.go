// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/varlatch/varlatch/go/lib/envelope"
)

func passphrase(t *testing.T) BEK {
	t.Helper()
	b, err := PassphraseBEK([]byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeComponents writes a format-3 archive's two component files.
func writeComponents(t *testing.T, database, configuration []byte) (map[string]string, []string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{}
	var paths []string
	for i, data := range [][]byte{database, configuration} {
		name := FormatComponents[FormatGo][i]
		files[name] = filepath.Join(dir, name)
		if err := os.WriteFile(files[name], data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, files[name])
	}
	return files, paths
}

// What Seal writes is compressed, named so in the authenticated header, and
// opens to the same bytes: of nothing, of less than a frame states the size
// of, of what does not compress, and of what does.
func TestCompressed(t *testing.T) {
	random := make([]byte, 3<<20)
	rand.Read(random)
	text := bytes.Repeat([]byte("an event of an installation that has been used, "), 5<<20/48)
	for _, tc := range []struct {
		name                    string
		database, configuration []byte
		most                    int // the archive's bytes beside its manifest
	}{
		{"nothing", nil, nil, 200},
		{"one byte", nil, []byte("x"), 200},
		{"255 bytes", random[:250], []byte("12345"), 400},
		{"256 bytes", random[:250], []byte("123456"), 400},
		{"one block", text[:70_000], []byte("{}"), 2000},
		{"what does not compress", random, []byte("{}"), len(random) + 2000},
		{"what does", text, []byte("{}"), len(text) / 100},
		{"both", append(append([]byte(nil), random...), text...), text[:100_000], len(random) + len(text)/50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, paths := writeComponents(t, tc.database, tc.configuration)
			manifest := goManifest(t, envelope.GenerateKey(), files)
			out := filepath.Join(t.TempDir(), "a.vlt")
			paced := int64(0)
			if err := Seal(out, manifest, paths, passphrase(t), SealOptions{Pace: func(n int64) error { paced = n; return nil }}); err != nil {
				t.Fatal(err)
			}
			// The pace counts what was read, not what was written.
			if want := int64(4 + len(manifest) + len(tc.database) + len(tc.configuration)); paced != want {
				t.Errorf("paced to %d, want %d", paced, want)
			}
			raw, _ := os.ReadFile(out)
			if string(raw[:8]) != "VLTBAK02" || binary.BigEndian.Uint32(raw[36:]) != 1 {
				t.Fatalf("header %x", raw[:40])
			}
			if got := len(raw) - len(manifest); got > tc.most {
				t.Errorf("%d bytes beside the manifest, at most %d expected", got, tc.most)
			}
			scratch := t.TempDir()
			passes := int64(0)
			o, err := OpenWith(out, passphrase(t), scratch, OpenOptions{Pace: func(n int64) error { passes = n; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			if want := int64(len(raw)-40-16) + int64(len(tc.database)+len(tc.configuration)); passes != want {
				t.Errorf("opening paced to %d, want %d", passes, want)
			}
			if !bytes.Equal(o.ManifestJSON, manifest) {
				t.Errorf("manifest %s", o.ManifestJSON)
			}
			for i, want := range [][]byte{tc.database, tc.configuration} {
				if got, err := os.ReadFile(o.Path(FormatComponents[FormatGo][i])); err != nil || !bytes.Equal(got, want) {
					t.Errorf("component %d differs (%v)", i, err)
				}
			}
			if left, _ := filepath.Glob(filepath.Join(scratch, "*", "authenticated.pack")); len(left) != 0 {
				t.Errorf("left %v", left)
			}
		})
	}
}

// What a frame's header states of its size: nothing below 256 bytes, the
// size from there on (the format's contract; nothing smaller than a
// database is ever sealed). Reading holds either to the manifest's size.
func TestFrameSize(t *testing.T) {
	for size, states := range map[int]bool{0: false, 1: false, 255: false, 256: true, 257: true, 1 << 10: true, 1<<16 - 1: true, 1 << 16: true, 1<<16 + 255: true, 1<<16 + 256: true, 3 << 20: true} {
		var b bytes.Buffer
		z, err := newCompressor(&b, int64(size))
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, size)
		rand.Read(data)
		if _, err := z.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		var h zstd.Header
		if err := h.Decode(b.Bytes()); err != nil || !h.HasCheckSum || h.HasFCS != states || states && h.FrameContentSize != uint64(size) {
			t.Errorf("%d bytes: %+v %v", size, h, err)
		}
		no := func() error { return nil }
		if err := checkFrame(bytes.NewReader(b.Bytes()), int64(b.Len()), int64(size), no); err != nil {
			t.Errorf("%d bytes: %v", size, err)
		}
		// Told another size, the frame is refused where it states its own;
		// below, the read refuses it (the small archives after this).
		if err := checkFrame(bytes.NewReader(b.Bytes()), int64(b.Len()), int64(size)+1, no); (err == nil) != (size < 255) {
			t.Errorf("%d bytes, told one more: %v", size, err)
		}
	}
	// Small archives, whose frame states nothing: more or less than the
	// manifest declares is refused as it is read.
	files, _ := writeComponents(t, []byte("a database"), []byte("{}"))
	manifest := goManifest(t, envelope.GenerateKey(), files)
	for data, ok := range map[string]bool{"a database{}": true, "a database{}!": false, "a database{": false, "": false, "a databasE{}": false} {
		_, err := openRaw(t, sealRaw(t, header2(1), plaintext(manifest, frame(t, []byte(data), int64(len(data))))), &rawKeys)
		if (err == nil) != ok {
			t.Errorf("%q: %v", data, err)
		}
	}
}

// The scan of a frame's blocks can be stopped, and counts nothing.
func TestFrameScanStops(t *testing.T) {
	random := make([]byte, 40<<20)
	rand.Read(random)
	packed := frame(t, random, int64(len(random)))
	beats := 0
	if err := checkFrame(bytes.NewReader(packed), int64(len(packed)), int64(len(random)), func() error { beats++; return nil }); err != nil || beats != 2 {
		t.Fatalf("%d beats, %v", beats, err)
	}
	stop := errors.New("stopped")
	if err := checkFrame(bytes.NewReader(packed), int64(len(packed)), int64(len(random)), func() error { return stop }); err != stop {
		t.Fatal(err)
	}
}

// A configuration past the limit is neither sealed nor opened: not a byte
// of it is written.
func TestConfigurationBound(t *testing.T) {
	for size, ok := range map[int]bool{MaxConfigurationBytes: true, MaxConfigurationBytes + 1: false} {
		configuration := bytes.Repeat([]byte(" "), size)
		files, paths := writeComponents(t, []byte("a database"), configuration)
		manifest := goManifest(t, envelope.GenerateKey(), files)
		out := filepath.Join(t.TempDir(), "a.vlt")
		err := Seal(out, manifest, paths, passphrase(t), SealOptions{})
		if _, serr := os.Stat(out); (err == nil) != ok || (serr == nil) != ok {
			t.Errorf("%d bytes sealed: %v", size, err)
		}
		all := append([]byte("a database"), configuration...)
		_, err = openRaw(t, sealRaw(t, header2(1), plaintext(manifest, frame(t, all, int64(len(all))))), &rawKeys)
		if (err == nil) != ok || !ok && !strings.Contains(err.Error(), "larger than 1 MiB") {
			t.Errorf("%d bytes opened: %v", size, err)
		}
	}
}

// failAfter fails every write past n bytes.
type failAfter struct {
	w io.Writer
	n int
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n -= len(p); f.n < 0 {
		return 0, errors.New("the disk is full")
	}
	return f.w.Write(p)
}

// A write that fails, the last block's while the compressor closes
// included, leaves neither an archive nor a partial file.
func TestSealWriteFails(t *testing.T) {
	random := make([]byte, 300_000)
	rand.Read(random)
	files, paths := writeComponents(t, random, []byte("{}"))
	manifest := goManifest(t, envelope.GenerateKey(), files)
	defer func() { testHooks.out = nil }()
	whole := &failAfter{n: 1 << 30}
	testHooks.out = func(w io.Writer) io.Writer { whole.w = w; return whole }
	dir := t.TempDir()
	if err := Seal(filepath.Join(dir, "whole"), manifest, paths, passphrase(t), SealOptions{}); err != nil {
		t.Fatal(err)
	}
	written := 1<<30 - whole.n
	for name, n := range map[string]int{"the manifest": 10, "a block": written / 2, "the last block, as the compressor closes": written - 1, "the frame's end": written - 4} {
		testHooks.out = func(w io.Writer) io.Writer { return &failAfter{w, n} }
		d := t.TempDir()
		if err := Seal(filepath.Join(d, "a"), manifest, paths, passphrase(t), SealOptions{}); err == nil || !strings.Contains(err.Error(), "the disk is full") {
			t.Errorf("%s: %v", name, err)
		}
		if left, _ := os.ReadDir(d); len(left) != 0 {
			t.Errorf("%s: left %v", name, left)
		}
	}
}

// A format-3 archive that is not compressed, as rc.1 to rc.3 sealed them,
// opens as before; it is the archive those releases open.
func TestUncompressedOpens(t *testing.T) {
	files, paths := writeComponents(t, bytes.Repeat([]byte("row "), 1<<18), []byte("{}"))
	manifest := goManifest(t, envelope.GenerateKey(), files)
	out := filepath.Join(t.TempDir(), "a.vlt")
	if err := Seal(out, manifest, paths, passphrase(t), SealOptions{Uncompressed: true}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	if string(raw[:8]) != "VLTBAK01" || len(raw) != 36+4+len(manifest)+(1<<20)+2+16 {
		t.Fatalf("%q, %d bytes", raw[:8], len(raw))
	}
	o, err := Open(out, passphrase(t), t.TempDir())
	if err != nil || !bytes.Equal(o.ManifestJSON, manifest) {
		t.Fatal(err)
	}
	_ = o.Close()
}

// sealRaw is an archive of any header and plaintext, its tag right.
func sealRaw(t *testing.T, header, plaintext []byte) []byte {
	t.Helper()
	key, err := rawKeys.derive(passphrase(t), header[8:24])
	if err != nil {
		t.Fatal(err)
	}
	s, err := newGCMStream(key, header[24:36], header, false)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(plaintext))
	if err := s.xor(body, plaintext); err != nil {
		t.Fatal(err)
	}
	tag := s.tag()
	return append(append(bytes.Clone(header), body...), tag[:]...)
}

// rawKeys keeps the key of header2's one salt: a derivation is slow.
var rawKeys KeyCache

func header2(compression uint32) []byte {
	h := make([]byte, 36)
	rand.Read(h[24:])
	copy(h, "VLTBAK02a salt: 16 bytes")
	return binary.BigEndian.AppendUint32(h, compression)
}

func plaintext(manifest, rest []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(manifest)))
	return append(append(b, manifest...), rest...)
}

// frame is data as one zstd frame of the size given (no size: -1).
func frame(t *testing.T, data []byte, size int64, o ...zstd.EOption) []byte {
	t.Helper()
	var b bytes.Buffer
	enc, err := zstd.NewWriter(nil, append([]zstd.EOption{zstd.WithEncoderConcurrency(1), zstd.WithZeroFrames(true)}, o...)...)
	if err != nil {
		t.Fatal(err)
	}
	enc.ResetContentSize(&b, size)
	if _, err := enc.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Under a right tag (the key's holder made it, or a fault did), a
// compressed archive is refused unless it is what Seal writes: nothing is
// left in scratch, and never more is written there than is declared.
func TestCompressedRefuses(t *testing.T) {
	database := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	configuration := []byte(`{"formatVersion":1}`)
	files, _ := writeComponents(t, database, configuration)
	manifest := goManifest(t, envelope.GenerateKey(), files)
	all := append(bytes.Clone(database), configuration...)
	size := int64(len(all))
	good := frame(t, all, size)
	if _, err := openRaw(t, sealRaw(t, header2(1), plaintext(manifest, good)), &rawKeys); err != nil {
		t.Fatalf("the control: %v", err)
	}
	with := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(manifest, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	component := func(m map[string]any, i int) map[string]any { return m["components"].([]any)[i].(map[string]any) }
	sized := func(i int, n int64) []byte { return with(func(m map[string]any) { component(m, i)["bytes"] = n }) }

	// The frame's size field, four bytes after its magic, its descriptor and
	// its window, set to another size: a frame that gives more than it says.
	lies := bytes.Clone(frame(t, append(bytes.Clone(all), make([]byte, 4<<20)...), size+4<<20))
	binary.LittleEndian.PutUint32(lies[6:], uint32(size))
	shorter := bytes.Clone(frame(t, all[:size-100], size-100))
	binary.LittleEndian.PutUint32(shorter[6:], uint32(size))
	random := make([]byte, 20<<20)
	rand.Read(random)
	wide := with(func(m map[string]any) {
		sum := sha256.Sum256(random[:len(random)-len(configuration)])
		component(m, 0)["bytes"], component(m, 0)["sha256"] = len(random)-len(configuration), hex.EncodeToString(sum[:])
		sum = sha256.Sum256(random[len(random)-len(configuration):])
		component(m, 1)["sha256"] = hex.EncodeToString(sum[:])
	})
	dictionary, err := (&zstd.Header{WindowSize: 1 << 20, DictionaryID: 7, HasFCS: true, FrameContentSize: uint64(size), HasCheckSum: true}).AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	var h zstd.Header
	if err := h.Decode(good); err != nil || !h.HasFCS || !h.HasCheckSum || h.SingleSegment || h.HeaderSize != 10 {
		t.Fatalf("the frame's header is not as the cases below take it: %+v %v", h, err)
	}
	blocks := good[h.HeaderSize:]
	flipped := func(i int) []byte { return flip(good, i) }
	last := good[:len(good)-4]

	for name, tc := range map[string]struct {
		manifest, rest []byte
		want           error
	}{
		"no frame":                    {manifest, nil, errCompressed},
		"not compressed":              {manifest, all, errCompressed},
		"a frame of nothing":          {manifest, frame(t, nil, 0), errCompressed},
		"one component too few":       {manifest, frame(t, database, int64(len(database))), errCompressed},
		"a byte more":                 {manifest, frame(t, append(bytes.Clone(all), 0), size+1), errCompressed},
		"no size stated":              {manifest, frame(t, all, -1), errCompressed},
		"no checksum":                 {manifest, frame(t, all, size, zstd.WithEncoderCRC(false)), errCompressed},
		"a dictionary":                {manifest, append(dictionary, blocks...), errCompressed},
		"a window past the limit":     {wide, frame(t, random, int64(len(random)), zstd.WithWindowSize(16<<20)), errCompressed},
		"a byte after the frame":      {manifest, append(bytes.Clone(good), 0), errCompressed},
		"an empty block":              {manifest, append(append(bytes.Clone(good[:h.HeaderSize]), 0, 0, 0), blocks...), errCompressed},
		"a reserved block":            {manifest, append(append(bytes.Clone(good[:h.HeaderSize]), 7|1<<3, 0, 0, 0), good[len(good)-4:]...), errCompressed},
		"a skippable frame after":     {manifest, append(bytes.Clone(good), 0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0), errCompressed},
		"a skippable frame first":     {manifest, append([]byte{0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0}, good...), errCompressed},
		"a second frame":              {manifest, append(bytes.Clone(good), frame(t, nil, 0)...), errCompressed},
		"two frames":                  {manifest, append(frame(t, database, int64(len(database))), frame(t, configuration, int64(len(configuration)))...), errCompressed},
		"cut short by a byte":         {manifest, good[:len(good)-1], errCompressed},
		"cut short by its checksum":   {manifest, last, errCompressed},
		"cut short in a block":        {manifest, good[:len(good)/2], errCompressed},
		"cut short in its header":     {manifest, good[:6], errCompressed},
		"its magic":                   {manifest, flipped(0), errCompressed},
		"its checksum wrong":          {manifest, flipped(len(good) - 1), errCompressed},
		"its size wrong":              {manifest, flipped(6), errCompressed},
		"more than it states":         {manifest, lies, errCompressed},
		"less than it states":         {manifest, shorter, errCompressed},
		"the manifest's size smaller": {sized(0, int64(len(database))-1), good, errCompressed},
		"the manifest's size larger":  {sized(0, int64(len(database))+1), good, errCompressed},
		"the manifest's size vast":    {sized(0, 1<<53-1), good, &Error{"Component sizes do not match archive"}},
		"a component's checksum": {with(func(m map[string]any) { component(m, 0)["sha256"] = strings.Repeat("0", 64) }), good,
			&Error{"Component checksum mismatch"}},
		"the bytes between the two": {with(func(m map[string]any) {
			component(m, 0)["bytes"], component(m, 1)["bytes"] = len(database)-1, len(configuration)+1
		}), good, &Error{"Component checksum mismatch"}},
	} {
		_, err := openRaw(t, sealRaw(t, header2(1), plaintext(tc.manifest, tc.rest)), &rawKeys)
		var want *Error
		if errors.As(tc.want, &want); err == nil || !errors.Is(err, tc.want) && err.Error() != want.msg {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// A TypeScript manifest is never compressed.
	ts := readVectors(t).Archives[0]
	dump, _ := base64Std(ts.Components["secret-plane.dump"])
	if _, err := openRaw(t, sealRaw(t, header2(1), plaintext(ts.Manifest, frame(t, dump, int64(len(dump))))), &rawKeys); err != ErrFormat {
		t.Errorf("a format-2 manifest, compressed: %v", err)
	}
}

// openRaw opens an archive's bytes. While it does, scratch never holds more
// than the archive and what its manifest declares (a bomb), seen at each
// step of the pace; a refusal leaves scratch empty.
func openRaw(t *testing.T, raw []byte, keys *KeyCache) (*Opened, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.vlt")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	most := int64(len(raw)) + 1<<20 + 100 // the cases' database and configuration
	o, err := OpenWith(p, passphrase(t), scratch, OpenOptions{Keys: keys, Pace: func(int64) error {
		var held int64
		_ = filepath.WalkDir(scratch, func(p string, d fs.DirEntry, err error) error {
			if info, ierr := d.Info(); err == nil && ierr == nil && info.Mode().IsRegular() {
				held += info.Size()
			}
			return nil
		})
		if held > most {
			t.Errorf("scratch held %d bytes of an archive of %d", held, len(raw))
		}
		return nil
	}})
	if left, _ := os.ReadDir(scratch); err != nil && len(left) != 0 {
		t.Errorf("a refusal left %d entries in scratch", len(left))
	}
	return o, err
}

// What the header says is refused before any key work: the magic, then the
// compression. A compression this release reads, put in another's place, is
// the authenticated header changed.
func TestHeaderRefusedFirst(t *testing.T) {
	files, paths := writeComponents(t, []byte("a database"), []byte("{}"))
	out := filepath.Join(t.TempDir(), "a.vlt")
	if err := Seal(out, goManifest(t, envelope.GenerateKey(), files), paths, passphrase(t), SealOptions{}); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(out)
	at := func(i int, b ...byte) []byte {
		c := bytes.Clone(good)
		copy(c[i:], b)
		return c
	}
	for name, tc := range map[string]struct {
		raw     []byte
		want    error
		derives int64
	}{
		"a later container":        {at(0, []byte("VLTBAK03")...), ErrFormat, 0},
		"no compression":           {at(36, 0, 0, 0, 0), ErrCompression, 0},
		"a later compression":      {at(36, 0, 0, 0, 2), ErrCompression, 0},
		"every byte of the number": {at(36, 1), ErrCompression, 0},
		"as the older container":   {at(0, []byte("VLTBAK01")...), ErrIntegrity, 1},
		"cut short in the header":  {good[:59], ErrSize, 0},
		"a longer file":            {append(bytes.Clone(good), 0), ErrIntegrity, 1},
		"a truncation":             {good[:len(good)-1], ErrIntegrity, 1},
		"the body":                 {flip(good, 50), ErrIntegrity, 1},
	} {
		before := Derivations()
		if _, err := openRaw(t, tc.raw, nil); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		if n := Derivations() - before; n != tc.derives {
			t.Errorf("%s: %d keys derived, want %d", name, n, tc.derives)
		}
	}
	// The other way: an older archive as the new container.
	if err := Seal(out+"1", goManifest(t, envelope.GenerateKey(), files), paths, passphrase(t), SealOptions{Uncompressed: true}); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(out + "1")
	copy(old, "VLTBAK02")
	copy(old[36:], []byte{0, 0, 0, 1})
	if _, err := openRaw(t, old, nil); err != ErrIntegrity {
		t.Errorf("an older archive under the new magic: %v", err)
	}
}

// An archive rc.3's own code sealed (testdata/rc3-archive.json): not compressed.
func TestRC3Archive(t *testing.T) {
	var v struct {
		Archive, Passphrase string
		Components          map[string]string
	}
	raw, err := os.ReadFile("testdata/rc3-archive.json")
	if err != nil || json.Unmarshal(raw, &v) != nil {
		t.Fatal(err)
	}
	archive, err := base64Std(v.Archive)
	if err != nil || string(archive[:8]) != "VLTBAK01" {
		t.Fatalf("%v", err)
	}
	bek, _ := PassphraseBEK([]byte(v.Passphrase))
	p := filepath.Join(t.TempDir(), "a.vlt")
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := Open(p, bek, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if r, err := o.Manifest.GoRelease(); err != nil || r.Version != "0.50.0-rc.3" {
		t.Fatalf("%+v %v", r, err)
	}
	for name, want := range v.Components {
		if got, err := os.ReadFile(o.Path(name)); err != nil || string(got) != want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

// A database past 4 GiB: no length is of 32 bits. Off by default (it writes
// and hashes 5 GiB three times): VARLATCH_BIG_ARCHIVE names a directory.
func TestBigArchive(t *testing.T) {
	base := os.Getenv("VARLATCH_BIG_ARCHIVE")
	if base == "" {
		t.Skip("VARLATCH_BIG_ARCHIVE is not set")
	}
	dir, err := os.MkdirTemp(base, "varlatch-big-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	const size = 5<<30 + 12345
	files, paths := writeComponents(t, nil, []byte("{}"))
	database := filepath.Join(dir, ComponentDatabase)
	f, err := os.Create(database)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse but for its ends, so that a length cut to 32 bits shows.
	if _, err := f.WriteAt([]byte("first"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("last"), size-4); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	files[ComponentDatabase], paths[0] = database, database
	manifest := goManifest(t, envelope.GenerateKey(), files)
	out := filepath.Join(dir, "a.vlt")
	start := time.Now()
	if err := Seal(out, manifest, paths, passphrase(t), SealOptions{}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(out)
	t.Logf("sealed in %v: %d bytes", time.Since(start).Round(time.Second), st.Size())
	start = time.Now()
	o, err := Open(out, passphrase(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("opened in %v", time.Since(start).Round(time.Second))
	defer o.Close()
	got, err := os.Open(o.Path(ComponentDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	end := make([]byte, 4)
	if st, _ := got.Stat(); st.Size() != size {
		t.Fatalf("%d bytes", st.Size())
	}
	if _, err := got.ReadAt(end, size-4); err != nil && err != io.EOF || string(end) != "last" {
		t.Fatalf("%q %v", end, err)
	}
}

func base64Std(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
