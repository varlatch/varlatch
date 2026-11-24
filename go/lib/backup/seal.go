// SPDX-License-Identifier: Apache-2.0

// Package backup is the installation archive (ADR-0033 as ADR-0036 and
// ADR-0059 Decision 7 amend it): sealing and opening an archive with the
// Backup Encryption Key, its manifest, and the checks restoring one needs.
// It is varlatchd's and, in steps 5 and 6, the CLI's `admin backup`
// (Apache-2.0: it never imports go/server).
//
// The seal is packages/backup archive.ts's, byte for byte, so archives
// cross between the servers in both directions:
//
//	header    "VLTBAK01" || salt (16 bytes) || nonce (12 bytes)
//	body      AES-256-GCM of: uint32 big-endian manifest length ||
//	          manifest JSON || each component, in the manifest's order;
//	          the header is the additional data
//	tag       the GCM tag (16 bytes)
//
// The key is scrypt(BEK, salt, N=32768, r=8, p=1, 32 bytes), for a key
// file (32 bytes) and a passphrase (at least 12 bytes) alike. An archive is
// at most 60 GiB, below one GCM message's limit.
package backup

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/scrypt"

	"github.com/varlatch/varlatch/go/lib/preread"
)

const (
	headerBytes = 36
	// MaxBytes bounds an archive's plaintext (packages/backup MAX_BYTES).
	MaxBytes = 60 << 30
	// MaxManifestBytes bounds the manifest.
	MaxManifestBytes = 1 << 20
	chunk            = 1 << 20
)

var magic = []byte("VLTBAK01")

// Error is a refusal with the TypeScript server's message (BackupError).
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

var (
	// ErrIntegrity is a wrong BEK, a changed byte or a truncation: the GCM
	// tag does not match.
	ErrIntegrity = &Error{"Archive integrity check failed (wrong BEK, corruption, or truncation)"}
	ErrSize      = &Error{"Invalid archive size"}
	ErrFormat    = &Error{"Unsupported archive format"}
)

// BEK is the Backup Encryption Key: a 32-byte key, or a passphrase.
type BEK struct {
	passphrase bool
	material   []byte
}

// KeyBEK is a BEK from a key file's 32 bytes (ParseKey reads one).
func KeyBEK(key []byte) (BEK, error) {
	if len(key) != 32 {
		return BEK{}, &Error{"BEK key file must contain a 32-byte key"}
	}
	return BEK{material: bytes.Clone(key)}, nil
}

// PassphraseBEK is a BEK from a passphrase of at least 12 bytes.
func PassphraseBEK(passphrase []byte) (BEK, error) {
	if len(passphrase) < 12 {
		return BEK{}, &Error{"BEK passphrase must have at least 12 bytes"}
	}
	return BEK{passphrase: true, material: bytes.Clone(passphrase)}, nil
}

// Clear overwrites the BEK's material.
func (b BEK) Clear() { clear(b.material) }

// derivations counts the archive keys derived (scrypt), for tests and
// diagnostics (Derivations).
var derivations atomic.Int64

// Derivations is how many archive keys this process has derived: each is
// scrypt with N = 32768, r = 8 (32 MiB, about 0.2 s of a CPU).
func Derivations() int64 { return derivations.Load() }

func (b BEK) derive(salt []byte) ([]byte, error) {
	if len(b.material) == 0 {
		return nil, &Error{"No Backup Encryption Key"}
	}
	derivations.Add(1)
	return scrypt.Key(b.material, salt, 32768, 8, 1, 32)
}

// KeyCache holds the key derived for one archive's salt and one BEK, so a
// backup that seals an archive and then checks it derives the key once
// (ADR-0059 Decision 7: the backup's CPU). Seal and OpenWith use it through
// their options. A hit needs both the salt and the BEK: the cache keeps an
// HMAC of the BEK under a random key of its own (never the BEK itself) and
// compares it in constant time, so another BEK, an empty one or a cleared
// one always takes the full derivation and fails as it would without the
// cache. A miss derives again and replaces the entry. Clear zeroes it: call
// it when the run that owns the cache ends. The archive format is
// unchanged: only how often the same key is derived.
type KeyCache struct {
	mu   sync.Mutex
	mac  []byte // the cache's own HMAC key, random, made on first use
	salt []byte
	bek  []byte // HMAC-SHA256(mac, the BEK's kind and material)
	key  []byte
}

// bekTag is the HMAC of b's kind and material under the cache's key.
func (c *KeyCache) bekTag(b BEK) []byte {
	if c.mac == nil {
		c.mac = make([]byte, 32)
		_, _ = rand.Read(c.mac)
	}
	h := hmac.New(sha256.New, c.mac)
	if b.passphrase {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	h.Write(b.material)
	return h.Sum(nil)
}

// derive is the archive key for salt and b, from the cache when it holds
// that pair's, else derived (and kept); a nil cache derives. The caller
// clears the copy it gets.
func (c *KeyCache) derive(b BEK, salt []byte) ([]byte, error) {
	if c == nil || len(b.material) == 0 {
		return b.derive(salt)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tag := c.bekTag(b)
	if c.key == nil || !bytes.Equal(c.salt, salt) || subtle.ConstantTimeCompare(c.bek, tag) != 1 {
		key, err := b.derive(salt)
		if err != nil {
			return nil, err
		}
		clear(c.key)
		c.salt, c.bek, c.key = bytes.Clone(salt), tag, key
	}
	return bytes.Clone(c.key), nil
}

// Clear zeroes the cached key, its HMAC key and the BEK's tag, and forgets
// them.
func (c *KeyCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.key)
	clear(c.mac)
	clear(c.bek)
	c.mac, c.salt, c.bek, c.key = nil, nil, nil, nil
}

var keyPattern = regexp.MustCompile(`^(?:[a-fA-F0-9]{64}|[A-Za-z0-9+/]{43}=)$`)

// ParseKey reads a key file: 32 bytes as hex or base64, surrounding
// whitespace ignored.
func ParseKey(raw string) ([]byte, error) {
	v := strings.TrimSpace(raw)
	if !keyPattern.MatchString(v) {
		return nil, &Error{"Key file must contain a 32-byte hex or base64 key"}
	}
	if len(v) == 64 {
		return hex.DecodeString(v)
	}
	return base64.StdEncoding.DecodeString(v)
}

// DistinctKeys refuses a BEK that is one of keys (a Root KEK), raw, or as
// its hex or base64 text: the two are held apart (ADR-0033 Decision 2).
func DistinctKeys(bek BEK, keys ...[]byte) error {
	text := strings.TrimSpace(string(bek.material))
	for _, k := range keys {
		if bytes.Equal(bek.material, k) || text == hex.EncodeToString(k) || text == base64.StdEncoding.EncodeToString(k) {
			return &Error{"The Backup Encryption Key must be independent of the Root KEK"}
		}
	}
	return nil
}

// SealOptions tune Seal.
type SealOptions struct {
	// Pace, when set, is called after each sealed chunk (about 1 MiB) with
	// the plaintext bytes sealed so far; sealing waits for it (ADR-0059
	// Decision 7's paced sealing). An error from it ends the sealing: Seal
	// returns it, and no archive is written.
	Pace func(sealed int64) error
	// Keys, when set, keeps the archive key, so a check of the same
	// archive with the same cache (OpenOptions.Keys) does not derive it
	// again.
	Keys *KeyCache
}

// LinkedError is a sealed archive in place whose directory could not be
// synced afterwards: the archive exists, but may not survive a crash yet.
type LinkedError struct {
	Path string
	Err  error
}

func (e *LinkedError) Error() string {
	return fmt.Sprintf("the archive %s was written, but its directory could not be synced (it may not survive a crash yet): %v", e.Path, e.Err)
}

func (e *LinkedError) Unwrap() error { return e.Err }

// Seal writes an archive to output: the manifest, which must be valid
// (ParseManifest), and the component files, one per component in the
// manifest's order, each named and sized as the manifest says. The
// archive is written to a temporary file beside output (mode 0600) and
// linked into place, so output never holds a partial archive and an
// existing one is never replaced. A *LinkedError says the archive is in
// place but its directory was not synced.
func Seal(output string, manifest []byte, components []string, bek BEK, o SealOptions) (err error) {
	if len(manifest) > MaxManifestBytes {
		return &Error{"Archive exceeds the v1 60 GiB size limit"}
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return err
	}
	if len(components) != len(m.Components) {
		return &Error{"The component files are not the manifest's components"}
	}
	total := int64(len(manifest) + 4)
	files := make([]*os.File, 0, len(components))
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, path := range components {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		files = append(files, f)
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if c := m.Components[len(files)-1]; filepath.Base(path) != c.Name || st.Size() != c.Bytes {
			return &Error{fmt.Sprintf("The component file %s is not the manifest's %s of %d bytes", filepath.Base(path), c.Name, c.Bytes)}
		}
		total += st.Size()
	}
	if total > MaxBytes {
		return &Error{"Archive exceeds the v1 60 GiB size limit"}
	}
	header := make([]byte, headerBytes)
	copy(header, magic)
	if _, err := rand.Read(header[8:]); err != nil {
		return err
	}
	key, err := o.Keys.derive(bek, header[8:24])
	if err != nil {
		return err
	}
	s, err := newGCMStream(key, header[24:], header, false)
	clear(key)
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	partial := fmt.Sprintf("%s.%x.partial", output, suffix)
	out, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
		_ = os.Remove(partial)
	}()
	if _, err := out.Write(header); err != nil {
		return err
	}
	var sealed int64
	buf := make([]byte, chunk)
	write := func(p []byte) error {
		if err := s.xor(p, p); err != nil {
			return err
		}
		if _, err := out.Write(p); err != nil {
			return err
		}
		sealed += int64(len(p))
		if o.Pace != nil {
			return o.Pace(sealed)
		}
		return nil
	}
	head := make([]byte, 4, 4+len(manifest))
	binary.BigEndian.PutUint32(head, uint32(len(manifest)))
	if err := write(append(head, manifest...)); err != nil {
		return err
	}
	for _, f := range files {
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				if err := write(buf[:n]); err != nil {
					return err
				}
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
	}
	if sealed != total {
		return &Error{"A component changed size while it was sealed"}
	}
	tag := s.tag()
	if _, err := out.Write(tag[:]); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Never overwrite an existing archive.
	if err := os.Link(partial, output); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(output)); err != nil {
		return &LinkedError{Path: output, Err: err}
	}
	return nil
}

// SyncDir syncs a directory, so a file linked or renamed into it survives a
// crash. It is the one directory sync; on Windows it does nothing
// (syncdir_windows.go).
func SyncDir(dir string) error { return syncDir(dir) }

// Opened is an archive authenticated and unpacked into a scratch
// directory: its manifest, and each component as a file, every one checked
// against the manifest.
type Opened struct {
	Manifest Manifest
	// ManifestJSON is the manifest as the archive holds it.
	ManifestJSON []byte
	dir          string
}

// Path is the unpacked file of a component.
func (o *Opened) Path(name string) string { return filepath.Join(o.dir, name) }

// Close removes the unpacked files.
func (o *Opened) Close() error { return os.RemoveAll(o.dir) }

// Open authenticates the whole archive before interpreting any of it: the
// plaintext goes to a file in a new directory under scratch, the GCM tag
// is checked, and only then are the manifest parsed and the components
// split out, each checked against its size and SHA-256.
func Open(path string, bek BEK, scratch string) (*Opened, error) {
	return OpenWith(path, bek, scratch, OpenOptions{})
}

// OpenOptions tune OpenWith.
type OpenOptions struct {
	// Keys, when set, gives the archive key a Seal with the same cache
	// derived (the backup's own check), and keeps one it derives.
	Keys *KeyCache
	// Pace, when set, is called after each chunk (about 1 MiB) of either
	// pass, the decryption and the components' SHA-256, with the bytes of
	// both passes so far; opening waits for it, as Seal waits for
	// SealOptions.Pace. An error from it ends the opening: OpenWith
	// returns it. It changes only the timing: every check is made.
	Pace func(done int64) error
}

// OpenWith is Open with options.
func OpenWith(path string, bek BEK, scratch string, o OpenOptions) (_ *Opened, err error) {
	f, err := preread.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size < headerBytes+20 || size > MaxBytes+headerBytes+16 {
		return nil, ErrSize
	}
	header := make([]byte, headerBytes)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:8], magic) {
		return nil, ErrFormat
	}
	tag := make([]byte, gcmTagSize)
	if _, err := f.ReadAt(tag, size-gcmTagSize); err != nil {
		return nil, err
	}
	key, err := o.Keys.derive(bek, header[8:24])
	if err != nil {
		return nil, err
	}
	s, err := newGCMStream(key, header[24:], header, true)
	clear(key)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(scratch, "varlatch-backup-")
	if err != nil {
		return nil, err
	}
	// The decrypted files are removed on any way out (an error, a panic)
	// until the caller owns them through the Opened returned.
	owned := false
	defer func() {
		if !owned {
			_ = os.RemoveAll(dir)
		}
	}()
	plainPath := filepath.Join(dir, "authenticated.pack")
	plain, err := os.OpenFile(plainPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer plain.Close()
	body := io.NewSectionReader(f, headerBytes, size-headerBytes-gcmTagSize)
	buf := make([]byte, chunk)
	var done int64
	pace := func(n int) error {
		done += int64(n)
		if o.Pace != nil {
			return o.Pace(done)
		}
		return nil
	}
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if err := s.xor(buf[:n], buf[:n]); err != nil {
				return nil, ErrIntegrity
			}
			if _, err := plain.Write(buf[:n]); err != nil {
				return nil, err
			}
			if err := pace(n); err != nil {
				return nil, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	if !s.verify(tag) {
		return nil, ErrIntegrity
	}
	plainSize := size - headerBytes - gcmTagSize
	head := make([]byte, 4)
	if _, err := plain.ReadAt(head, 0); err != nil {
		return nil, &Error{"Invalid manifest size"}
	}
	n := int64(binary.BigEndian.Uint32(head))
	if n < 2 || n > MaxManifestBytes {
		return nil, &Error{"Invalid manifest size"}
	}
	raw := make([]byte, n)
	if got, _ := plain.ReadAt(raw, 4); int64(got) != n {
		return nil, &Error{"Truncated manifest"}
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	offset := 4 + n
	sum := offset
	for _, c := range m.Components {
		sum += c.Bytes
	}
	if sum != plainSize {
		return nil, &Error{"Component sizes do not match archive"}
	}
	for _, c := range m.Components {
		out, err := os.OpenFile(filepath.Join(dir, c.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, cerr := copyPaced(io.MultiWriter(out, h), io.NewSectionReader(plain, offset, c.Bytes), buf, pace)
		if err := out.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return nil, cerr
		}
		if hex.EncodeToString(h.Sum(nil)) != c.SHA256 {
			return nil, &Error{"Component checksum mismatch"}
		}
		offset += c.Bytes
	}
	_ = plain.Close()
	if err := os.Remove(plainPath); err != nil {
		return nil, err
	}
	owned = true
	return &Opened{Manifest: m, ManifestJSON: raw, dir: dir}, nil
}

// Describe gives a component's manifest entry from its file: its size and
// SHA-256.
func Describe(name, path string) (Component, error) {
	return DescribeWith(name, path, nil)
}

// DescribeWith is Describe with its hashing paced: pace, when set, is
// called after each chunk (about 1 MiB) with the bytes hashed so far, and
// the hashing waits for it; an error from it ends the hashing.
func DescribeWith(name, path string, pace func(hashed int64) error) (Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return Component{}, err
	}
	defer f.Close()
	h := sha256.New()
	var hashed int64
	n, err := copyPaced(h, f, make([]byte, chunk), func(n int) error {
		hashed += int64(n)
		if pace != nil {
			return pace(hashed)
		}
		return nil
	})
	if err != nil {
		return Component{}, err
	}
	return Component{Name: name, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// copyPaced copies src to dst through buf, calling pace after each chunk.
func copyPaced(dst io.Writer, src io.Reader, buf []byte, pace func(n int) error) (int64, error) {
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
			if err := pace(n); err != nil {
				return total, err
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}
