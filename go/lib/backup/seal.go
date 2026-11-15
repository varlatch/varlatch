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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/scrypt"
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

func (b BEK) derive(salt []byte) ([]byte, error) {
	return scrypt.Key(b.material, salt, 32768, 8, 1, 32)
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
	// Decision 7's paced sealing).
	Pace func(sealed int64)
}

// Seal writes an archive to output: the manifest and the component files,
// in the manifest's order, each checked against its size. The archive is
// written to a temporary file beside output (mode 0600) and linked into
// place, so output never holds a partial archive and an existing one is
// never replaced.
func Seal(output string, manifest []byte, components []string, bek BEK, o SealOptions) (err error) {
	if len(manifest) > MaxManifestBytes {
		return &Error{"Archive exceeds the v1 60 GiB size limit"}
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
	key, err := bek.derive(header[8:24])
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
			o.Pace(sealed)
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
	return syncDir(filepath.Dir(output))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

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
func Open(path string, bek BEK, scratch string) (_ *Opened, err error) {
	f, err := os.Open(path)
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
	key, err := bek.derive(header[8:24])
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
	defer func() {
		if err != nil {
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
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if err := s.xor(buf[:n], buf[:n]); err != nil {
				return nil, ErrIntegrity
			}
			if _, err := plain.Write(buf[:n]); err != nil {
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
		_, cerr := io.Copy(io.MultiWriter(out, h), io.NewSectionReader(plain, offset, c.Bytes))
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
	return &Opened{Manifest: m, ManifestJSON: raw, dir: dir}, nil
}

// Describe gives a component's manifest entry from its file: its size and
// SHA-256.
func Describe(name, path string) (Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return Component{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return Component{}, err
	}
	return Component{Name: name, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
