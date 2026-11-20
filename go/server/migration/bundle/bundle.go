// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bundle is the migration's bundle, bundle-v1 (BUNDLE.md): the
// stream the TypeScript server's export and varlatchd's reverse export
// write, a header, each manifest table's canonical rows, the check
// sections (the writer's keyed digests and decisions), and an end line
// carrying the stream's SHA-256, so a stream cut short is refused whole.
package bundle

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// Format is bundle-v1's version.
const Format = 1

// Directions.
const (
	Forward = "forward" // the TypeScript server's export, for varlatchd
	Reverse = "reverse" // varlatchd's reverse export, for the TypeScript server
)

// maxLine bounds one line (a row): 64 MiB.
const maxLine = 64 << 20

// Header is the first line.
type Header struct {
	Manifest    int
	Encoding    string
	Direction   string
	Release     string
	FrozenPoint FrozenPoint
}

// FrozenPoint is where the writer read from (decision 6).
type FrozenPoint struct {
	AuditPosition int64
	// Snapshot is the PostgreSQL snapshot of a forward bundle; "" in a
	// reverse one.
	Snapshot string
}

// Tables are the manifest's tables a bundle carries, in its order: those
// it copies or transforms.
func Tables(m *manifest.Manifest) []manifest.Table {
	var out []manifest.Table
	for _, t := range m.Tables {
		if t.Action == manifest.Copy || t.Action == manifest.Transform {
			out = append(out, t)
		}
	}
	return out
}

// Writer writes a bundle: the header, each table's line and rows, the end.
type Writer struct {
	w       *bufio.Writer
	sum     hash.Hash
	tables  []manifest.Table
	next    int // the next table expected
	left    int // rows still due for the current table
	nTables int
	nRows   int64
	err     error
	// section is 0 in the tables, 1 in the digests, 2 in the decisions.
	section    int
	nDigests   int
	nDecisions int
	lastDigest *Digest
}

// NewWriter writes h to w and returns the writer for m's tables.
func NewWriter(w io.Writer, m *manifest.Manifest, h Header) (*Writer, error) {
	bw := &Writer{w: bufio.NewWriterSize(w, 1<<20), sum: sha256.New(), tables: Tables(m)}
	if err := checkHeader(h, m); err != nil {
		return nil, err
	}
	fp := jsvalue.Object{{Key: "auditPosition", Value: h.FrozenPoint.AuditPosition}}
	if h.FrozenPoint.Snapshot != "" {
		fp = append(fp, jsvalue.Member{Key: "snapshot", Value: h.FrozenPoint.Snapshot})
	}
	header := jsvalue.Object{
		{Key: "bundle", Value: "varlatch-migration"}, {Key: "format", Value: Format}, {Key: "manifest", Value: h.Manifest},
		{Key: "encoding", Value: h.Encoding}, {Key: "direction", Value: h.Direction}, {Key: "release", Value: h.Release},
		{Key: "frozenPoint", Value: fp}, {Key: "sequences", Value: []any{}},
	}
	bw.line(jsvalue.Stringify(header))
	return bw, bw.err
}

func (w *Writer) line(b []byte) {
	if w.err != nil {
		return
	}
	b = append(b, '\n')
	w.sum.Write(b)
	_, w.err = w.w.Write(b)
}

// Table starts the next table, with its number of rows.
func (w *Writer) Table(source string, rows int) error {
	if w.err != nil {
		return w.err
	}
	if w.left != 0 {
		return fmt.Errorf("bundle: %d rows of %s still due", w.left, w.tables[w.next-1].Source)
	}
	if w.next >= len(w.tables) || w.tables[w.next].Source != source {
		return fmt.Errorf("bundle: table %s is not the next in the manifest's order", source)
	}
	if rows < 0 {
		return errors.New("bundle: a negative row count")
	}
	w.next++
	w.left = rows
	w.nTables++
	w.line(jsvalue.Stringify(jsvalue.Object{{Key: "table", Value: source}, {Key: "rows", Value: rows}}))
	return w.err
}

// Row writes one canonical row of the current table.
func (w *Writer) Row(row []byte) error {
	if w.err != nil {
		return w.err
	}
	if w.left <= 0 || w.section != 0 {
		return errors.New("bundle: a row beyond its table's count")
	}
	if bytes.IndexByte(row, '\n') >= 0 {
		return errors.New("bundle: a row holding a line break")
	}
	w.left--
	w.nRows++
	w.line(row)
	return w.err
}

// Close writes the end line once every table and row is written.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.left != 0 || w.next != len(w.tables) || w.section != 2 {
		return fmt.Errorf("bundle: closed after %d of %d tables and section %d, %d lines still due", w.next, len(w.tables), w.section, w.left)
	}
	end := jsvalue.Object{{Key: "end", Value: jsvalue.Object{
		{Key: "tables", Value: w.nTables}, {Key: "rows", Value: w.nRows}, {Key: "digests", Value: w.nDigests},
		{Key: "decisions", Value: w.nDecisions}, {Key: "sha256", Value: hex.EncodeToString(w.sum.Sum(nil))},
	}}}
	b := append(jsvalue.Stringify(end), '\n')
	if _, err := w.w.Write(b); err != nil {
		return err
	}
	return w.w.Flush()
}

func checkHeader(h Header, m *manifest.Manifest) error {
	switch {
	case h.Manifest != m.Version || h.Encoding != m.Encoding:
		return fmt.Errorf("bundle: manifest %d in %s; this varlatchd reads manifest %d in %s", h.Manifest, h.Encoding, m.Version, m.Encoding)
	case h.Direction != Forward && h.Direction != Reverse:
		return fmt.Errorf("bundle: direction %q is neither forward nor reverse", h.Direction)
	case h.Release == "":
		return errors.New("bundle: no release")
	case h.FrozenPoint.AuditPosition < 0:
		return errors.New("bundle: a negative audit position")
	case h.Direction == Forward && h.Release != m.Source.Release:
		return fmt.Errorf("bundle: written by %s; the manifest's source is %s", h.Release, m.Source.Release)
	case h.Direction == Forward && h.FrozenPoint.Snapshot == "":
		return errors.New("bundle: a forward bundle names its PostgreSQL snapshot")
	case h.Direction == Reverse && h.FrozenPoint.Snapshot != "":
		return errors.New("bundle: a reverse bundle names no PostgreSQL snapshot")
	}
	return nil
}

// Reader reads a bundle: Header first, then each table and its rows, then
// End, which checks the counts and the digest.
type Reader struct {
	r      *bufio.Reader
	sum    hash.Hash
	m      *manifest.Manifest
	tables []manifest.Table
	next   int
	left   int
	nRows  int64
	head   Header
	// section is 0 in the tables, 1 in the digests, 2 in the decisions.
	section    int
	nDigests   int
	nDecisions int
	lastDigest *Digest
}

// NewReader reads and checks the header against m.
func NewReader(r io.Reader, m *manifest.Manifest) (*Reader, error) {
	br := &Reader{r: bufio.NewReaderSize(r, 1<<20), sum: sha256.New(), m: m, tables: Tables(m)}
	line, err := br.line()
	if err != nil {
		return nil, err
	}
	var h struct {
		Bundle      string `json:"bundle"`
		Format      *int   `json:"format"`
		Manifest    *int   `json:"manifest"`
		Encoding    string `json:"encoding"`
		Direction   string `json:"direction"`
		Release     string `json:"release"`
		FrozenPoint *struct {
			AuditPosition *int64  `json:"auditPosition"`
			Snapshot      *string `json:"snapshot"`
		} `json:"frozenPoint"`
		Sequences *[]json.RawMessage `json:"sequences"`
	}
	if err := strict(line, &h); err != nil {
		return nil, fmt.Errorf("bundle: the header: %w", err)
	}
	if h.Bundle != "varlatch-migration" || h.Format == nil || *h.Format != Format {
		return nil, errors.New("bundle: not a bundle-v1 stream")
	}
	if h.Manifest == nil || h.FrozenPoint == nil || h.FrozenPoint.AuditPosition == nil || h.Sequences == nil {
		return nil, errors.New("bundle: the header lacks a member")
	}
	if len(*h.Sequences) != 0 {
		return nil, fmt.Errorf("bundle: the source has %d sequences; the migration carries none (decision 16)", len(*h.Sequences))
	}
	br.head = Header{Manifest: *h.Manifest, Encoding: h.Encoding, Direction: h.Direction, Release: h.Release,
		FrozenPoint: FrozenPoint{AuditPosition: *h.FrozenPoint.AuditPosition}}
	if h.FrozenPoint.Snapshot != nil {
		if *h.FrozenPoint.Snapshot == "" {
			return nil, errors.New("bundle: an empty snapshot")
		}
		br.head.FrozenPoint.Snapshot = *h.FrozenPoint.Snapshot
	}
	if err := checkHeader(br.head, m); err != nil {
		return nil, err
	}
	return br, nil
}

// Header is the bundle's header.
func (r *Reader) Header() Header { return r.head }

// line reads one line, adding it to the digest; io.ErrUnexpectedEOF when
// the stream ends before a line does.
func (r *Reader) line() ([]byte, error) {
	b, err := r.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		var full []byte
		full = append(full, b...)
		for errors.Is(err, bufio.ErrBufferFull) {
			if len(full) > maxLine {
				return nil, errors.New("bundle: a line past 64 MiB")
			}
			b, err = r.r.ReadSlice('\n')
			full = append(full, b...)
		}
		b = full
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("bundle: the stream ends before its end line: cut short")
		}
		return nil, err
	}
	if len(b) > maxLine {
		return nil, errors.New("bundle: a line past 64 MiB")
	}
	r.sum.Write(b)
	line := b[:len(b)-1]
	if len(line) == 0 || line[len(line)-1] == '\r' {
		return nil, errors.New("bundle: a blank line, or a line ending in \\r\\n")
	}
	return append([]byte(nil), line...), nil
}

// NextTable reads the next table's line: the manifest's table and its row
// count. It is an error while rows of the previous table are due, or after
// the last table (read the sections, then call End).
func (r *Reader) NextTable() (manifest.Table, int, error) {
	if r.left != 0 {
		return manifest.Table{}, 0, fmt.Errorf("bundle: %d rows of %s still due", r.left, r.tables[r.next-1].Source)
	}
	if r.next >= len(r.tables) {
		return manifest.Table{}, 0, errors.New("bundle: every table is read")
	}
	line, err := r.line()
	if err != nil {
		return manifest.Table{}, 0, err
	}
	var t struct {
		Table *string `json:"table"`
		Rows  *int    `json:"rows"`
	}
	if err := strict(line, &t); err != nil || t.Table == nil || t.Rows == nil || *t.Rows < 0 {
		return manifest.Table{}, 0, fmt.Errorf("bundle: a table line was due (table %s): %s", r.tables[r.next].Source, shortLine(line))
	}
	want := r.tables[r.next]
	if *t.Table != want.Source {
		return manifest.Table{}, 0, fmt.Errorf("bundle: table %s where the manifest's order has %s", *t.Table, want.Source)
	}
	r.next++
	r.left = *t.Rows
	return want, *t.Rows, nil
}

// Row reads the current table's next row (its canonical bytes; the caller
// decodes them with the table's types).
func (r *Reader) Row() ([]byte, error) {
	if r.left <= 0 || r.section != 0 {
		return nil, errors.New("bundle: no row is due")
	}
	line, err := r.line()
	if err != nil {
		return nil, err
	}
	r.left--
	r.nRows++
	return line, nil
}

// End reads the end line once every table and both sections are read, and
// checks its counts and the stream's digest; nothing may follow it.
func (r *Reader) End() error {
	if r.left != 0 || r.next != len(r.tables) || r.section != 2 {
		return fmt.Errorf("bundle: the end before %d of %d tables and both sections were read", r.next, len(r.tables))
	}
	want := hex.EncodeToString(r.sum.Sum(nil))
	b, err := r.r.ReadSlice('\n')
	if err != nil {
		return errors.New("bundle: the stream ends before its end line: cut short")
	}
	var e struct {
		End *struct {
			Tables    *int    `json:"tables"`
			Rows      *int64  `json:"rows"`
			Digests   *int    `json:"digests"`
			Decisions *int    `json:"decisions"`
			SHA256    *string `json:"sha256"`
		} `json:"end"`
	}
	if err := strict(b[:len(b)-1], &e); err != nil || e.End == nil || e.End.Tables == nil || e.End.Rows == nil ||
		e.End.Digests == nil || e.End.Decisions == nil || e.End.SHA256 == nil {
		return errors.New("bundle: the end line was due")
	}
	if *e.End.Tables != len(r.tables) || *e.End.Rows != r.nRows || *e.End.Digests != r.nDigests || *e.End.Decisions != r.nDecisions {
		return fmt.Errorf("bundle: the end line counts %d tables, %d rows, %d digests and %d decisions; the stream holds %d, %d, %d and %d",
			*e.End.Tables, *e.End.Rows, *e.End.Digests, *e.End.Decisions, len(r.tables), r.nRows, r.nDigests, r.nDecisions)
	}
	if *e.End.SHA256 != want {
		return errors.New("bundle: the stream's SHA-256 is not the end line's: damaged")
	}
	if _, err := r.r.ReadByte(); !errors.Is(err, io.EOF) {
		return errors.New("bundle: text after the end line")
	}
	return nil
}

// strict decodes one control line: no unknown member, nothing after it.
func strict(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("text after the value")
	}
	return nil
}

func shortLine(b []byte) string {
	if len(b) > 80 {
		return strconv.Quote(string(b[:80])) + "..."
	}
	return strconv.Quote(string(b))
}

// Verify reads a whole bundle without keeping it: its header, every table
// line and row count, the check sections' lines, the end line's counts and
// the stream's SHA-256. An
// import runs it first, so a bundle cut short or damaged is named so before
// anything is written.
func Verify(r io.Reader, m *manifest.Manifest) (Header, error) {
	br, err := NewReader(r, m)
	if err != nil {
		return Header{}, err
	}
	for range br.tables {
		_, n, err := br.NextTable()
		if err != nil {
			return Header{}, err
		}
		for range n {
			if _, err := br.Row(); err != nil {
				return Header{}, err
			}
		}
	}
	if err := br.SkipSections(); err != nil {
		return Header{}, err
	}
	return br.head, br.End()
}

// Decode reads one row of table t: canonical-v1 (canonical.DecodeRow), and
// every column the manifest leaves out null. A left-out column is never
// exported (the session's token, which is plaintext in PostgreSQL): a row
// that carries a value there is refused.
func Decode(t manifest.Table, row []byte) ([]any, error) {
	values, err := canonical.DecodeRow(t.Types(), row)
	if err != nil {
		return nil, err
	}
	for i, c := range t.Columns {
		if c.LeftOut != "" && values[i] != nil {
			return nil, fmt.Errorf("bundle: %s.%s holds a value; the manifest leaves it out, so an export writes null there", t.Source, c.Source)
		}
	}
	return values, nil
}
