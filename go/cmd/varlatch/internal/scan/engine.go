// SPDX-License-Identifier: Apache-2.0

// Package scan is apps/cli/src/scan.ts and scanSources.ts: local secret
// scanning, the engine behind `varlatch scan` (ADR-0038 Decision 14).
//
//   - Content is streamed through the shared matcher (internal/matcher),
//     one file at a time, as bytes: binary files are scanned like text, and
//     a value that spans lines (a PEM key) is found because matching runs
//     across the whole file. Offsets are mapped back to a line and a byte
//     column while streaming, keeping only the newline positions a later
//     occurrence can still need.
//   - Only complete occurrences are findings. A file that ends with the
//     start of a Secret is counted, without a location, and is not a
//     finding.
//   - A finding names the file, line, column, item, version and form. It
//     never carries the value, a fragment of it, or anything else from the
//     matched line, so a second Secret on that line cannot leak through it.
//   - A file that is skipped or cannot be read is reported as not scanned,
//     never as clean.
//   - False positives: an inline `varlatch:allow NAME` marker on a line the
//     occurrence touches, or a baseline entry (path, item, version).
//     Neither holds anything derived from the value.
package scan

import (
	"bytes"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/termtext"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Secret is ScanSecret: one value to look for, a Secret's current or
// retiring version.
type Secret struct {
	Item      string
	VersionID string
	Retiring  bool
	Value     string
}

// Finding is one complete occurrence: Path is relative to the directory
// holding varlatch.toml, with `/` separators; Column is 1-based, in bytes
// from the start of the line; Offset is in bytes from the start of the
// file. AllowedBy is "marker" or "baseline" for an allowed one, "" for a
// finding.
type Finding struct {
	Path      string
	Line      int
	Column    int
	Offset    int64
	Item      string
	VersionID string
	Retiring  bool
	Form      matcher.FormName
	AllowedBy string
}

// NotScanned is a path that was not read to its end, and why.
type NotScanned struct {
	Path   string
	Reason string
}

// Unlisted are occurrences beyond the per-file listing limit: counted by
// item and version, not located.
type Unlisted struct {
	Path      string
	Item      string
	VersionID string
	Retiring  bool
	Count     int
}

// BaselineEntry is one allowed (path, item, version).
type BaselineEntry struct {
	Path      string
	Item      string
	VersionID string
}

// Report is ScanReport.
type Report struct {
	Findings   []Finding
	Unlisted   []Unlisted
	Allowed    []Finding
	NotScanned []NotScanned
	// SkippedItems have a value shorter than the matcher's minimum length;
	// not checked.
	SkippedItems []string
	// ValuesChecked counts Secret versions checked (a rotating item counts
	// twice).
	ValuesChecked int
	FilesScanned  int
	BytesScanned  int64
	// IncompletePrefixes counts files that end with at least MinLength
	// bytes of a Secret's start and hold no complete occurrence of it there.
	IncompletePrefixes int
}

// Limits are ScanLimits.
type Limits struct {
	MaxFileSize  int64
	MaxTotalSize int64
}

// DefaultLimits are DEFAULT_LIMITS: 64 MiB per file, 1 GiB in all.
var DefaultLimits = Limits{MaxFileSize: 64 << 20, MaxTotalSize: 1 << 30}

// MaxListedPerFile is MAX_LISTED_PER_FILE: detailed findings kept per
// file; further occurrences are counted per item and version.
const MaxListedPerFile = 1000

// maxMarkersPerFile: allow markers kept per file; further markers are
// ignored, which can only add findings.
const maxMarkersPerFile = 10_000

var markerText = []byte("varlatch:allow")

const (
	maxGap  = 16
	maxName = 256
	// markerSpan is how many bytes a partly seen marker can span: the
	// marker, its gap, a name, and the byte after it.
	markerSpan = 14 + maxGap + maxName + 1
)

func isUpper(b byte) bool    { return b >= 'A' && b <= 'Z' }
func isNameByte(b byte) bool { return isUpper(b) || b >= '0' && b <= '9' || b == '_' }
func isWordByte(b byte) bool { return isNameByte(b) || b >= 'a' && b <= 'z' }

// lineIndex holds the newline positions near the end of the stream, enough
// to locate any offset at or after the last prune's bound.
type lineIndex struct {
	newlines   []int64
	head       int
	before     int
	lastPruned int64
}

func newLineIndex() *lineIndex { return &lineIndex{lastPruned: -1} }

func (l *lineIndex) feed(chunk []byte, base int64) {
	for at := 0; ; {
		i := bytes.IndexByte(chunk[at:], '\n')
		if i < 0 {
			return
		}
		l.newlines = append(l.newlines, base+int64(at+i))
		at += i + 1
	}
}

func (l *lineIndex) prune(keepFrom int64) {
	for l.head < len(l.newlines) && l.newlines[l.head] < keepFrom {
		l.lastPruned = l.newlines[l.head]
		l.before++
		l.head++
	}
	if l.head > 4096 && l.head*2 > len(l.newlines) {
		l.newlines = append([]int64(nil), l.newlines[l.head:]...)
		l.head = 0
	}
}

// locate is the 1-based line and byte column of offset.
func (l *lineIndex) locate(offset int64) (line, column int) {
	lo, hi := l.head, len(l.newlines)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if l.newlines[mid] < offset {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	previous := l.lastPruned
	if lo > l.head {
		previous = l.newlines[lo-1]
	}
	return l.before + (lo - l.head) + 1, int(offset - previous)
}

type marker struct {
	offset int64
	name   string
}

// markerFinder finds `varlatch:allow NAME` markers in a byte stream,
// including across chunks.
type markerFinder struct{ carry []byte }

// feed is the markers completed in this chunk, by offset and name.
func (m *markerFinder) feed(chunk []byte, base int64, final bool) []marker {
	data := chunk
	if len(m.carry) > 0 {
		data = append(append([]byte(nil), m.carry...), chunk...)
	}
	dataBase := base - int64(len(m.carry))
	var found []marker
	from, resume := 0, -1
	for from <= len(data) {
		rel := bytes.Index(data[from:], markerText)
		if rel < 0 {
			break
		}
		at := from + rel
		gapStart := at + len(markerText)
		gapEnd := gapStart
		for gapEnd < len(data) && gapEnd-gapStart <= maxGap && (data[gapEnd] == ' ' || data[gapEnd] == '\t') {
			gapEnd++
		}
		if gapEnd == len(data) && !final {
			resume = at
			break
		}
		nameEnd := gapEnd
		if gapEnd > gapStart && gapEnd-gapStart <= maxGap && gapEnd < len(data) && isUpper(data[gapEnd]) {
			for nameEnd < len(data) && nameEnd-gapEnd <= maxName && isNameByte(data[nameEnd]) {
				nameEnd++
			}
			if nameEnd == len(data) && !final {
				resume = at
				break
			}
			bounded := nameEnd-gapEnd <= maxName
			terminated := nameEnd == len(data) || !isWordByte(data[nameEnd])
			if bounded && terminated {
				found = append(found, marker{dataBase + int64(at), string(data[gapEnd:nameEnd])})
				from = nameEnd
				continue
			}
		}
		from = at + 1
	}
	switch {
	case final:
		m.carry = nil
	case resume >= 0:
		m.carry = append([]byte(nil), data[resume:]...)
	default:
		m.carry = append([]byte(nil), data[max(0, len(data)-(len(markerText)-1)):]...)
	}
	return found
}

type occ struct {
	entry   int
	form    matcher.FormName
	start   int64
	line    int
	column  int
	endLine int
}

// FileScan is one file being scanned, made by Engine.Begin.
type FileScan struct {
	engine      *Engine
	path        string
	window      int64
	lines       *lineIndex
	markers     markerFinder
	allow       map[int]map[string]bool
	markerCount int
	occurrences []occ
	// unlisted counts by entry, in the order the entries were first
	// counted (a Map's order).
	unlisted      map[int]int
	unlistedOrder []int
	bytes         int64
	done          bool
}

// Path is the file's path as reported.
func (f *FileScan) Path() string { return f.path }

// Push feeds the next chunk: false when the file went over the per-file
// bound (stop reading and call Fail).
func (f *FileScan) Push(chunk []byte) bool {
	if f.done {
		panic("file scan already finished")
	}
	if f.bytes+int64(len(chunk)) > f.engine.limits.MaxFileSize {
		return false
	}
	base := f.bytes
	f.bytes += int64(len(chunk))
	f.lines.feed(chunk, base)
	f.collectMarkers(f.markers.feed(chunk, base, false))
	found, _ := f.engine.scanner.Push(chunk)
	for _, o := range found {
		if len(f.occurrences) >= MaxListedPerFile {
			if _, ok := f.unlisted[o.Entry]; !ok {
				f.unlistedOrder = append(f.unlistedOrder, o.Entry)
			}
			f.unlisted[o.Entry]++
			continue
		}
		start, end := int64(o.Start), int64(o.End)
		line, column := f.lines.locate(start)
		endLine, _ := f.lines.locate(end - 1)
		f.occurrences = append(f.occurrences, occ{entry: o.Entry, form: o.Form, start: start, line: line, column: column, endLine: endLine})
	}
	// Any later occurrence or marker starts after this point.
	f.lines.prune(f.bytes - f.window)
	return true
}

// End is the file's clean end.
func (f *FileScan) End() {
	if f.done {
		panic("file scan already finished")
	}
	f.done = true
	f.collectMarkers(f.markers.feed(nil, f.bytes, true))
	end, _ := f.engine.scanner.End()
	prefix := end.IncompletePrefix
	f.engine.finish(f, prefix != nil && prefix.Length >= matcher.MinLength, nil)
}

// Fail is a file that could not be read to its end: what was found so far
// is still reported, and the file is reported as not scanned.
func (f *FileScan) Fail(reason string) {
	if f.done {
		panic("file scan already finished")
	}
	f.done = true
	f.engine.finish(f, false, &reason)
}

func (f *FileScan) allowedBy(o occ, item string) bool {
	for line := o.line; line <= o.endLine; line++ {
		if f.allow[line][item] {
			return true
		}
	}
	return false
}

func (f *FileScan) collectMarkers(found []marker) {
	for _, m := range found {
		if f.markerCount >= maxMarkersPerFile {
			return
		}
		f.markerCount++
		line, _ := f.lines.locate(m.offset)
		names := f.allow[line]
		if names == nil {
			names = map[string]bool{}
			f.allow[line] = names
		}
		names[m.name] = true
	}
}

type secretMeta struct {
	item      string
	versionID string
	retiring  bool
}

// Engine is ScanEngine.
type Engine struct {
	limits Limits
	// secrets are item, version and phase per registered entry; the values
	// live only in the matcher.
	secrets  []secretMeta
	scanner  *matcher.StreamScanner
	baseline map[BaselineEntry]bool
	open     *FileScan
	report   Report
	window   int64
}

// NewEngine registers the values and the baseline.
func NewEngine(secrets []Secret, limits Limits, baseline []BaselineEntry) *Engine {
	// A retiring value equal to the current one is the same bytes: check it
	// once.
	seen := map[string]bool{}
	var entries []matcher.SecretEntry
	e := &Engine{limits: limits, baseline: map[BaselineEntry]bool{}}
	for _, s := range secrets {
		key := s.Item + "\x00" + s.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, matcher.SecretEntry{Item: s.Item, Value: s.Value})
		e.secrets = append(e.secrets, secretMeta{s.Item, s.VersionID, s.Retiring})
	}
	e.scanner = matcher.NewStreamScanner(entries)
	e.window = int64(max(e.scanner.MaxLength, markerSpan) + 1)
	for _, b := range baseline {
		e.baseline[b] = true
	}
	skipped := []string{}
	for _, item := range e.scanner.Skipped {
		if !slices.Contains(skipped, item) {
			skipped = append(skipped, item)
		}
	}
	slices.SortStableFunc(skipped, jsval.CompareUTF16)
	e.report = Report{
		Findings: []Finding{}, Unlisted: []Unlisted{}, Allowed: []Finding{}, NotScanned: []NotScanned{},
		SkippedItems:  skipped,
		ValuesChecked: len(e.secrets) - len(e.scanner.SkippedEntries),
	}
	return e
}

// Limits are the engine's bounds.
func (e *Engine) Limits() Limits { return e.limits }

// ChecksAnything is whether any value is registered at all; if not, reading
// files cannot find anything.
func (e *Engine) ChecksAnything() bool { return e.report.ValuesChecked > 0 }

// Admit decides whether a file of size bytes is read, bytes the engine
// already read and reserved counting towards the total bound: a file over
// the per-file bound, or one that no longer fits in the total bound, is
// recorded as not scanned and false is returned.
func (e *Engine) Admit(path string, size, reserved int64) bool {
	if size > e.limits.MaxFileSize {
		e.NotScanned(path, "larger than the per-file bound ("+FormatBytes(size)+" > "+FormatBytes(e.limits.MaxFileSize)+")")
		return false
	}
	if e.report.BytesScanned+reserved+size > e.limits.MaxTotalSize {
		e.NotScanned(path, "over the total size bound of "+FormatBytes(e.limits.MaxTotalSize))
		return false
	}
	return true
}

// NotScanned records a path that is not scanned.
func (e *Engine) NotScanned(path, reason string) {
	e.report.NotScanned = append(e.report.NotScanned, NotScanned{path, reason})
}

// Begin starts reading a file. Only one file is open at a time.
func (e *Engine) Begin(path string) *FileScan {
	if e.open != nil {
		panic("still scanning " + e.open.path)
	}
	e.scanner.Reset()
	e.open = &FileScan{
		engine: e, path: path, window: e.window, lines: newLineIndex(),
		allow: map[int]map[string]bool{}, unlisted: map[int]int{},
	}
	return e.open
}

func (e *Engine) finish(file *FileScan, incompletePrefix bool, failure *string) {
	if e.open != file {
		panic("not the open file")
	}
	e.open = nil
	e.report.BytesScanned += file.bytes
	if failure != nil {
		e.NotScanned(file.path, *failure)
	} else {
		e.report.FilesScanned++
	}
	if incompletePrefix {
		e.report.IncompletePrefixes++
	}
	// Found in the order they end; listed in the order they start.
	ordered := slices.Clone(file.occurrences)
	slices.SortStableFunc(ordered, func(a, b occ) int {
		if a.start != b.start {
			if a.start < b.start {
				return -1
			}
			return 1
		}
		return a.entry - b.entry
	})
	for _, o := range ordered {
		s := e.secrets[o.entry]
		f := Finding{Path: file.path, Line: o.line, Column: o.column, Offset: o.start, Item: s.item, VersionID: s.versionID, Retiring: s.retiring, Form: o.form}
		switch {
		case file.allowedBy(o, s.item):
			f.AllowedBy = "marker"
			e.report.Allowed = append(e.report.Allowed, f)
		case e.baseline[BaselineEntry{f.Path, f.Item, f.VersionID}]:
			f.AllowedBy = "baseline"
			e.report.Allowed = append(e.report.Allowed, f)
		default:
			e.report.Findings = append(e.report.Findings, f)
		}
	}
	for _, entry := range file.unlistedOrder {
		s := e.secrets[entry]
		u := Unlisted{Path: file.path, Item: s.item, VersionID: s.versionID, Retiring: s.retiring, Count: file.unlisted[entry]}
		// Unlisted occurrences have no location, so only the baseline can
		// allow them.
		if !e.baseline[BaselineEntry{u.Path, u.Item, u.VersionID}] {
			e.report.Unlisted = append(e.report.Unlisted, u)
		}
	}
}

// Result is the report; no file may be open.
func (e *Engine) Result() *Report {
	if e.open != nil {
		panic("still scanning " + e.open.path)
	}
	return &e.report
}

// FormatBytes is formatBytes.
func FormatBytes(n int64) string {
	for _, u := range []struct {
		unit string
		size int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.size && n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + " " + u.unit
		}
	}
	if n >= 1<<20 {
		// (n / 2 ** 20).toFixed(1): the nearest tenth, a tie to the larger
		// one, of the exact quotient.
		tenths := (n*10 + 1<<19) >> 20
		return strconv.FormatInt(tenths/10, 10) + "." + strconv.FormatInt(tenths%10, 10) + " MiB"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// sizeText is parseSize's pattern.
var sizeText = regexp.MustCompile(`(?i)^(\d+)([KMG]?)(i?B)?$`)

// ParseSize is parseSize: `64M`, `1G`, `512K`, or a plain number of bytes;
// false when the text is none of them.
func ParseSize(text string) (int64, bool) {
	m := sizeText.FindStringSubmatch(strings.TrimFunc(text, jsval.IsWhitespace))
	if m == nil {
		return 0, false
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	switch strings.ToUpper(m[2]) {
	case "K":
		n *= 1 << 10
	case "M":
		n *= 1 << 20
	case "G":
		n *= 1 << 30
	}
	if !(n > 0 && n <= 1<<53-1 && n == float64(int64(n))) {
		return 0, false
	}
	return int64(n), true
}

// ---- The report ----------------------------------------------------------------

// ReportVersion is SCAN_REPORT_VERSION.
const ReportVersion = 1

// ExitCode is scanExitCode: 0 clean; 1 findings; 2 no findings, but not
// everything was scanned.
func (r *Report) ExitCode() int {
	if len(r.Findings) > 0 || len(r.Unlisted) > 0 {
		return 1
	}
	if len(r.NotScanned) > 0 {
		return 2
	}
	return 0
}

var formText = map[matcher.FormName]string{
	matcher.Raw:       "as written",
	matcher.JSON:      "JSON-escaped",
	matcher.Percent:   "percent-encoded",
	matcher.Base64:    "base64",
	matcher.Base64URL: "base64url",
}

func version(versionID string, retiring bool) string {
	if retiring {
		return "version " + versionID + ", retiring"
	}
	return "version " + versionID
}

// Human is formatScanHuman: names, versions and locations only. mode is
// "staged" or "paths".
func (r *Report) Human(environment, mode string) []string {
	var lines []string
	count := len(r.Findings)
	files := map[string]bool{}
	for _, f := range r.Findings {
		files[f.Path] = true
	}
	for _, u := range r.Unlisted {
		count += u.Count
		files[u.Path] = true
	}
	for _, f := range r.Findings {
		lines = append(lines, termtext.DisplayPath(f.Path)+":"+strconv.Itoa(f.Line)+":"+strconv.Itoa(f.Column)+": "+f.Item+" ("+version(f.VersionID, f.Retiring)+"), "+formText[f.Form])
	}
	for _, u := range r.Unlisted {
		lines = append(lines, termtext.DisplayPath(u.Path)+": "+strconv.Itoa(u.Count)+" more occurrence(s) of "+u.Item+" ("+version(u.VersionID, u.Retiring)+"), not listed")
	}
	if len(r.NotScanned) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "Not scanned ("+strconv.Itoa(len(r.NotScanned))+"), so not known to be clean:")
		for _, n := range r.NotScanned {
			lines = append(lines, "  "+termtext.DisplayPath(n.Path)+": "+n.Reason)
		}
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	what := "file"
	if mode == "staged" {
		what = "staged file"
	}
	summary := "varlatch scan: " + strconv.Itoa(r.FilesScanned) + " " + what + "(s) checked against " + strconv.Itoa(r.ValuesChecked) + " Secret value(s) of " + environment + ": "
	if count > 0 {
		summary += strconv.Itoa(count) + " finding(s) in " + strconv.Itoa(len(files)) + " file(s)."
	} else {
		summary += "no findings."
	}
	if len(r.NotScanned) > 0 {
		summary += " " + strconv.Itoa(len(r.NotScanned)) + " not scanned."
	}
	if len(r.Allowed) > 0 {
		summary += " " + strconv.Itoa(len(r.Allowed)) + " allowed by a marker or the baseline."
	}
	lines = append(lines, summary)
	if count > 0 {
		lines = append(lines, "Values and line contents are never shown. Rotate a Secret that was committed or published.")
	}
	return lines
}

// Notices are scanNotices: what was not checked, by name only, for stderr.
func (r *Report) Notices() []string {
	var notices []string
	if len(r.SkippedItems) > 0 {
		notices = append(notices, "varlatch scan: values shorter than "+strconv.Itoa(matcher.MinLength)+" bytes are not checked: "+strings.Join(r.SkippedItems, ", "))
	}
	if r.IncompletePrefixes > 0 {
		notices = append(notices, "varlatch scan: "+strconv.Itoa(r.IncompletePrefixes)+" file(s) end with the first "+strconv.Itoa(matcher.MinLength)+
			" or more bytes of a Secret but hold no complete occurrence there; that is not a finding")
	}
	return notices
}

func findingJSON(f Finding) jsjson.Object {
	o := jsjson.Object{
		{Key: "path", Value: f.Path}, {Key: "line", Value: float64(f.Line)}, {Key: "column", Value: float64(f.Column)},
		{Key: "offset", Value: float64(f.Offset)}, {Key: "item", Value: f.Item}, {Key: "versionId", Value: f.VersionID},
		{Key: "retiring", Value: f.Retiring}, {Key: "form", Value: string(f.Form)},
	}
	if f.AllowedBy != "" {
		o = append(o, jsjson.Member{Key: "allowedBy", Value: f.AllowedBy})
	}
	return o
}

// JSON is the report's members as `{...report}` spreads them.
func (r *Report) JSON() jsjson.Object {
	findings, allowed, unlisted, notScanned, skipped := []any{}, []any{}, []any{}, []any{}, []any{}
	for _, f := range r.Findings {
		findings = append(findings, findingJSON(f))
	}
	for _, u := range r.Unlisted {
		unlisted = append(unlisted, jsjson.Object{{Key: "path", Value: u.Path}, {Key: "item", Value: u.Item}, {Key: "versionId", Value: u.VersionID},
			{Key: "retiring", Value: u.Retiring}, {Key: "count", Value: float64(u.Count)}})
	}
	for _, f := range r.Allowed {
		allowed = append(allowed, findingJSON(f))
	}
	for _, n := range r.NotScanned {
		notScanned = append(notScanned, jsjson.Object{{Key: "path", Value: n.Path}, {Key: "reason", Value: n.Reason}})
	}
	for _, s := range r.SkippedItems {
		skipped = append(skipped, s)
	}
	return jsjson.Object{
		{Key: "findings", Value: findings}, {Key: "unlisted", Value: unlisted}, {Key: "allowed", Value: allowed},
		{Key: "notScanned", Value: notScanned}, {Key: "skippedItems", Value: skipped},
		{Key: "valuesChecked", Value: float64(r.ValuesChecked)}, {Key: "filesScanned", Value: float64(r.FilesScanned)},
		{Key: "bytesScanned", Value: float64(r.BytesScanned)}, {Key: "incompletePrefixes", Value: float64(r.IncompletePrefixes)},
	}
}

// AcceptAll is --write-baseline's report: every finding allowed by the
// baseline, nothing unlisted.
func (r *Report) AcceptAll() *Report {
	out := *r
	out.Allowed = slices.Clone(r.Allowed)
	for _, f := range r.Findings {
		f.AllowedBy = "baseline"
		out.Allowed = append(out.Allowed, f)
	}
	out.Findings, out.Unlisted = []Finding{}, []Unlisted{}
	return &out
}

// BaselineEntries is baselineEntriesOf: an entry for everything the report
// found, listed or not.
func (r *Report) BaselineEntries() []BaselineEntry {
	var out []BaselineEntry
	for _, f := range r.Findings {
		out = append(out, BaselineEntry{f.Path, f.Item, f.VersionID})
	}
	for _, u := range r.Unlisted {
		out = append(out, BaselineEntry{u.Path, u.Item, u.VersionID})
	}
	return out
}
