// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/dotenv"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch import <file>` (ADR-0043 Decision 2; slice 5.3a of internal
// docs/design/go-cli.md), main.ts's "import" case and importCommand.ts: the
// CLI reads a dotenv file itself and stores its values, so the values never
// pass through a coding agent's context. It prints names, counts, inferred
// types, and sensitivity, never a value, including in every diagnostic and
// in --json and --dry-run output.

const importUsage = "Usage: varlatch import <file> [--dry-run] [--contract [--plain <NAME>]...] [--replace <NAME>]... [--delete-source] [--json] [-e <env>]"

// ImportError is importCommand.ts's ImportError: "varlatch import: <message>"
// and its exit status.
type importError struct {
	message string
	code    int
}

func (e *importError) Error() string { return e.message }

func importFail(message string, code int) error { return &importError{message, code} }

// importOptions are importCommand.ts's ImportOptions.
type importOptions struct {
	file         string
	dryRun       bool
	contract     bool
	plain        []string
	deleteSource bool
	json         bool
	assisted     bool
	replace      []string
}

// importTarget is the project to import into, or why there is none (a dry
// run still lists names).
type importTarget struct {
	ctx     *clientctx.Context
	api     *lazyClient
	offline string
}

func importCommand(r *Run) error {
	// One filename, with options on either side of it, parsed strictly: an unknown option, a missing value,
	// or a second filename is 64.
	parsed, err := strictOptions("import", r.Args, OptionSpec{
		Values:      []string{"--environment", "--server"},
		Aliases:     []Alias{{"-e", "--environment"}},
		Lists:       []string{"--plain", "--replace"},
		Booleans:    []string{"--dry-run", "--contract", "--delete-source", "--json"},
		Positionals: 1,
	}, importUsage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) == 0 {
		return UsageError(importUsage)
	}
	opts := importOptions{
		file:         parsed.Positionals[0],
		dryRun:       parsed.Has("--dry-run"),
		contract:     parsed.Has("--contract"),
		plain:        parsed.Lists["--plain"],
		deleteSource: parsed.Has("--delete-source"),
		json:         parsed.Has("--json"),
		assisted:     r.Assisted.On,
		replace:      parsed.Lists["--replace"],
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	var target importTarget
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		message, isContext := clientctx.IsContextError(err)
		if !isContext || !opts.dryRun {
			return contextError(err)
		}
		first, _, _ := strings.Cut(message, ". ")
		target.offline = clientctx.MaskUserinfoInText(first)
	} else {
		server, err := serverString(ctx.Server)
		if err != nil {
			return err
		}
		token, err := r.loadToken(server)
		if err != nil {
			return err
		}
		if token != "" || !opts.dryRun {
			target.ctx, target.api = ctx, r.client(ctx)
		} else {
			target.offline = "not signed in to " + jsjson.String(clientctx.MaskServer(ctx.Server))
		}
	}
	code, err := r.runImport(opts, target)
	if err != nil {
		var ie *importError
		if errors.As(err, &ie) {
			return Fail("varlatch import: "+ie.message, ie.code)
		}
		return err
	}
	if code != 0 {
		return ExitWith(code)
	}
	return nil
}

// importRow is importCommand.ts's Row.
type importRow struct {
	entry dotenv.Entry
	// typ is the item's type: the Contract's (any JSON value it holds) or the inferred one.
	typ any
	// sensitive is null (nil) when unknown (a dry run without a connection), else the Contract's value or a boolean.
	sensitive any
	// contracted: already in the active Contract.
	contracted bool
	// existing: the target environment already has a value under this name; nil when unknown.
	existing any
}

// isBooleanWord is /^(true|false)$/i as JavaScript reads it without the u
// flag: ASCII letters fold, nothing else does ("falſe" is not "false";
// Go's (?i) would fold the long s).
func isBooleanWord(value string) bool {
	lower := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
	return lower == "true" || lower == "false"
}

var typeOrder = []string{"integer", "number", "url", "email"}

// InferType is importCommand.ts's inferType: the most specific type whose
// validation accepts the value, by the Contract Semantics version a
// revision would get; "string" otherwise.
func InferType(value string, semanticsVersion any) (string, error) {
	if value == "" {
		return "string", nil
	}
	// `true` and `false` only: a boolean item also accepts 1 and 0, but a count of 1 is far more often a number.
	if isBooleanWord(value) {
		return "boolean", nil
	}
	version, err := semanticsOf(semanticsVersion)
	if err != nil {
		return "", err
	}
	for _, t := range typeOrder {
		if t == "integer" && version.Version() < 3 {
			continue
		}
		if version.Validate(contract.Item{Name: "X", Required: contract.Requiredness{Kind: "never"}, Type: t}, value) == "" {
			return t, nil
		}
	}
	return "string", nil
}

// semanticsOf is semanticsFor(version) for a JSON value: an unknown
// version fails closed.
func semanticsOf(v any) (contract.Semantics, error) {
	if f, ok := v.(float64); ok && f == float64(int(f)) {
		return contract.SemanticsFor(int(f))
	}
	return contract.Semantics{}, errors.New("Contract semantics version " + jsjson.String(v) + " is not supported (supported: 1, 2, 3)")
}

var configItemName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// checkEntries is importCommand.ts's checkEntries: every problem with the
// file's names at once, by line: names and lines only.
func checkEntries(entries []dotenv.Entry) []string {
	var problems []string
	var order []string
	lines := map[string][]int{}
	for _, e := range entries {
		if _, seen := lines[e.Name]; !seen {
			order = append(order, e.Name)
		}
		lines[e.Name] = append(lines[e.Name], e.Line)
		if strings.HasPrefix(e.Name, "VARLATCH_") {
			problems = append(problems, "line "+strconv.Itoa(e.Line)+": "+e.Name+" is reserved for the Varlatch CLI and is never stored as configuration")
		} else if !configItemName.MatchString(e.Name) {
			problems = append(problems, "line "+strconv.Itoa(e.Line)+": "+e.Name+" is not a valid item name (upper-case letters, digits, and _, starting with a letter)")
		}
		if strings.Contains(e.Value, "\x00") {
			problems = append(problems, "line "+strconv.Itoa(e.Line)+": "+e.Name+" contains a NUL byte, which an environment variable cannot hold")
		}
	}
	for _, name := range order {
		if at := lines[name]; len(at) > 1 {
			shown := make([]string, len(at))
			for i, n := range at {
				shown[i] = strconv.Itoa(n)
			}
			problems = append(problems, name+" is set more than once, on lines "+strings.Join(shown, ", "))
		}
	}
	return problems
}

// decodeStrict is importCommand.ts's decodeStrict: the file as text (one
// byte order mark removed, as TextDecoder removes it), or an error naming
// the first line that is not valid UTF-8. Decoding with replacement would
// store U+FFFD in place of the original bytes, and --delete-source would
// then remove the only copy.
func decodeStrict(b []byte, file string) (string, error) {
	if utf8.Valid(b) {
		return strings.TrimPrefix(string(b), "\uFEFF"), nil
	}
	// A multi-byte sequence never contains a line feed, so lines can be checked one by one.
	line := 1
	for _, l := range bytes.Split(b, []byte{'\n'}) {
		if !utf8.Valid(l) {
			break
		}
		line++
	}
	return "", importFail(file+" line "+strconv.Itoa(line)+": not valid UTF-8 text. Nothing was imported.", ExitFailure)
}

// source is the file import reads: its bytes (the snapshot later steps
// compare with) and, for --delete-source, the file still open and what it
// is, so only that file is ever removed.
type source struct {
	bytes []byte
	open  *os.File
	info  os.FileInfo
}

func (s *source) close() {
	if s != nil && s.open != nil {
		_ = s.open.Close()
	}
}

// readSource is importCommand.ts's readSource: the file's bytes and its
// entries; value-free errors. With --delete-source the source must be a
// regular file named directly: not a symbolic link (deleting the link
// would leave the values in the file it points to) and not a directory, a
// device or a pipe. It is opened without following a link, read from what
// was opened, and kept open until it is deleted.
func readSource(file string, deleteSource bool) (*source, []dotenv.Entry, error) {
	src := &source{}
	if deleteSource {
		info, err := os.Lstat(file)
		if err != nil {
			return nil, nil, importFail("No such file: "+file, ExitFailure)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, importFail(file+" is a symbolic link, so --delete-source does not import from it: deleting the link would leave the values in the file it points to. Nothing was imported.", ExitFailure)
		}
		if !info.Mode().IsRegular() {
			return nil, nil, importFail(file+" is not a regular file, so --delete-source does not import from it. Nothing was imported.", ExitFailure)
		}
		f, err := openNoFollow(file)
		if err != nil {
			return nil, nil, importFail(file+" changed while it was opened, so --delete-source does not import from it. Nothing was imported.", ExitFailure)
		}
		opened, err := f.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			_ = f.Close()
			return nil, nil, importFail(file+" changed while it was opened, so --delete-source does not import from it. Nothing was imported.", ExitFailure)
		}
		if src.bytes, err = io.ReadAll(f); err != nil {
			_ = f.Close()
			return nil, nil, err
		}
		src.open, src.info = f, opened
	} else {
		if _, err := os.Stat(file); err != nil {
			return nil, nil, importFail("No such file: "+file, ExitFailure)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, err
		}
		src.bytes = b
	}
	text, err := decodeStrict(src.bytes, file)
	if err != nil {
		src.close()
		return nil, nil, err
	}
	entries, err := dotenv.Parse(text)
	if err != nil {
		src.close()
		return nil, nil, importFail(file+" "+err.Error()+". Nothing was imported.", ExitFailure)
	}
	return src, entries, nil
}

// presentValue is what an environment already has under a name: a plain
// value to compare, or a Secret or a withheld value (unknown).
type presentValue struct {
	sensitive any
	value     any // nil when unknown
}

// readPresent is importCommand.ts's readPresent: the environment's present
// values, or the HTTP status (403, 404) that kept them unreadable.
func readPresent(api *lazyClient, ctx *clientctx.Context) (map[string]presentValue, int, error) {
	c, err := api.get()
	if err != nil {
		return nil, 0, err
	}
	effective, err := c.EffectiveConfiguration(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), true)
	if err != nil {
		var a *apiclient.APIError
		if errors.As(err, &a) && (a.Status == 403 || a.Status == 404) {
			return nil, a.Status, nil
		}
		return nil, 0, err
	}
	items, err := itemsOf(effective)
	if err != nil {
		return nil, 0, err
	}
	present := map[string]presentValue{}
	for _, i := range items {
		name, _, err := read(i, true, "name")
		if err != nil {
			return nil, 0, err
		}
		sensitive, _ := jsval.Get(i, "sensitive")
		p := presentValue{sensitive: sensitive}
		if !jsjson.Truthy(sensitive) {
			// i.rawValue ?? i.value ?? null
			if v, ok := jsval.Get(i, "rawValue"); ok && v != nil {
				p.value = v
			} else if v, ok := jsval.Get(i, "value"); ok && v != nil {
				p.value = v
			}
		}
		present[jsjson.String(name)] = p
	}
	return present, 0, nil
}

// activeContract is importCommand.ts's activeContract: the active
// Contract, nil when there is none (404), forbidden without contract.read.
func activeContract(api *lazyClient, ctx *clientctx.Context) (c any, forbidden bool, err error) {
	client, err := api.get()
	if err != nil {
		return nil, false, err
	}
	revision, err := client.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		var a *apiclient.APIError
		if errors.As(err, &a) && a.Status == 404 {
			return nil, false, nil
		}
		if errors.As(err, &a) && a.Status == 403 {
			return nil, true, nil
		}
		return nil, false, err
	}
	found, _, err := read(revision, true, "contract")
	if err != nil {
		return nil, false, err
	}
	return found, false, nil
}

// UnrecognizedType and UnrecognizedHash are said in place of a Contract
// item's type, or a revision's content hash, that is not one the protocol
// defines.
const (
	UnrecognizedType = "an unrecognized type"
	UnrecognizedHash = "an unrecognized hash"
)

// contentHash is a Contract revision's content hash (lib/contract).
var contentHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// itemType is a Contract item's type as import shows it: one of
// contract.ItemTypes, else UnrecognizedType.
func itemType(t any) any {
	if s, ok := t.(string); ok && slices.Contains(contract.ItemTypes, s) {
		return s
	}
	return UnrecognizedType
}

// idOrUnrecognized is an identifier from an answer as a template literal
// shows it, when it has the server's shape; UnrecognizedID otherwise.
func idOrUnrecognized(v any, present bool, prefix string) string {
	if s, ok := v.(string); ok && present && serverID(prefix).MatchString(s) {
		return s
	}
	return UnrecognizedID
}

// typeText is a row's type as a template literal shows it.
func typeText(t any) string { return jsjson.String(t) }

// formatRows is importCommand.ts's formatRows.
func formatRows(rows []importRow, plain []string) []string {
	width, typeWidth := 0, 0
	for _, r := range rows {
		width = max(width, utf16Len(r.entry.Name))
		typeWidth = max(typeWidth, utf16Len(typeText(r.typ)))
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		sensitivity := ""
		switch {
		case r.sensitive == nil:
		case jsjson.Truthy(r.sensitive):
			sensitivity = "secret"
		case r.contracted || !slices.Contains(plain, r.entry.Name):
			sensitivity = "plain"
		default:
			sensitivity = "plain (--plain)"
		}
		note := ""
		if r.contracted {
			note += "  in the Contract"
		}
		if r.existing == true {
			note += "  already has a value"
		}
		line := "  " + padEnd(r.entry.Name, width) + "  " + padEnd(typeText(r.typ), typeWidth) + "  " + sensitivity + note
		out[i] = strings.TrimRightFunc(line, jsSpace)
	}
	return out
}

func padEnd(s string, width int) string {
	if n := utf16Len(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// storeFailure is storeValues' failure: the failing name with a value-free
// reason, its exit status, and the names not attempted.
type storeFailure struct {
	name    string
	reason  string
	code    int
	skipped []string
}

// storeValues is importCommand.ts's storeValues: the entries stored in
// order, stopping at the first failure.
func (r *Run) storeValues(api *apiclient.Client, ctx *clientctx.Context, entries []dotenv.Entry) ([]string, *storeFailure) {
	stored := []string{}
	for index, e := range entries {
		if _, err := api.SetValue(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), e.Name, e.Value); err != nil {
			var a *apiclient.APIError
			f := &storeFailure{name: e.Name}
			for _, s := range entries[index+1:] {
				f.skipped = append(f.skipped, s.Name)
			}
			network := apiclient.NetworkFailure(err)
			switch {
			case errors.As(err, &a):
				// Only a code the protocol defines: a server could echo the value it was sent in that field.
				f.reason = safeCode(a.Code)
				code, _ := a.Code.(string)
				f.code = APIErrorExit(a.Status, code)
			case network != "":
				f.reason, f.code = network, ExitUnavailable
			default:
				var fetch *apiclient.FetchError
				f.reason, f.code = "Error", ExitFailure
				if errors.As(err, &fetch) {
					f.reason = "TypeError"
				}
			}
			return stored, f
		}
		stored = append(stored, e.Name)
	}
	return stored, nil
}

// finishSource is importCommand.ts's finishSource, for the file
// readSource opened: deleted only if what was opened still holds the bytes
// read, and the path still names that same regular file (a fresh Lstat
// compared with the open file), so a file put in its place is never
// removed, nor a directory. True only when the path that held the values
// is gone afterwards. Never writes a value.
func finishSource(file string, src *source) (bool, error) {
	if src == nil || src.open == nil {
		return false, nil
	}
	current, err := io.ReadAll(io.NewSectionReader(src.open, 0, 1<<62))
	if err != nil || sha256.Sum256(current) != sha256.Sum256(src.bytes) {
		return false, nil
	}
	now, err := os.Lstat(file)
	if err != nil || !now.Mode().IsRegular() || !os.SameFile(src.info, now) {
		return false, nil
	}
	if err := os.Remove(file); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := os.Lstat(file); !errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return true, nil
}

// sortedUnique is `[...new Set(list)].sort()`: JavaScript's default sort,
// by UTF-16 code units.
func sortedUnique(list []string) []string {
	var out []string
	for _, s := range list {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.SortStableFunc(out, jsval.CompareUTF16)
	return out
}

// runImport is importCommand.ts's runImport.
func (r *Run) runImport(opts importOptions, target importTarget) (int, error) {
	// In JSON mode the human lines are replaced by one document at the end.
	out := func(line string) { _ = r.println(line) }
	if opts.json {
		out = func(string) {}
	}
	errLine := r.eprintln
	doc := jsjson.Object{{Key: "file", Value: opts.file}, {Key: "dryRun", Value: opts.dryRun}}
	emit := func(fields jsjson.Object) {
		if opts.json {
			full := jsjson.Object{{Key: "version", Value: float64(1)}}
			for _, m := range append(append(jsjson.Object{}, doc...), fields...) {
				full = full.Set(m.Key, m.Value)
			}
			_ = r.printJSON(full)
		}
	}
	if len(opts.plain) > 0 && !opts.contract {
		return 0, importFail("--plain applies only with --contract: an item's sensitivity lives in the Contract", ExitUsage)
	}
	src, entries, err := readSource(opts.file, opts.deleteSource)
	if err != nil {
		return 0, err
	}
	defer src.close()
	problems := checkEntries(entries)
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	plain := sortedUnique(opts.plain)
	for _, name := range plain {
		if !names[name] {
			problems = append(problems, "--plain names "+name+", which "+opts.file+" does not set")
		}
	}
	replace := sortedUnique(opts.replace)
	for _, name := range replace {
		if !names[name] {
			problems = append(problems, "--replace names "+name+", which "+opts.file+" does not set")
		}
	}
	if len(problems) > 0 {
		for _, line := range problems {
			errLine("varlatch import: " + opts.file + " " + line)
		}
		return 0, importFail(strconv.Itoa(len(problems))+" problem(s) in "+opts.file+". Nothing was imported.", ExitFailure)
	}
	if len(entries) == 0 {
		note := ""
		if opts.deleteSource {
			note = " It was not deleted."
		}
		out(opts.file + " sets no values; nothing to import." + note)
		emit(jsjson.Object{{Key: "target", Value: nil}, {Key: "items", Value: []any{}}, {Key: "stored", Value: []any{}}, {Key: "deleted", Value: false}})
		return 0, nil
	}

	online := target.api != nil
	var active any // the active Contract; nil when there is none
	if online {
		found, forbidden, err := activeContract(target.api, target.ctx)
		if err != nil {
			return 0, err
		}
		if forbidden {
			if opts.contract {
				return 0, importFail("--contract needs contract.read on this project to merge with the active Contract. Nothing was imported.", ExitDenied)
			}
			errLine("varlatch import: cannot read this project's Contract (403); sensitivity is shown as the default for items outside a Contract")
		} else {
			active = found
		}
	}
	// What the target environment already has, by name: a value there would be replaced. Plain values are
	// requested and compared in their stored form; a Secret's value is never on this path, and a withheld
	// plain value is unknown: both count as replacements.
	var present map[string]presentValue
	if online {
		read, status, err := readPresent(target.api, target.ctx)
		if err != nil {
			return 0, err
		}
		if read == nil {
			errLine("varlatch import: cannot read what " + environmentOf(target.ctx) + " already has (" + strconv.Itoa(status) + "); existing values cannot be told apart")
		} else {
			present = read
		}
	}
	var semanticsVersion any = float64(contract.LatestSemanticsVersion)
	if jsjson.Truthy(active) {
		semanticsVersion = float64(1)
		if v, ok := jsval.Get(active, "semanticsVersion"); ok && v != nil {
			semanticsVersion = v
		}
	}
	var contractList []any
	if active != nil {
		if items, ok := jsval.Get(active, "items"); ok && items != nil {
			list, isList := items.([]any)
			if !isList {
				return 0, &clientctx.TypeError{Message: "(contract?.items ?? []).map is not a function"}
			}
			contractList = list
		}
	}
	contracted := map[string]any{}
	for _, item := range contractList {
		name, _, err := read(item, true, "name")
		if err != nil {
			return 0, err
		}
		contracted[jsjson.String(name)] = item
	}
	for _, name := range plain {
		if item, ok := contracted[name]; ok {
			if s, _ := jsval.Get(item, "sensitive"); jsjson.Truthy(s) {
				problems = append(problems, "--plain names "+name+", which the Contract already marks sensitive; change it in the Contract instead")
			}
		}
	}
	if len(problems) > 0 {
		for _, line := range problems {
			errLine("varlatch import: " + line)
		}
		return 0, importFail("Nothing was imported.", ExitFailure)
	}

	rows := make([]importRow, len(entries))
	for i, e := range entries {
		item, isContracted := contracted[e.Name]
		row := importRow{entry: e, contracted: isContracted}
		switch {
		case !online:
			row.sensitive = nil
		case isContracted:
			v, _ := jsval.Get(item, "sensitive")
			// Plain only on the active Contract's explicit false; a missing or
			// malformed field counts as a Secret, the safe classification.
			row.sensitive = v != false
		case opts.contract:
			row.sensitive = !slices.Contains(plain, e.Name)
		default:
			row.sensitive = true
		}
		if present != nil {
			there, ok := present[e.Name]
			row.existing = ok && (jsjson.Truthy(there.sensitive) || there.value == nil || there.value != any(e.Value))
		}
		if t, ok := jsval.Get(item, "type"); isContracted && ok && t != nil {
			row.typ = itemType(t)
		} else {
			inferred, err := InferType(e.Value, semanticsVersion)
			if err != nil {
				return 0, err
			}
			row.typ = inferred
		}
		rows[i] = row
	}
	// The Secrets, and the values of unknown sensitivity, are in flight from
	// here on: no output or diagnostic shows one, whatever its length.
	// Only an item the active Contract marks plain (an explicit false) is
	// not held: an item --contract --plain only proposes as plain is held
	// until a Contract says so.
	for _, row := range rows {
		if !row.contracted || row.sensitive != false {
			r.holdValue(row.entry.Value)
		}
	}
	where := ""
	if online {
		where = target.ctx.Organization + "/" + target.ctx.Project + " (" + environmentOf(target.ctx) + ")"
	}
	secrets := 0
	for _, row := range rows {
		if jsjson.Truthy(row.sensitive) {
			secrets++
		}
	}
	counts := ""
	if online {
		counts = " (" + strconv.Itoa(secrets) + " secret, " + strconv.Itoa(len(rows)-secrets) + " plain)"
	}
	head := "Importing"
	if opts.dryRun {
		head = "Dry run: would import"
	}
	if online {
		out(head + " " + strconv.Itoa(len(rows)) + " value(s)" + counts + " from " + opts.file + " into " + where + ":")
	} else {
		out(head + " " + strconv.Itoa(len(rows)) + " value(s)" + counts + " from " + opts.file + " (not connected: " + target.offline + "):")
	}
	for _, line := range formatRows(rows, plain) {
		out(line)
	}
	var references []any
	var referenceNames []string
	for _, row := range rows {
		if strings.Contains(row.entry.Value, "${") {
			references = append(references, row.entry.Name)
			referenceNames = append(referenceNames, row.entry.Name)
		}
	}
	if references == nil {
		references = []any{}
	}
	var targetDoc, offlineDoc any
	if online {
		targetDoc = jsjson.Object{{Key: "organization", Value: target.ctx.Organization}, {Key: "project", Value: target.ctx.Project}, {Key: "environment", Value: target.ctx.Environment}}
	} else {
		offlineDoc = target.offline
	}
	items := make([]any, len(rows))
	for i, row := range rows {
		items[i] = jsjson.Object{
			{Key: "name", Value: row.entry.Name}, {Key: "type", Value: row.typ}, {Key: "sensitive", Value: row.sensitive},
			{Key: "inContract", Value: row.contracted}, {Key: "existing", Value: row.existing}, {Key: "line", Value: float64(row.entry.Line)},
		}
	}
	doc = append(doc, jsjson.Object{{Key: "target", Value: targetDoc}, {Key: "offline", Value: offlineDoc}, {Key: "items", Value: items}, {Key: "references", Value: references}}...)
	if len(referenceNames) > 0 {
		out("Note: Varlatch reads ${NAME} in a value as a reference to another item: " + strings.Join(referenceNames, ", "))
	}

	var additions []importRow
	if opts.contract {
		for _, row := range rows {
			if !row.contracted {
				additions = append(additions, row)
			}
		}
		kept := len(rows) - len(additions)
		switch {
		case len(additions) == 0:
			out("Contract: every item is already in the Contract; no revision is needed.")
		case kept > 0:
			out("Contract: " + strconv.Itoa(len(additions)) + " new item(s); " + strconv.Itoa(kept) + " already in the Contract keep their definition.")
		default:
			out("Contract: " + strconv.Itoa(len(additions)) + " new item(s).")
		}
	}
	contractDoc := func(revision any) jsjson.Object {
		if !opts.contract {
			return jsjson.Object{{Key: "contract", Value: nil}}
		}
		newItems := make([]any, len(additions))
		for i, row := range additions {
			newItems[i] = row.entry.Name
		}
		return jsjson.Object{{Key: "contract", Value: jsjson.Object{{Key: "newItems", Value: newItems}, {Key: "revision", Value: revision}}}}
	}
	var replacing []string
	for _, row := range rows {
		if row.existing == true {
			replacing = append(replacing, row.entry.Name)
		}
	}
	if len(replacing) > 0 && online {
		them := "them"
		if len(replacing) == 1 {
			them = "it"
		}
		out(environmentOf(target.ctx) + " already has a value for " + strings.Join(replacing, ", ") + "; importing replaces " + them + ".")
	}
	if opts.dryRun {
		note := ""
		if opts.deleteSource {
			note = " and " + opts.file + " was not deleted"
		}
		out("Dry run: nothing was stored" + note + ".")
		emit(append(contractDoc(nil), jsjson.Object{{Key: "stored", Value: []any{}}, {Key: "deleted", Value: false}}...))
		return 0, nil
	}
	if !online {
		return 0, importFail("Cannot import: "+target.offline, ExitFailure)
	}
	ctx := target.ctx
	environment := environmentOf(ctx)
	// Assisted mode: replacing what the environment has is the human's decision, item by item.
	if opts.assisted {
		var unapproved []string
		if present == nil {
			for _, row := range rows {
				if !slices.Contains(replace, row.entry.Name) {
					unapproved = append(unapproved, row.entry.Name)
				}
			}
		} else {
			for _, name := range replacing {
				if !slices.Contains(replace, name) {
					unapproved = append(unapproved, name)
				}
			}
		}
		if len(unapproved) > 0 {
			if present == nil {
				errLine("varlatch import: what " + environment + " already has cannot be read, so any of these may replace a value: " + strings.Join(unapproved, ", "))
			} else {
				errLine("varlatch import: " + environment + " already has a value for " + strings.Join(unapproved, ", ") + "; the file may be an older copy.")
			}
			errLine("  Replacing a value is the human's decision, for each named item. Ask them; with their approval for an item, add --replace <NAME> for it.")
			note := ""
			if opts.deleteSource {
				note = " and " + opts.file + " was not deleted"
			}
			return 0, importFail("Nothing was imported"+note+".", ExitConfig)
		}
	}
	api, err := target.api.get()
	if err != nil {
		return 0, err
	}

	var pushed any // {id, contentHash, active}, or null
	if len(additions) > 0 {
		list := append([]any{}, contractList...)
		for _, row := range additions {
			list = append(list, jsjson.Object{
				{Key: "name", Value: row.entry.Name},
				{Key: "required", Value: jsjson.Object{{Key: "kind", Value: "never"}}},
				{Key: "sensitive", Value: row.sensitive != false},
				{Key: "type", Value: row.typ},
			})
		}
		next := jsjson.Object{{Key: "schemaVersion", Value: float64(contract.SchemaVersion)}}
		if base, ok := active.(jsjson.Object); ok {
			next = append(jsjson.Object{}, base...)
		}
		next = next.Set("items", list)
		revision, err := api.PushContractRevision(context.Background(), ctx.Organization, ctx.Project, jsjson.Object{
			{Key: "contract", Value: next},
			{Key: "provenance", Value: jsjson.Object{{Key: "adapter", Value: "varlatch-import"}}},
		})
		if err != nil {
			return 0, err
		}
		id, idOK, err := read(revision, true, "id")
		if err != nil {
			return 0, err
		}
		hash, _, _ := read(revision, true, "contentHash")
		isActive, activeOK, _ := read(revision, true, "active")
		// The server's identifiers and hash only when they have its shapes.
		shownRev := idOrUnrecognized(id, idOK, "rev")
		shownHash := UnrecognizedHash
		if h, ok := hash.(string); ok && contentHash.MatchString(h) {
			shownHash = h
		}
		p := jsjson.Object{{Key: "id", Value: shownRev}, {Key: "contentHash", Value: shownHash}}
		if activeOK {
			p = append(p, jsjson.Member{Key: "active", Value: jsjson.Truthy(isActive)})
		}
		pushed = p
		mark := ""
		if jsjson.Truthy(isActive) {
			mark = " [active]"
		}
		out("Contract revision " + shownRev + " (" + shownHash + ")" + mark)
		if !jsjson.Truthy(isActive) {
			out("Activate with: varlatch contract activate " + shownRev)
		}
	}

	allEntries := make([]dotenv.Entry, len(rows))
	for i, row := range rows {
		allEntries[i] = row.entry
	}
	stored, failure := r.storeValues(api, ctx, allEntries)
	// The stored names that are Secrets (or of unknown sensitivity, which counts as one).
	secretsAmong := func(names []string) []string {
		var out []string
		for _, n := range names {
			for _, row := range rows {
				if row.entry.Name == n && row.sensitive != false {
					out = append(out, n)
					break
				}
			}
		}
		return out
	}
	if failure != nil {
		if len(stored) > 0 {
			errLine("varlatch import: stored: " + strings.Join(stored, ", "))
		}
		errLine("varlatch import: not stored: " + failure.name + " (" + failure.reason + ")")
		if len(failure.skipped) > 0 {
			errLine("varlatch import: not attempted: " + strings.Join(failure.skipped, ", "))
		}
		if len(stored) > 0 {
			r.copyNotice(opts.file, secretsAmong(stored), false)
		}
		// A retry in assisted mode finds the values stored above as existing, and may find them changed since
		// (rotated) or the file edited: replacing each needs the human's approval again, never this run's word.
		again := "Fix the cause and run the import again; stored values are overwritten with the same ones."
		if opts.assisted {
			again = "Fix the cause and run the import again."
			if len(stored) > 0 {
				each := "each"
				if len(stored) == 1 {
					each = "it"
				}
				again = "Fix the cause and run the import again: it now finds " + strings.Join(stored, ", ") + " stored, and replaces " + each +
					" only with the human's approval for that item (--replace <NAME>)."
			}
		}
		note := ""
		if opts.deleteSource {
			note = " " + opts.file + " was not deleted."
		}
		return 0, importFail(strconv.Itoa(len(stored))+" of "+strconv.Itoa(len(rows))+" value(s) stored."+note+" "+again, failure.code)
	}
	out("Stored " + strconv.Itoa(len(stored)) + " value(s) in " + where + ".")
	storedSecrets := secretsAmong(stored)
	storedDoc := make([]any, len(stored))
	for i, n := range stored {
		storedDoc[i] = n
	}
	if opts.deleteSource {
		finished, err := finishSource(opts.file, src)
		if err != nil {
			return 0, err
		}
		if !finished {
			errLine("varlatch import: " + opts.file + " changed or disappeared while importing; it was not deleted")
			r.copyNotice(opts.file, storedSecrets, false)
			emit(append(contractDoc(pushed), jsjson.Object{{Key: "stored", Value: storedDoc}, {Key: "deleted", Value: false}}...))
			return 1, nil
		}
		out("Deleted " + opts.file + ".")
		r.copyNotice(opts.file, storedSecrets, true)
	} else {
		r.copyNotice(opts.file, storedSecrets, false)
	}
	emit(append(contractDoc(pushed), jsjson.Object{{Key: "stored", Value: storedDoc}, {Key: "deleted", Value: opts.deleteSource}}...))
	return 0, nil
}

// copyNotice is importCommand.ts's copyNotice: what remains outside
// Varlatch after an import stored values (ADR-0053), on stderr.
func (r *Run) copyNotice(file string, secrets []string, deleted bool) {
	if deleted {
		r.eprintln("varlatch import: other copies of these values may still exist (CI settings, teammates, chat, backups); deleting " + file + " revokes nothing.")
	} else {
		r.eprintln("varlatch import: " + file + " still holds copies of these values. Rotating or deleting a value in Varlatch does not change the file; delete it once you no longer need it.")
	}
	if len(secrets) == 0 {
		return
	}
	r.eprintln("varlatch import: before relying on Varlatch for these secrets:")
	n := 1
	if !deleted {
		r.eprintln("  1. delete " + file + ";")
		n = 2
	}
	r.eprintln("  " + strconv.Itoa(n) + ". check where else it was copied (CI settings, teammates, chat);")
	r.eprintln("  " + strconv.Itoa(n+1) + ". rotate any secret whose copies you cannot account for: " + strings.Join(secrets, ", ") + ".")
}
