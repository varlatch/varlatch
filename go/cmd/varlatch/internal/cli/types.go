// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/typegen"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

// `varlatch types --out <file> [--revision <id>] [--check]` (slice 5.3c of
// internal docs/design/go-cli.md): main.ts's "types" case and
// typesCommand.ts. One Contract Revision is fetched (the active one, or
// --revision), the module is generated in the language the file's
// extension names (internal/typegen, the TypeScript generators' bytes), and
// it is written only if its bytes changed: never through a symbolic link,
// by a fresh file in the same directory renamed over the old one. --check
// compares and writes nothing. A file another release generated is current
// when only its Generator lines differ.

const typesUsage = "Usage: varlatch types --out <file.ts|file.py> [--revision <id>] [--check]"

// typesGenerators: the output file's extension selects the language
// (ADR-0041).
var typesGenerators = map[string]func(typegen.Revision, string) (string, error){
	".ts":  typegen.TypeScript,
	".mts": typegen.TypeScript,
	".cts": typegen.TypeScript,
	".py":  typegen.Python,
}

func typesCommand(r *Run) error {
	out, ok := flagArg(r.Args, "--out")
	if !ok || strings.HasPrefix(out, "-") {
		return UsageOnly(typesUsage)
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	// The output is the same for every Environment, so none is selected.
	options := clientctx.ResolveOptions{Cwd: cwd, Environment: "(unused)"}
	options.Server, _ = flagArg(r.Args, "--server")
	ctx, err := clientctx.ResolveContext(options, r.Env)
	if err != nil {
		return contextError(err)
	}
	revision, _ := flagArg(r.Args, "--revision")
	return r.runTypes(ctx, r.client(ctx), cwd, out, revision, hasArg(r.Args, "--check"))
}

// typesFailure is a TypesError as runTypes reports it: status 1, nothing
// written. The message can quote the server's answer (a Contract's
// unrecognized key, say), so its control characters and bidirectional
// overrides are escaped (Printable).
func typesFailure(message string) error {
	return Fail(Printable("varlatch types: "+message+". Nothing was written."), ExitFailure)
}

// shownSemanticsVersion is a semantics version as messages show it: ""
// (as it is) for a whole number from 1 to 999, else the placeholder, as
// `contract push` shows its answer's.
func shownSemanticsVersion(v any) string {
	if f, ok := v.(float64); ok && f == math.Trunc(f) && f >= 1 && f < 1000 {
		return ""
	}
	return UnrecognizedVersion
}

// shownRevision is a revision ID as messages show it: as it is when it has
// the server's shape, else the placeholder (go/README.md, "No message
// holds a value").
func shownRevision(id string) string {
	if serverID("rev").MatchString(id) {
		return id
	}
	return UnrecognizedID
}

func (r *Run) runTypes(ctx *clientctx.Context, api *lazyClient, cwd, out, revision string, check bool) error {
	path := out
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	generate, ok := typesGenerators[nodeExtname(path)]
	if !ok {
		return Fail("varlatch types: --out must name a TypeScript file (.ts, .mts, .cts) or a Python file (.py): "+out, ExitFailure)
	}
	answer, err := r.fetchRevision(ctx, api, revision)
	if err != nil {
		return err
	}
	field := func(key string) any {
		if v, ok := jsval.Get(answer, key); ok {
			return v
		}
		return typegen.Absent
	}
	input := typegen.Revision{ID: field("id"), ContentHash: field("contentHash"), SemanticsVersion: field("semanticsVersion"), Contract: field("contract")}
	if id, ok := input.ID.(string); ok {
		input.Shown = shownRevision(id)
	}
	input.ShownVersion = shownSemanticsVersion(input.SemanticsVersion)
	text, err := generate(input, buildinfo.Version)
	var typesErr *typegen.Error
	if errors.As(err, &typesErr) {
		return typesFailure(typesErr.Message)
	} else if err != nil {
		return err
	}
	// The bytes Node.js writes: a lone surrogate from the Contract as U+FFFD.
	content := typegen.Encode(text)
	// Generated, so the id, the hash and the version are of their shapes.
	source := "Contract Revision " + input.Shown + " (" + input.ContentHash.(string) + ", Contract Semantics version " +
		strconv.Itoa(int(input.SemanticsVersion.(float64))) + ")"
	current, mode, err := readTypesOutput(path)
	var refused *typegen.Error
	if errors.As(err, &refused) {
		return typesFailure(refused.Message)
	} else if err != nil {
		return err
	}
	generatedBy, fresh := "", false
	if current != nil {
		generatedBy, fresh = currentAs(current, content, buildinfo.Version, func(v string) (string, error) { return generate(input, v) })
	}
	by := ""
	if fresh && generatedBy != buildinfo.Version {
		by = " (generated by varlatch " + generatedBy + "; only the Generator lines differ)"
	}
	if check {
		if fresh {
			return r.println(out + " is current with " + source + by + ".")
		}
		state := "is stale"
		if current == nil {
			state = "does not exist"
		}
		again := ""
		if revision != "" {
			again = " --revision " + revisionArgument(revision)
		}
		return Fail("varlatch types --check: "+out+" "+state+": it does not match "+source+". Regenerate it with varlatch types --out "+out+again+".", ExitFailure)
	}
	if fresh {
		return r.println(out + " is already current with " + source + by + "; left unchanged.")
	}
	if err := writeReplacing(path, content, mode, current != nil); err != nil {
		return err
	}
	return r.println("Wrote " + out + " from " + source + ".")
}

// revisionArgument is a --revision argument as a command hint repeats it:
// as given when it has the server's shape, else a placeholder.
func revisionArgument(revision string) string {
	if serverID("rev").MatchString(revision) {
		return revision
	}
	return "<revision-id>"
}

// fetchRevision is typesCommand.ts's fetchRevision: the active revision,
// or the one named; 403 and 404 are said plainly.
func (r *Run) fetchRevision(ctx *clientctx.Context, api *lazyClient, revision string) (any, error) {
	c, err := api.get()
	if err != nil {
		return nil, err
	}
	var answer any
	if revision != "" {
		answer, err = c.GetContractRevision(context.Background(), ctx.Organization, ctx.Project, revision)
	} else {
		answer, err = c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	}
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case 403:
			return nil, typesFailure("reading the Contract needs contract.read on the project")
		case 404:
			where := ctx.Organization + "/" + ctx.Project
			if revision != "" {
				return nil, typesFailure("Contract Revision " + shownRevision(revision) + " was not found in " + where + " (fetching a revision by ID needs Varlatch 0.11.0 or later)")
			}
			return nil, typesFailure(where + " has no active Contract visible to this identity")
		}
	}
	return answer, err
}

// readTypesOutput is typesCommand.ts's readOutput: the bytes at the output
// path and its mode, or nil when there is no file. Anything but a regular
// file is refused (a *typegen.Error), a symbolic link above all.
func readTypesOutput(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	} else if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, &typegen.Error{Message: path + " is a symbolic link; varlatch types never writes through one, so point --out at the file itself"}
	}
	if !info.Mode().IsRegular() {
		return nil, 0, &typegen.Error{Message: path + " is not a regular file"}
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	// What was opened is the regular file Lstat saw: nothing put in its
	// place in between (where openNoFollow cannot refuse a link) is read.
	if opened, err := f.Stat(); err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, 0, &typegen.Error{Message: path + " changed while it was read"}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	if b == nil {
		b = []byte{}
	}
	return b, info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky), nil
}

// currentAs is typesCommand.ts's currentAs: the release whose output the
// file is, byte for byte (this one, or the one its Generator line names
// when only the Generator lines differ), and whether there is one.
func currentAs(current, content []byte, ours string, regenerate func(string) (string, error)) (string, bool) {
	if bytes.Equal(current, content) {
		return ours, true
	}
	theirs, ok := typegen.GeneratorOf(current)
	if !ok || theirs == ours {
		return "", false
	}
	// A version the generator cannot print is no release's output.
	text, err := regenerate(theirs)
	if err != nil || !bytes.Equal(current, typegen.Encode(text)) {
		return "", false
	}
	return theirs, true
}

// writeReplacing is typesCommand.ts's writeReplacing: the content goes to a
// fresh file in the same directory (created exclusively, not through a
// link), synced, given the old file's mode, and renamed over the path.
func writeReplacing(path string, content []byte, mode os.FileMode, keepMode bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(dir, "."+filepath.Base(path)+"."+strconv.Itoa(os.Getpid())+"."+hex.EncodeToString(random)+".tmp")
	// O_EXCL: created here, so nothing planted at the name (a link
	// included) is followed or reused.
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil && keepMode {
		err = os.Chmod(temporary, mode)
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		_ = os.Remove(temporary) // already renamed or never made
		return err
	}
	return nil
}

// nodeExtname is node's path.extname: the last path element's extension,
// from its last dot; none when the element has no dot, when its last dot is
// its first character, or when it is "..". Node's algorithm comes to
// exactly that: ".ts" has none, "..ts" is ".ts", "..." is ".", "a." is ".".
func nodeExtname(path string) string {
	base := path
	if i := strings.LastIndexAny(base, "/"+string(filepath.Separator)); i >= 0 {
		base = base[i+1:]
	}
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 || base == ".." {
		return ""
	}
	return base[dot:]
}
