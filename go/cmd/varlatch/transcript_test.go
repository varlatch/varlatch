// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/envschema"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The test binary is also the CLI under test: run with this variable set,
// it is `varlatch` (main's run), so the transcripts run the CLI as a
// process without a second build.
const asCLI = "VARLATCH_TEST_AS_CLI"

// promptPause names the hidden prompt's stage at which the CLI under test
// pauses (secretinput.Hook).
const promptPause = "VARLATCH_TEST_PROMPT_PAUSE"

func TestMain(m *testing.M) {
	if os.Getenv(asCLI) == "1" {
		// The pseudo-terminal tests stop the hidden prompt at a stage before
		// its question, to send a signal in that window.
		if stage := os.Getenv(promptPause); stage != "" {
			secretinput.Hook = func(at string) {
				if at == stage {
					fmt.Fprintf(os.Stderr, "PAUSED %s\n", at)
					time.Sleep(5 * time.Second)
				}
			}
		}
		// The platform client never reaches the network here (5.8b).
		apiclient.PlatformDial = replayPlatformDial(os.Getenv(transcript.PlatformEnv))
		os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	setTranscriptUmask()
	os.Exit(m.Run())
}

// replayPlatformDial is the platform client's dialer while a CLI under
// test runs: a fake platform's host name at port 443 reaches the replay's
// server at fake, when the case has one; every other platform host, a fake
// platform when the case has none, and any address that is not loopback
// is refused, so no case can ever reach a real platform (api.github.com).
func replayPlatformDial(fake string) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		switch {
		case slices.Contains(transcript.PlatformHosts, host):
			if fake == "" || port != "443" {
				return nil, fmt.Errorf("transcript replay: %s has no fake platform in this case", address)
			}
			address = fake
		case host != "localhost" && !isLoopbackIP(host):
			return nil, fmt.Errorf("transcript replay: %s is not a fake platform, and a replay never dials the network", address)
		}
		return dialer.DialContext(ctx, network, address)
	}
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TestReplayNeverDialsAPlatform: the replay's dialer sends a fake
// platform's host to the fake, refuses it when the case has none, and
// refuses every address that is not loopback.
func TestReplayNeverDialsAPlatform(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	fake := ln.Addr().String()
	for _, c := range []struct {
		fake, address string
		dials         bool
	}{
		{fake, "api.github.com:443", true},
		{"", "api.github.com:443", false},
		{fake, "api.github.com:80", false},
		{"", "coolify.conformance.test:443", false},
		{fake, "github.com:443", false},
		{fake, "203.0.113.7:443", false},
		{fake, fake, true},
	} {
		conn, err := replayPlatformDial(c.fake)(context.Background(), "tcp", c.address)
		if conn != nil {
			_ = conn.Close()
		}
		if (err == nil) != c.dials {
			t.Errorf("fake %q, %s: dialed %v (%v), want %v", c.fake, c.address, err == nil, err, c.dials)
		}
	}
}

// versionLine is the TypeScript CLI's --version: `varlatch <version>
// (migration <n>)`.
var versionLine = regexp.MustCompile(`^varlatch \S+ \(migration \d+\)\n$`)

// differences are the Go CLI's accepted differences (go/README.md), by the
// name a recorded case gives.
var differences = map[string]transcript.Difference{
	// On Windows both CLIs walk the skill directories in NTFS's order, not
	// the sorted order a Linux recording holds. For a case replayed on
	// Windows against its Linux recording (no Windows expectation), Go's
	// stdout is accepted where the two are the same with each run of
	// skill-file entries sorted (transcript.SkillOrderFree): nothing added
	// or dropped, everything else in place. A Windows-recorded case is
	// compared exactly.
	"skill-order": func(want *transcript.Outcome, got transcript.Outcome) {
		if transcript.SkillOrderFree(want.Stdout) == transcript.SkillOrderFree(got.Stdout) {
			want.Stdout = got.Stdout
		}
	},
	// Decision 6: `varlatch <version>`, without the migration number.
	"version": func(o *transcript.Outcome, _ transcript.Outcome) {
		if versionLine.MatchString(o.Stdout) {
			o.Stdout = "varlatch " + buildinfo.Version + "\n"
		}
	},
	// The User-Agent names the CLI's own version and the platform it runs
	// on: the recording's, made by TypeScript 0.22.0 on the recorder's
	// machine, becomes this build's, on this machine, with the same
	// assisted token (decision 2: the format is kept, the values are the
	// running CLI's).
	"user-agent": func(o *transcript.Outcome, _ transcript.Outcome) {
		for i := range o.Requests {
			ua, ok := o.Requests[i].Headers["user-agent"]
			if !ok {
				continue
			}
			m := recordedUserAgent.FindStringSubmatch(ua)
			if m == nil {
				continue
			}
			headers := map[string]string{}
			for k, v := range o.Requests[i].Headers {
				headers[k] = v
			}
			headers["user-agent"] = cli.FormatUserAgent(buildinfo.Version, m[2] != "", cli.NodePlatform(), cli.NodeArch())
			if m[1] == "mcp" {
				// `varlatch mcp`'s own (run.ts's mcpUserAgent), which has no assisted token.
				headers["user-agent"] = cli.FormatMCPUserAgent(buildinfo.Version, cli.NodePlatform(), cli.NodeArch())
			}
			o.Requests[i].Headers = headers
		}
	},
	// `varlatch mcp` reports its own version to the MCP host (initialize's
	// serverInfo): the recording's TypeScript version becomes this build's,
	// as the User-Agent's does.
	"mcp-version": func(o *transcript.Outcome, _ transcript.Outcome) {
		o.Stdout = mcpServerInfo.ReplaceAllString(o.Stdout, `${1}"`+buildinfo.Version+`"`)
	},
	// The skill files `agents install` writes name the CLI that wrote them
	// (SKILL.md's metadata, each reference's first line): the recording's
	// TypeScript version becomes this build's. TestTranscripts does the
	// same to the case's inputs, so files installed "by this CLI" are.
	"skill-version": func(o *transcript.Outcome, _ transcript.Outcome) {
		files := map[string]transcript.FileState{}
		for path, f := range o.Files {
			f.Content = withSkillVersion(path, f.Content)
			files[path] = f
		}
		o.Files = files
	},
	// init writes each value of varlatch.toml as an escaped TOML basic
	// string, so the file reads back as what was given; the TypeScript CLI
	// writes the value verbatim between quotes. The recording's lines
	// become the escaped form of the same values.
	"toml-escaped": func(o *transcript.Outcome, _ transcript.Outcome) {
		files := map[string]transcript.FileState{}
		for path, f := range o.Files {
			if strings.HasSuffix(path, "varlatch.toml") {
				lines := strings.Split(f.Content, "\n")
				for i, line := range lines {
					if m := verbatimTOMLLine.FindStringSubmatch(line); m != nil {
						lines[i] = m[1] + " = " + cli.TOMLString(m[2])
					}
				}
				f.Content = strings.Join(lines, "\n")
			}
			files[path] = f
		}
		o.Files = files
	},
	// An unknown option given with its value attached (`--name=value`,
	// `-Xvalue`): the TypeScript CLI echoes the value, the Go CLI shows it
	// as [redacted] (go/README.md, "Diagnostics never print credential
	// values"). The rest of stderr, the status and stdout are compared as
	// recorded.
	"option-value": func(o *transcript.Outcome, _ transcript.Outcome) {
		o.Stderr = cli.OptionValueDifference(o.Stderr)
	},
	// `varlatch help admin` (and `admin --help`, `admin -h`) prints the
	// admin forms of a Go installation, which the Go CLI runs through
	// varlatchd; the TypeScript usage is a Compose installation's (slice
	// 6.2a). The recording's usage becomes the Go one.
	"admin-usage": func(o *transcript.Outcome, _ transcript.Outcome) {
		if strings.HasPrefix(o.Stdout, "Usage:\n  varlatch admin ") {
			o.Stdout = cli.AdminHelp + "\n"
		}
	},
	// `varlatch help doctor` (and `doctor --help`, `doctor -h`) prints a
	// Go installation's doctor, which varlatchd runs; the TypeScript usage
	// is a Compose installation's (slice 6.5).
	"doctor-usage": func(o *transcript.Outcome, _ transcript.Outcome) {
		if strings.HasPrefix(o.Stdout, "Usage:\n  varlatch doctor ") {
			o.Stdout = cli.DoctorHelp + "\n"
		}
	},
	// `varlatch help move` (and `move --help`, `move -h`) prints a Go
	// installation's move (slice 6.9); the TypeScript usage is a Compose
	// installation's. The recording's usage becomes the Go one.
	"move-usage": func(o *transcript.Outcome, _ transcript.Outcome) {
		if strings.HasPrefix(o.Stdout, "Usage:\n  varlatch move ") {
			o.Stdout = cli.MoveHelp + "\n"
		}
	},
	// `varlatch help self-update` (and `self-update --help`, `-h`) prints
	// the Go CLI's forms: it replaces a native binary, always checks the
	// signature, and takes --prerelease and --allow-downgrade (slice 6.7a).
	// The recording's usage becomes the Go one.
	"self-update-usage": func(o *transcript.Outcome, _ transcript.Outcome) {
		if strings.HasPrefix(o.Stdout, "Usage:\n  varlatch self-update ") {
			o.Stdout = cli.SelfUpdateHelp + "\n"
		}
	},
	// A --json document's fields the API defines as scalars: an object or
	// array a server sent there is left out by the Go CLI (go/README.md,
	// "--json documents hold only scalars where the API defines them"), so
	// the recording's document is compared with those values removed:
	// env list's name, tier and kind, and status --probe's identity and
	// organization fields.
	"json-scalars": func(o *transcript.Outcome, _ transcript.Outcome) {
		doc, err := jsjson.Parse([]byte(o.Stdout))
		top, isObject := doc.(jsjson.Object)
		if err != nil || !isObject {
			return
		}
		if list, ok := top.Value("environments").([]any); ok {
			out := make([]any, len(list))
			for i, e := range list {
				out[i] = withoutNonScalars(e, "name", "tier", "kind")
			}
			top = top.Set("environments", out)
		}
		if list, ok := top.Value("servers").([]any); ok {
			out := make([]any, len(list))
			for i, srv := range list {
				out[i] = srv
				s, ok := srv.(jsjson.Object)
				if !ok {
					continue
				}
				p, ok := s.Value("probe").(jsjson.Object)
				if !ok {
					continue
				}
				if _, has := p.Get("identity"); has {
					p = p.Set("identity", withoutNonScalars(p.Value("identity"), "id", "name", "kind"))
				}
				if _, has := p.Get("organization"); has {
					p = p.Set("organization", withoutNonScalars(p.Value("organization"), "id", "slug", "name"))
				}
				out[i] = s.Set("probe", p)
			}
			top = top.Set("servers", out)
		}
		o.Stdout = string(jsjson.StringifyIndent(top, 2)) + "\n"
	},
	// An error the TypeScript CLI lets escape (recorded as {{uncaught ...}}):
	// Node.js prints a stack and exits 1; the Go CLI exits 1 too, with one
	// line saying what went wrong. Only that stderr is accepted; the status
	// and everything else are compared as recorded.
	// A command `run` cannot start: TypeScript lets Node's error escape
	// (its stack), Go prints Node's own message, `spawn <command> <code>`.
	// Accepted only where Go says exactly the recorded error.
	"spawn-error": func(o *transcript.Outcome, got transcript.Outcome) {
		if m := recordedSpawnError.FindStringSubmatch(o.Stderr); m != nil && o.Status == 1 && got.Stderr == "varlatch: "+m[1]+"\n" {
			o.Stderr = got.Stderr
		}
	},
	"uncaught": func(o *transcript.Outcome, got transcript.Outcome) {
		if strings.HasPrefix(o.Stderr, "{{uncaught") && o.Status == 1 && goFailure.MatchString(got.Stderr) {
			o.Stderr = got.Stderr
		}
	},
	// Every server URL the Go CLI shows goes through clientctx.DisplayServer
	// (go/README.md, "server-display"): its scheme, host and port, and its
	// path when allow-listed, with markers for what it leaves out, and
	// "[unrecognised server URL]" for a value it cannot read as a URL.
	// TypeScript shows the value with its user name and password masked.
	// Accepted only where Go's stdout and stderr are the recording with each
	// fixture server, where TypeScript shows it, shown through DisplayServer
	// instead (serverDisplayFixtures).
	// The browser sign-in's loopback callback: Go's has a random path
	// (internal/cli's callbackNonce), so only a POST to exactly it is the
	// sign-in's; TypeScript's is "/". Accepted only where Go's stdout, with
	// that path taken out of the printed address, is the recording.
	"loopback-nonce": func(o *transcript.Outcome, got transcript.Outcome) {
		if shown := loopbackNonce.ReplaceAllString(got.Stdout, "${1}"); shown == o.Stdout {
			o.Stdout = got.Stdout
		}
	},
	"server-display": func(o *transcript.Outcome, got transcript.Outcome) {
		stdout, stderr := o.Stdout, o.Stderr
		for _, f := range serverDisplayFixtures {
			shown := make([]any, len(f.raw))
			for i, raw := range f.raw {
				shown[i] = clientctx.DisplayServer(raw)
			}
			goText := fmt.Sprintf(f.goText, shown...)
			stdout = strings.ReplaceAll(stdout, f.recorded, goText)
			stderr = strings.ReplaceAll(stderr, f.recorded, goText)
		}
		if stdout == got.Stdout && stderr == got.Stderr {
			o.Stdout, o.Stderr = got.Stdout, got.Stderr
		}
	},
	// `values set` and `values rotate` never repeat an argument they
	// refuse, whatever its spelling: it may be the value or part of it
	// (go/README.md, "No message holds a value"). The message names its
	// place among the command's arguments instead. Accepted only where Go's
	// first line of stderr is the refusal's own words for the same command
	// and holds no part of the refused argument, and every other line,
	// the status and stdout are as recorded.
	"value-free-usage": func(o *transcript.Outcome, got transcript.Outcome) {
		wantFirst, wantRest, _ := strings.Cut(o.Stderr, "\n")
		gotFirst, gotRest, _ := strings.Cut(got.Stderr, "\n")
		if wantRest != gotRest {
			return
		}
		for _, form := range valueFreeForms {
			m := form.ts.FindStringSubmatch(wantFirst)
			if m == nil {
				continue
			}
			argument := ""
			for _, part := range m[2:] {
				if part != "" {
					argument = part
				}
			}
			g := form.goWords.FindStringSubmatch(gotFirst)
			if g != nil && g[1] == m[1] && argument != "" && !strings.Contains(got.Stderr, argument) {
				o.Stderr = got.Stderr
			}
			return
		}
	},
	// The .env.schema parser never quotes the file in an error (a file given
	// as --schema by mistake may be a .env holding values; go/README.md, "No
	// message holds a value"): the package repeats part of the line it cannot
	// read. And a reason holding a decorator ("@rotationGrace") is put
	// before the line's place, so the fail-safe never reads the colon and the
	// at-sign as a password. Accepted only where Go's stderr is the
	// recording as envschema.GoWording words it, and holds no part of a
	// quoted fragment.
	"env-schema-value-free": func(o *transcript.Outcome, got transcript.Outcome) {
		first, rest, _ := strings.Cut(o.Stderr, "\n")
		accepted := envschema.GoWording(first) + "\n" + rest
		if q := schemaFragment.FindStringSubmatch(o.Stderr); q != nil && strings.Contains(got.Stderr, strings.TrimSpace(q[2])) {
			return // the quoted fragment must be gone
		}
		if got.Stderr == accepted {
			o.Stderr = accepted
		}
	},

	// A server's identifier that does not have the server's shape (a
	// prefix and 26 characters of lower-case base32) is shown as "an
	// unrecognized id" (go/README.md, "No message holds a value").
	"unrecognized-id": func(o *transcript.Outcome, got transcript.Outcome) {
		if m := recordedVersion.FindStringSubmatchIndex(o.Stdout); m != nil {
			if accepted := o.Stdout[:m[2]] + cli.UnrecognizedID + o.Stdout[m[3]:]; accepted == got.Stdout {
				o.Stdout = accepted
			}
		}
		// `contract activate` repeats only an id of the server's shape.
		if recordedActivation.MatchString(o.Stdout) && got.Stdout == "Activated the revision.\n" {
			o.Stdout = got.Stdout
		}
		// `types` names a revision, the server's or --revision's, only by
		// an id of the server's shape, and its --check hint repeats only
		// such a --revision.
		unshaped := func(text string) string {
			text = recordedRevisionName.ReplaceAllStringFunc(text, func(m string) string {
				if id := strings.TrimPrefix(m, "Contract Revision "); !revisionShape.MatchString(id) {
					return "Contract Revision " + cli.UnrecognizedID
				}
				return m
			})
			return recordedRevisionHint.ReplaceAllStringFunc(text, func(m string) string {
				if id := strings.TrimSuffix(strings.TrimPrefix(m, " --revision "), ".\n"); !revisionShape.MatchString(id) {
					return " --revision <revision-id>.\n"
				}
				return m
			})
		}
		if accepted := unshaped(o.Stdout); accepted == got.Stdout {
			o.Stdout = accepted
		}
		if accepted := unshaped(o.Stderr); accepted == got.Stderr {
			o.Stderr = accepted
		}
	},
	// `types` shows a semantics version only as a whole number from 1 to
	// 999 (else "an unrecognized version"), and escapes the control
	// characters and bidirectional overrides of a refusal that quotes the
	// server's answer (go/README.md, "types shows the server's text
	// safely"). Accepted only where Go's stderr is the recorded one with
	// exactly that done.
	"types-printable": func(o *transcript.Outcome, got transcript.Outcome) {
		message, ok := strings.CutSuffix(o.Stderr, "\n")
		if !ok {
			return
		}
		if m := recordedSemanticsVersion.FindStringSubmatchIndex(message); m != nil && !wholeVersion.MatchString(message[m[2]:m[3]]) {
			message = message[:m[2]] + cli.UnrecognizedVersion + message[m[3]:]
		}
		if accepted := cli.Printable(message) + "\n"; accepted == got.Stderr {
			o.Stderr = accepted
		}
	},
	// A Coolify service's compose file with an alias inside its own anchor
	// (step 4 defect 6; go/README.md, "compose-usage-unchecked"): the
	// TypeScript adapter overflows its stack and sync check dies; lib/sync
	// reads the file as unreadable, so Go reports the service's usage
	// unchecked and finishes the comparison, disclosing the Secrets it
	// compares as any check does. Accepted only where the recording is that
	// RangeError, Go's stderr says usage was not checked for that reason,
	// Go's stdout ends with a verdict, and Go's requests are the recorded
	// ones and one disclosure.
	"compose-usage-unchecked": func(o *transcript.Outcome, got transcript.Outcome) {
		if o.Status != 1 || o.Stdout != "" || o.Stderr != "{{uncaught RangeError: Maximum call stack size exceeded}}\n" {
			return
		}
		if !strings.Contains(got.Stderr, "varlatch: usage: usage not checked: the service's compose file is too large or could not be read\n") ||
			!composeVerdict.MatchString(got.Stdout) || len(got.Requests) != len(o.Requests)+1 {
			return
		}
		for i, r := range o.Requests {
			if got.Requests[i].Method != r.Method || got.Requests[i].Path != r.Path {
				return
			}
		}
		if extra := got.Requests[len(o.Requests)]; extra.Method != "POST" || !strings.HasSuffix(extra.Path, "/disclosures") {
			return
		}
		o.Status, o.Stdout, o.Stderr, o.Requests = got.Status, got.Stdout, got.Stderr, got.Requests
	},
	// `contract show` shows a sensitive item's default as [redacted]
	// (go/README.md, "No message holds a value"). Accepted only where Go's
	// stdout is the recorded document with exactly those defaults replaced.
	"contract-show-sensitive-default": func(o *transcript.Outcome, got transcript.Outcome) {
		doc, err := jsjson.Parse([]byte(o.Stdout))
		if err != nil {
			return
		}
		if accepted := string(jsjson.StringifyIndent(cli.ContractShowView(doc), 2)) + "\n"; accepted == got.Stdout {
			o.Stdout = accepted
		}
	},
}

// schemaFragment is a packages/env-schema error that quotes the file: the
// message and the quoted fragment.
var schemaFragment = regexp.MustCompile(`(?s)^(\.env\.schema line [0-9]+: (?:Unrecognized line|Unexpected text after the value|Malformed decorator|Unsupported @required form|Unsupported @sensitive form|Unsupported @type)): (.*)\n$`)

// composeVerdict is sync check's last line: its verdict and tally.
var composeVerdict = regexp.MustCompile(`\n(in sync|DRIFT|INCOMPLETE): [0-9]+ match, [0-9]+ differ, [0-9]+ missing on the platform, [0-9]+ extra on the platform, [0-9]+ not compared\n$`)

// recordedActivation is a recorded `contract activate` success.
var recordedActivation = regexp.MustCompile(`^Activated .+\.\n$`)

// recordedSpawnError is a recorded spawn failure, as the recorder keeps an
// error that escaped.
var recordedSpawnError = regexp.MustCompile(`^\{\{uncaught Error: (spawn \S+ [A-Z]+)\}\}\n$`)

// recordedRevisionName is a revision `types` names; recordedRevisionHint is
// the --revision its --check hint repeats; revisionShape is the server's
// revision ids' shape.
var (
	recordedRevisionName = regexp.MustCompile(`Contract Revision [A-Za-z0-9_-]+`)
	recordedRevisionHint = regexp.MustCompile(` --revision \S+\.\n$`)
	revisionShape        = regexp.MustCompile(`^rev_[a-z2-7]{26}$`)
)

// recordedSemanticsVersion is the version a recorded `types` refusal
// names; wholeVersion is one Go shows as it is.
var (
	recordedSemanticsVersion = regexp.MustCompile(`(?s)uses Contract Semantics version (.*?), which this CLI does not implement`)
	wholeVersion             = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)
)

// recordedVersion is the version a recorded `values set` names.
var recordedVersion = regexp.MustCompile(` set \(version (.*)\)\.\n$`)

// valueFreeForms are the refusals `values set` and `values rotate` word
// without the argument: the TypeScript words (the command, the argument)
// and the Go words (the command).
var valueFreeForms = []struct{ ts, goWords *regexp.Regexp }{
	{
		regexp.MustCompile(`^varlatch (values set|values rotate): (?:unknown option (\S+)(?: \(a value that begins with "-" goes after --\))?|(\S+): unknown option.*)$`),
		regexp.MustCompile(`^varlatch (values set|values rotate): unknown option at argument [0-9]+, not shown since it may be a value \(a value that begins with "-" goes after --\)$`),
	},
	{
		regexp.MustCompile(`^varlatch (values set|values rotate): (?:unexpected argument (\S+)|(\S+): unexpected argument)$`),
		regexp.MustCompile(`^varlatch (values set|values rotate): unexpected argument [0-9]+, not shown since it may be part of a value \(a value with spaces goes in quotes\)$`),
	},
	{
		regexp.MustCompile(`^varlatch (values set|values rotate): --replace names (\S+), but this command (?:sets|rotates) \S+; approval for one item never covers another\.$`),
		regexp.MustCompile(`^varlatch (values set|values rotate): --replace names another item, but this command (?:sets|rotates) \S+; approval for one item never covers another\.$`),
	},
	{
		regexp.MustCompile(`^varlatch (values rotate): --grace needs a whole number of seconds, not (.+)$`),
		regexp.MustCompile(`^varlatch (values rotate): --grace needs a whole number of seconds$`),
	},
}

// withoutNonScalars is v without the named members whose value is an
// object or an array, when v is an object; anything else as it is.
func withoutNonScalars(v any, keys ...string) any {
	o, ok := v.(jsjson.Object)
	if !ok {
		return v
	}
	out := jsjson.Object{}
	for _, m := range o {
		switch m.Value.(type) {
		case jsjson.Object, []any:
			if slices.Contains(keys, m.Key) {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// skillVersion is the version a skill file names.
var skillVersion = regexp.MustCompile(`(generator: varlatch |<!-- Generated by varlatch )[0-9A-Za-z.+-]+`)

// withSkillVersion is a skill file's content naming this build's version.
func withSkillVersion(path, content string) string {
	if !strings.Contains(path, "skills/varlatch/") {
		return content
	}
	return skillVersion.ReplaceAllString(content, "${1}"+buildinfo.Version)
}

// serverDisplayFixtures are the servers of the server-display cases: the
// text that shows them in the TypeScript recording, and the same text with
// each server (raw, as the case stores or gives it) shown through
// DisplayServer (goText, a format with one %[n]s per server).
var serverDisplayFixtures = []struct {
	recorded, goText string
	raw              []string
}{
	{`"server": "0",`, `"server": "%[1]s",`, []string{"0"}},
	{`"server": "1",`, `"server": "%[1]s",`, []string{"1"}},
	{`"server": "https://a.example/\ud800",`, `"server": "%[1]s",`, []string{"https://a.example/\uFFFD"}},
	{"https://a.example/\uFFFD  (", "%[1]s  (", []string{"https://a.example/\uFFFD"}},
	{`"url": "x"`, `"url": "%[1]s"`, []string{"x"}},
	{`"https://[redacted]@segment"`, `"%[1]s"`, []string{`https://example.com\path@segment`}},
	{"not a URL: b.example\n", "not a URL: %[1]s\n", []string{"b.example"}},
	{"\"a\",\n    \"b\"\n", "\"%[1]s\",\n    \"%[2]s\"\n", []string{"a", "b"}},
	{"Server        a,b\n", "Server        %[1]s,%[2]s\n", []string{"a", "b"}},
	{`"server": "not a url",`, `"server": "%[1]s",`, []string{"not a url"}},
	{`"detail": "Failed to parse URL from not a url/v1/meta"`, `"detail": "Failed to parse URL from %[1]s"`, []string{"not a url/v1/meta"}},
	{"for https://x.example/p q. Commit", "for %[1]s. Commit", []string{"https://x.example/p q"}},
	{"not authenticated to http://[redacted]@127.0.0.1:9;", "not authenticated to %[1]s;", []string{"http://user:pw-canary@127.0.0.1:9"}},
	{"login: varlatch.example.com is not a URL", "login: %[1]s is not a URL", []string{"varlatch.example.com"}},
}

// verbatimTOMLLine is a line init writes, `key = "<value as given>"`.
var verbatimTOMLLine = regexp.MustCompile(`^([a-z_]+) = "(.*)"$`)

// mcpServerInfo is the serverInfo an MCP initialize answer names.
var mcpServerInfo = regexp.MustCompile(`("serverInfo":\{"name":"varlatch","version":)"[^"]*"`)

// recordedUserAgent is the TypeScript CLI's User-Agent in a recording.
var recordedUserAgent = regexp.MustCompile(`^varlatch-(cli|mcp)/[0-9A-Za-z.+-]+ \([a-z0-9]+; [a-z0-9]+(; assisted)?\)$`)

// loopbackNonce is the Go callback's random path in a printed sign-in
// address, the port already a pattern.
var loopbackNonce = regexp.MustCompile(`(callback=http%3A%2F%2F127\.0\.0\.1%3A\{\{port\}\}%2F)[A-Za-z0-9_-]{32}`)

// goFailure is one line of the Go CLI's own failure.
var goFailure = regexp.MustCompile(`^varlatch: [^\n]+\n$`)

// transcriptParallelism bounds how many cases replay at once: each case
// runs the CLI as a process (this test binary, race-instrumented under
// -race), so the bound keeps memory sane on a hosted runner while the cases
// no longer run one after another.
const transcriptParallelism = 4

// TestTranscripts replays every recorded case (testdata/transcripts). The
// cases run in parallel, at most transcriptParallelism at once: each has
// its own directory, fake server and environment (transcript.Replay gives
// the child its environment explicitly), and nothing here is shared but
// read-only tables, so no case can see another.
func TestTranscripts(t *testing.T) {
	files, err := filepath.Glob("testdata/transcripts/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no transcripts: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(args []string) *exec.Cmd { return exec.Command(exe, args...) }
	var windows map[string]map[string]transcript.Outcome
	if runtime.GOOS == "windows" {
		windows = windowsExpectations(t)
	}
	slots := make(chan struct{}, transcriptParallelism)
	for _, path := range files {
		f, err := transcript.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			t.Run(f.Area+"/"+c.ID, func(t *testing.T) {
				// On Windows, a case whose outcome names a path below its
				// directory is compared with TypeScript's Windows recording
				// (testdata/transcripts/windows), since both CLIs join such
				// paths with backslashes there. Every other case replays
				// against its Linux recording, the directory inside a JSON
				// string included (transcript.UnfillDir).
				if runtime.GOOS == "windows" {
					if expectsPath(t, c) {
						w, ok := windows[f.Area][c.ID]
						if !ok {
							t.Fatal("no Windows expectation: record one (apps/cli/test/goWindows.ts)")
						}
						c.Expect = w
					} else {
						c.Differences = append(slices.Clone(c.Differences), "skill-order")
					}
				}
				t.Parallel()
				slots <- struct{}{}
				defer func() { <-slots }()
				c.Env = withMarker(c.Env)
				if slices.Contains(c.Differences, "skill-version") {
					files := map[string]string{}
					for path, content := range c.Files {
						files[path] = withSkillVersion(path, content)
					}
					c.Files = files
				}
				_, problems, err := transcript.Replay(c, start, differences)
				if errors.Is(err, transcript.ErrUnsupported) {
					t.Skip(err)
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(problems) > 0 {
					t.Errorf("%s (%s):\n%s", c.ID, c.Title, strings.Join(problems, "\n"))
				}
			})
		}
	}
}

// expectsPath reports whether a case's recorded outcome names a path below
// its directory: the directory's placeholder followed by a separator
// (pathBelowDir). TypeScript recorded it on Linux; on Windows both CLIs
// join such a path with backslashes, so such a case has a Windows
// recording too (apps/cli/test/goWindows.ts). Every other case, the
// directory itself named alone included, replays its Linux recording on
// every platform.
func expectsPath(t *testing.T, c transcript.Case) bool {
	t.Helper()
	b, err := json.Marshal(c.Expect)
	if err != nil {
		t.Fatal(err)
	}
	return pathBelowDir.Match(b)
}

// pathBelowDir matches a path below a placeholder directory. {{dir}} is the
// only one the recorder writes today; {{home}} is matched too, so a
// recorder that adds it is covered.
var pathBelowDir = regexp.MustCompile(`\{\{(dir|home)\}\}[/\\]`)

// windowsFile is the Windows expectations of an area (goWindows.ts):
// each case that names a path below its directory, as TypeScript did it on
// Windows.
type windowsFile struct {
	Schema   int    `json:"schema"`
	Area     string `json:"area"`
	Platform string `json:"platform"`
	Cases    []struct {
		ID     string             `json:"id"`
		Expect transcript.Outcome `json:"expect"`
	} `json:"cases"`
}

// windowsExpectations is every area's Windows expectations, by area and
// case id.
func windowsExpectations(t *testing.T) map[string]map[string]transcript.Outcome {
	t.Helper()
	files, err := filepath.Glob("testdata/transcripts/windows/*.json")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]transcript.Outcome{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var w windowsFile
		if err := json.Unmarshal(data, &w); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if w.Platform != "windows" || w.Schema != transcript.Schema || filepath.Base(path) != w.Area+".json" {
			t.Fatalf("%s: platform %q, schema %d, area %q", path, w.Platform, w.Schema, w.Area)
		}
		out[w.Area] = map[string]transcript.Outcome{}
		for _, c := range w.Cases {
			out[w.Area][c.ID] = c.Expect
		}
	}
	return out
}

// TestWindowsExpectationsComplete: each area's Windows recording holds
// exactly the cases whose Linux recording names a path below their
// directory (the same set of ids), and no area without one has a file.
// Checked on every platform, so a case that needs a Windows expectation and
// has none fails before Windows runs it.
func TestWindowsExpectationsComplete(t *testing.T) {
	files, err := filepath.Glob("testdata/transcripts/*.json")
	if err != nil {
		t.Fatal(err)
	}
	windows := windowsExpectations(t)
	for _, path := range files {
		f, err := transcript.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		var needed []string
		for _, c := range f.Cases {
			if expectsPath(t, c) {
				needed = append(needed, c.ID)
			}
		}
		have := windows[f.Area]
		delete(windows, f.Area)
		for _, id := range needed {
			if _, ok := have[id]; !ok {
				t.Errorf("%s/%s names a path and has no Windows expectation: record one (apps/cli/test/goWindows.ts)", f.Area, id)
			}
		}
		for id := range have {
			if !slices.Contains(needed, id) {
				t.Errorf("windows/%s.json holds %s, which names no path below its directory: record again (apps/cli/test/goWindows.ts)", f.Area, id)
			}
		}
	}
	for area := range windows {
		t.Errorf("windows/%s.json is for an area with no recording", area)
	}
}

func withMarker(env map[string]string) map[string]string {
	out := map[string]string{asCLI: "1"}
	for k, v := range env {
		out[k] = v
	}
	return out
}

// TestServerDisplayDifferenceIsExact: server-display accepts Go's output
// only where it is the recording with the fixture server shown through
// DisplayServer; the raw value, the TypeScript form, another server or any
// other change fails.
func TestServerDisplayDifferenceIsExact(t *testing.T) {
	recorded := `{"server": "https://[redacted]@segment"}` + "\n"
	for got, accepted := range map[string]bool{
		`{"server": "[unrecognised server URL]"}` + "\n":         true,
		`{"server": "https://example.com\\path@segment"}` + "\n": false,
		`{"server": "https://example.com/[redacted]"}` + "\n":    false,
		`{"server": "[unrecognised server URL]", "x": 1}` + "\n": false,
	} {
		want := transcript.Outcome{Stdout: recorded}
		differences["server-display"](&want, transcript.Outcome{Stdout: got})
		if (want.Stdout == got) != accepted {
			t.Errorf("%q: accepted %v, want %v", got, want.Stdout == got, accepted)
		}
	}
	// On stderr too, and both streams must match.
	want := transcript.Outcome{Stderr: "varlatch server use: not a URL: b.example\n"}
	differences["server-display"](&want, transcript.Outcome{Stderr: "varlatch server use: not a URL: b.example\n", Stdout: "x"})
	if want.Stdout == "x" {
		t.Error("accepted a stdout the recording does not have")
	}
}

// TestWindowsExpectationsAreNarrow: only a recorded outcome that names a
// path below the case's directory has a Windows expectation; the directory
// alone, or any other placeholder, replays its Linux recording.
func TestWindowsExpectationsAreNarrow(t *testing.T) {
	for text, needed := range map[string]bool{
		`"repoRoot": "{{dir}}/repo"`:                                true,
		`"root": "{{dir}}\\project"`:                                true,
		`"home": "{{home}}/.config"`:                                true,
		`outside {{dir}}, so nothing`:                               false,
		`"root": "{{dir}}"`:                                         false,
		`{"offline": "No varlatch.toml found from {{dir}} upward"}`: false,
		`{{server}}/v1/whoami`:                                      false,
		`{{skill}}/SKILL.md`:                                        false,
	} {
		if got := pathBelowDir.MatchString(text); got != needed {
			t.Errorf("%s: needs a Windows expectation %v, want %v", text, got, needed)
		}
	}
}

// TestValueFreeUsageIsExact: value-free-usage accepts only Go's own words
// for the same refusal, never a message that holds the argument.
func TestValueFreeUsageIsExact(t *testing.T) {
	const usage = "\nUsage: varlatch values set <ITEM>\n"
	recorded := `varlatch values set: unknown option -s3cr3t (a value that begins with "-" goes after --)` + usage
	for got, accepted := range map[string]bool{
		`varlatch values set: unknown option at argument 2, not shown since it may be a value (a value that begins with "-" goes after --)` + usage:    true,
		`varlatch values rotate: unknown option at argument 2, not shown since it may be a value (a value that begins with "-" goes after --)` + usage: false,
		`varlatch values set: unknown option at argument 2, not shown since it may be a value -s3cr3t` + usage:                                         false,
		`varlatch values set: unknown option at argument 2, not shown since it may be a value (a value that begins with "-" goes after --)` + "\n":     false,
	} {
		want := transcript.Outcome{Stderr: recorded}
		differences["value-free-usage"](&want, transcript.Outcome{Stderr: got})
		if (want.Stderr == got) != accepted {
			t.Errorf("%q: accepted %v, want %v", got, want.Stderr == got, accepted)
		}
	}
}

// TestComposeUsageUncheckedIsExact: compose-usage-unchecked accepts only
// Go's finished check with usage unchecked for its fixed reason, a verdict
// and one more request, the disclosure; never against another recording.
func TestComposeUsageUncheckedIsExact(t *testing.T) {
	read := transcript.Request{Method: "GET", Path: "/v1/organizations/acme/projects/web/environments/dev/effective-configuration?include=values"}
	disclose := transcript.Request{Method: "POST", Path: "/v1/organizations/acme/projects/web/environments/dev/disclosures"}
	recorded := transcript.Outcome{Status: 1, Stderr: "{{uncaught RangeError: Maximum call stack size exceeded}}\n", Requests: []transcript.Request{read}}
	stderr := "varlatch: no active Contract: x\nvarlatch: usage: usage not checked: the service's compose file is too large or could not be read\n"
	stdout := "coolify https://coolify.conformance.test svc-uuid-0001 against dev:\n  match  API_TOKEN\nin sync: 1 match, 0 differ, 0 missing on the platform, 0 extra on the platform, 0 not compared\n"
	good := transcript.Outcome{Status: 0, Stdout: stdout, Stderr: stderr, Requests: []transcript.Request{read, disclose}}
	for _, c := range []struct {
		name     string
		got      transcript.Outcome
		accepted bool
	}{
		{"usage unchecked, a verdict, the disclosure", good, true},
		{"usage checked", transcript.Outcome{Status: 0, Stdout: stdout, Stderr: "varlatch: no active Contract: x\n", Requests: good.Requests}, false},
		{"no verdict", transcript.Outcome{Status: 1, Stdout: "", Stderr: stderr, Requests: good.Requests}, false},
		{"another request", transcript.Outcome{Status: 0, Stdout: stdout, Stderr: stderr, Requests: []transcript.Request{read, {Method: "POST", Path: "/v1/other"}}}, false},
		{"two more requests", transcript.Outcome{Status: 0, Stdout: stdout, Stderr: stderr, Requests: []transcript.Request{read, disclose, disclose}}, false},
	} {
		want := recorded
		differences["compose-usage-unchecked"](&want, c.got)
		if accepted := want.Stdout == c.got.Stdout && want.Stderr == c.got.Stderr && len(want.Requests) == len(c.got.Requests); accepted != c.accepted {
			t.Errorf("%s: accepted %v, want %v", c.name, accepted, c.accepted)
		}
	}
	other := transcript.Outcome{Status: 1, Stderr: "{{uncaught TypeError: x}}\n", Requests: []transcript.Request{read}}
	differences["compose-usage-unchecked"](&other, good)
	if other.Stdout == good.Stdout {
		t.Error("accepted against a recording of another error")
	}
}
