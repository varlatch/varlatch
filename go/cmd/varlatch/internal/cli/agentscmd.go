// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/agents"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/toml"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The commands of slice 5.1d (internal docs/design/go-cli.md): `agents
// guide`, `agents install` with every option, and `init` with its flags
// off a terminal, ported from apps/cli/src/main.ts over internal/agents.
// `agents hook` is slice 5.6a; `init` on a terminal (guided) is 5.8a.

const agentsUsage = "Usage: varlatch agents <guide [topic]|install [--scope project|user] [--agent <name>]... [--guardrails] [--mcp] [--check|--remove] [--json]" +
	"|hook --format <claude|codex>>"

// agentsCommand is `varlatch agents` (ADR-0043 Decision 7): the
// agent-neutral skill, printed or installed.
func agentsCommand(r *Run) error {
	sub, rest := "", []string{}
	if len(r.Args) > 0 {
		sub, rest = r.Args[0], r.Args[1:]
	}
	switch sub {
	case "guide":
		opts, err := strictOptions("agents guide", rest, OptionSpec{Positionals: 1}, agentsUsage)
		if err != nil {
			return err
		}
		topic, given := "", len(opts.Positionals) > 0
		if given {
			topic = opts.Positionals[0]
		}
		text, err := agents.Guide(topic, given)
		var guideErr *agents.GuideTopicError
		if errors.As(err, &guideErr) {
			// The topic, as echoed, is masked as one value; one holding an
			// at-sign comes before its explanation (the fail-safe keeps what
			// follows the last at-sign).
			shown := shownArgument(guideErr.Topic)
			topics := "; topics: " + strings.Join(guideErr.Topics, ", ")
			if clientctx.HasAtSign(shown) {
				return UsageError("varlatch agents guide: " + shown + ": no such guide topic" + topics)
			}
			return UsageError("varlatch agents guide: no guide topic " + shown + topics)
		}
		return r.out(text)
	case "hook":
		return UsageError("varlatch agents hook: not in this build of the Go CLI yet (slice 5.6a); use the TypeScript CLI for it until then")
	case "install":
		return r.agentsInstall(rest)
	}
	return UsageError(agentsUsage)
}

func (r *Run) agentsInstall(args []string) error {
	opts, err := strictOptions("agents install", args, OptionSpec{
		Values:   []string{"--scope"},
		Lists:    []string{"--agent"},
		Booleans: []string{"--check", "--remove", "--json", "--guardrails", "--mcp"},
	}, agentsUsage)
	if err != nil {
		return err
	}
	if opts.Has("--check") && opts.Has("--remove") {
		return UsageError("varlatch agents install: --check and --remove do not combine")
	}
	scope, ok := opts.Value("--scope")
	if !ok {
		scope = "project"
	}
	if scope != "project" && scope != "user" {
		return UsageError("varlatch agents install: --scope must be project or user")
	}
	mode := "install"
	if opts.Has("--check") {
		mode = "check"
	} else if opts.Has("--remove") {
		mode = "remove"
	}
	var root string
	if scope == "user" {
		// The home directory as the credential store finds it (5.1b).
		if root, err = clientctx.HomeDir(r.Env); err != nil {
			return err
		}
	} else {
		cwd, err := Cwd()
		if err != nil {
			return err
		}
		if root = clientctx.FindRepoRoot(cwd); root == "" {
			root = cwd
		}
	}
	result, err := agents.RunInstall(agents.Options{
		Scope:      scope,
		Root:       root,
		Version:    buildinfo.Version,
		Agents:     opts.Lists["--agent"],
		Mode:       mode,
		Guardrails: opts.Has("--guardrails"),
		MCP:        opts.Has("--mcp"),
	})
	if err != nil {
		var installErr *agents.Error
		if errors.As(err, &installErr) {
			code := ExitConfig
			if installErr.Usage {
				code = ExitUsage
			}
			return Fail("varlatch agents install: "+installErr.Message, code)
		}
		return err
	}
	if opts.Has("--json") {
		if err := r.printJSON(append(jsjson.Object{{Key: "version", Value: float64(statusSchemaVersion)}}, result.JSON()...)); err != nil {
			return err
		}
	} else {
		for _, line := range agents.Describe(result, mode) {
			if err := r.println(line); err != nil {
				return err
			}
		}
	}
	// --check is for CI: files that differ from what install writes exit 1.
	if mode == "check" && result.Drift {
		return ExitWith(ExitFailure)
	}
	return nil
}

const initUsage = "Usage: varlatch init --org <slug> --project <slug> [--server <url>] [--default-environment <name>] [--no-agent-files]"

// initCommand is `varlatch init` with its flags (ADR-0058 Decisions 1 and
// 2): varlatch.toml naming its server, and the agent files unless
// --no-agent-files. Its command line is parsed strictly: a mistyped
// --no-agent-files must not write the agent files.
func initCommand(r *Run) error {
	opts, err := strictOptions("init", r.Args, OptionSpec{
		Values:   []string{"--org", "--project", "--server", "--default-environment"},
		Booleans: []string{"--no-agent-files"},
	}, initUsage)
	if err != nil {
		return err
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	if root := clientctx.FindRepoRoot(cwd); root != "" {
		// Already set up: say what comes next instead.
		cli := "varlatch"
		if r.Assisted.On {
			cli = "varlatch --assisted"
		}
		return Fail(clientctx.RepoConfigFile+" already exists at "+root+": this repository is already set up for Varlatch, so there is nothing to initialize.\n"+
			"  To compare a .env file's names with what Varlatch has, without values: "+cli+" import .env --dry-run --json\n"+
			"  To see whether an environment is ready: "+cli+" validate -e <environment> --json", ExitFailure)
	}
	org, hasOrg := opts.Value("--org")
	project, hasProject := opts.Value("--project")
	// ADR-0058 Decision 2: guided only on a terminal (both ends), outside
	// assisted mode, when --org or --project is missing (slice 5.8a).
	if !r.Assisted.On && isTerminal(r.Stdin) && isTerminal(r.Stdout) && (!hasOrg || !hasProject) {
		return UsageError("varlatch init: guided init on a terminal is not in this build of the Go CLI yet (slice 5.8a); pass --org and --project, or use the TypeScript CLI for it until then")
	}
	if !hasOrg {
		return UsageError(initUsage)
	}
	if !hasProject {
		return UsageError("Provide --project")
	}
	server, _ := opts.Value("--server")
	resolved, err := clientctx.ResolveServer(cwd, server, r.Env)
	if err != nil {
		return contextError(err)
	}
	if resolved == nil {
		return UsageErrorWithUsage("varlatch init: no server to write in "+clientctx.RepoConfigFile+"; pass --server <url>, or sign in first with varlatch login --server <url>", "\n"+initUsage)
	}
	said := ""
	if resolved.Source != clientctx.ServerFlag {
		said = " (" + serverSourceWords[resolved.Source] + ")"
	}
	environment, ok := opts.Value("--default-environment")
	if !ok {
		environment = "development"
	}
	serverText := jsjson.String(resolved.Server)
	// Each value as a TOML basic string, escaped, so the file reads back as
	// exactly what was given.
	lines := []string{
		"server = " + TOMLString(serverText),
		"organization = " + TOMLString(org),
		"project = " + TOMLString(project),
		"default_environment = " + TOMLString(environment),
		"",
	}
	// varlatch.toml is committed: a user name or password in the server URL,
	// wherever it came from, would be committed with it. The check reads the
	// server as the file will give it back, so it and the writer cannot
	// disagree. Nothing is written, and the URL is not repeated.
	readBack, err := readBackServer(strings.Join(lines, "\n"))
	if err != nil || readBack != serverText || clientctx.HasUserinfo(readBack) {
		return UsageError("varlatch init: a server URL with a user name or password can't be written to " + clientctx.RepoConfigFile +
			"; give the server's address without them. Nothing was written.")
	}
	if err := os.WriteFile(filepath.Join(cwd, clientctx.RepoConfigFile), []byte(strings.Join(lines, "\n")), 0o666); err != nil {
		return err
	}
	if err := r.println("Wrote " + clientctx.RepoConfigFile + " for " + clientctx.MaskURLInValue(serverText) + said + ". Commit it; it contains no credentials."); err != nil {
		return err
	}
	// ADR-0043 Decision 7: the files coding agents read, unless
	// --no-agent-files. A failure here leaves the project initialized.
	if opts.Has("--no-agent-files") {
		return nil
	}
	result, err := agents.RunInstall(agents.Options{Scope: "project", Root: cwd, Version: buildinfo.Version, Mode: "install"})
	if err != nil {
		// Written here, not through finish: r.warn applies the fail-safe.
		return r.warn("varlatch: the files for coding agents were not written (" + err.Error() + "); run varlatch agents install to try again.")
	}
	if targets := agents.ChangedTargets(result); len(targets) > 0 {
		if err := r.println("Wrote the Varlatch skill and instructions for coding agents: " + strings.Join(targets, ", ") + ". Commit them too."); err != nil {
			return err
		}
	}
	for _, m := range result.Manual {
		if err := r.println("To do by hand: " + m); err != nil {
			return err
		}
	}
	for _, n := range result.Notices {
		if err := r.println("Note: " + n); err != nil {
			return err
		}
	}
	return nil
}

// TOMLString is s as a TOML basic string: quotes, backslashes and control
// characters escaped, so a TOML reader gives back s byte for byte.
func TOMLString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// readBackServer is the server a varlatch.toml with this text gives, read
// as the CLI reads it (internal/toml, smol-toml's parser).
func readBackServer(text string) (string, error) {
	doc, err := toml.ParseString(text)
	if err != nil {
		return "", err
	}
	v, _ := doc.Get("server")
	server, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("varlatch.toml: no server")
	}
	return server, nil
}

// isTerminal is a stream's isTTY.
func isTerminal(stream any) bool {
	f, ok := stream.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
