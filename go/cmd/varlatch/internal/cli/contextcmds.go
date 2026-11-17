// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The offline commands of slice 5.1b (internal docs/design/go-cli.md):
// `status` without --probe (apps/cli/src/status.ts and main.ts), `server`
// and `server use` (serverCommand.ts), and `context` (main.ts), over the
// context and credential store of internal/clientctx.

// hasArg is main.ts's has(): the option anywhere in the arguments.
func hasArg(args []string, name string) bool { return slices.Contains(args, name) }

// flagArg is main.ts's flag(): what follows the first occurrence of name,
// false when name is absent or last.
func flagArg(args []string, name string) (string, bool) {
	i := slices.Index(args, name)
	if i < 0 || i+1 >= len(args) {
		return "", false
	}
	return args[i+1], true
}

// contextError turns a *ContextError into the failure main.ts's catch
// prints (status 1); any other error is left to escape, as TypeScript lets
// it.
func contextError(err error) error {
	if message, ok := clientctx.IsContextError(err); ok {
		return Fail(message, ExitFailure)
	}
	return err
}

// resolveFromArgs is main.ts's context(args): --environment (else -e) and
// --server read leniently from the command's arguments.
func (r *Run) resolveFromArgs(cwd string) (*clientctx.Context, error) {
	options := clientctx.ResolveOptions{Cwd: cwd}
	environment, ok := flagArg(r.Args, "--environment")
	if !ok {
		environment, _ = flagArg(r.Args, "-e")
	}
	options.Environment = environment
	options.Server, _ = flagArg(r.Args, "--server")
	return clientctx.ResolveContext(options, r.Env)
}

// printJSON writes JSON.stringify(doc, null, 2) and a newline.
func (r *Run) printJSON(doc jsjson.Object) error {
	return r.println(string(jsjson.StringifyIndent(doc, 2)))
}

// statusSchemaVersion is status.ts's STATUS_SCHEMA_VERSION, the version of
// every --json document.
const statusSchemaVersion = 1

// warnLifetimeFraction: warn when less than this fraction of a
// credential's lifetime remains (status.ts).
const warnLifetimeFraction = 0.2

// ExpiryState is status.ts's expiryState: "ok", "expiring", "expired", or
// "" when the lifetime is unknowable (no issuedAt or expiresAt, a
// timestamp that does not parse, or an expiry not after the issue).
func ExpiryState(credential any, now float64) string {
	if credential == nil {
		return ""
	}
	issuedAt, _ := jsval.Get(credential, "issuedAt")
	expiresAt, _ := jsval.Get(credential, "expiresAt")
	if !jsjson.Truthy(issuedAt) || !jsjson.Truthy(expiresAt) {
		return ""
	}
	issued, ok1 := jsval.DateParse(jsjson.String(issuedAt))
	expires, ok2 := jsval.DateParse(jsjson.String(expiresAt))
	if !ok1 || !ok2 || expires <= issued {
		return ""
	}
	if now >= expires {
		return "expired"
	}
	if expires-now < (expires-issued)*warnLifetimeFraction {
		return "expiring"
	}
	return "ok"
}

// serverStatus is status.ts's serverStatus: the stored metadata as it is,
// with expired and expiring derived.
func serverStatus(server string, credential any, now float64) (jsjson.Object, error) {
	if credential == nil {
		return nil, &clientctx.TypeError{Message: "credentials.json: a stored entry is null, not an object"}
	}
	field := func(name string) any {
		v, _ := jsval.Get(credential, name)
		return v // undefined ?? null and null are both null
	}
	var expired any
	if expiresAt := field("expiresAt"); jsjson.Truthy(expiresAt) {
		at, ok := jsval.DateParse(jsjson.String(expiresAt))
		expired = ok && at <= now
	}
	var expiring any
	if state := ExpiryState(credential, now); state != "" {
		expiring = state == "expiring"
	}
	return jsjson.Object{
		{Key: "server", Value: clientctx.MaskUserinfo(server)},
		{Key: "name", Value: field("name")},
		{Key: "issuedAt", Value: field("issuedAt")},
		{Key: "expiresAt", Value: field("expiresAt")},
		{Key: "credentialId", Value: field("credentialId")},
		{Key: "expired", Value: expired},
		{Key: "expiring", Value: expiring},
	}, nil
}

// repoStatus is status.ts's repoStatus. The cached tier belongs to the
// locally selected Environment only: a flag or variable selects another,
// whose tier is unknown.
func repoStatus(ctx *clientctx.Context, local any) (jsjson.Object, error) {
	tier, tierGiven, err := clientctx.LocalField(local, "selectedTier")
	if err != nil {
		return nil, err
	}
	applies := false
	if tierGiven {
		selected, _, _ := clientctx.LocalField(local, "selectedEnvironment")
		applies = jsval.StrictEqual(selected, ctx.Environment)
	}
	var shownTier, cachedAt any
	if applies {
		shownTier = tier
		cachedAt, _, _ = clientctx.LocalField(local, "tierCachedAt")
	}
	return jsjson.Object{
		{Key: "server", Value: clientctx.MaskServer(ctx.Server)},
		{Key: "organization", Value: ctx.Organization},
		{Key: "project", Value: ctx.Project},
		{Key: "environment", Value: ctx.Environment},
		{Key: "environmentSource", Value: ctx.EnvironmentSource},
		{Key: "repoRoot", Value: ctx.RepoRoot},
		{Key: "tier", Value: shownTier},
		{Key: "tierCachedAt", Value: cachedAt},
		{Key: "serverSource", Value: ctx.ServerSource},
	}, nil
}

// statusCommand is `varlatch status [--json]`: the stored credentials and
// the repository's context, offline (ADR-0032). Its options are read
// leniently, as TypeScript's has() reads them; --environment, -e and
// --server reach the repository's context. --probe goes online and is
// slice 5.1c.
func statusCommand(r *Run) error {
	if hasArg(r.Args, "--probe") {
		return UsageError("varlatch status --probe: not in this build of the Go CLI yet (slice 5.1c); use the TypeScript CLI for it until then")
	}
	list, err := clientctx.ListCredentials(r.Env)
	if err != nil {
		return err
	}
	now := float64(time.Now().UnixMilli())
	servers := []any{}
	for _, e := range list {
		s, err := serverStatus(e.Server, e.Credential, now)
		if err != nil {
			return err
		}
		servers = append(servers, s)
	}
	var repo any
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	if root := clientctx.FindRepoRoot(cwd); root != "" {
		// Inside a repository with incomplete context, the user-level status still prints.
		if ctx, err := r.resolveFromArgs(cwd); err == nil {
			if status, err := repoStatus(ctx, clientctx.LoadLocalState(root)); err == nil {
				repo = status
			}
		}
	}
	doc := jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "servers", Value: servers}, {Key: "repo", Value: repo}}
	if hasArg(r.Args, "--json") {
		return r.printJSON(doc)
	}
	return r.println(formatStatusHuman(servers, repo))
}

// formatStatusHuman is status.ts's formatStatusHuman, a frozen format
// (ADR-0032 Decision 6): every line escaped, since credential names and the
// cached tier came from servers.
func formatStatusHuman(servers []any, repo any) string {
	var lines []string
	if len(servers) == 0 {
		lines = append(lines, "No stored credentials. Run: varlatch login --server <url>")
	}
	for _, v := range servers {
		s := v.(jsjson.Object)
		var bits []string
		switch {
		case s.Value("expired") == true:
			bits = append(bits, "EXPIRED")
		case jsjson.Truthy(s.Value("expiresAt")):
			at, _ := SafeTime(s.Value("expiresAt"))
			bits = append(bits, "expires "+at)
		default:
			bits = append(bits, "no expiry recorded")
		}
		if name := s.Value("name"); jsjson.Truthy(name) {
			bits = append(bits, jsjson.String(name))
		}
		lines = append(lines, s.Value("server").(string)+"  ("+strings.Join(bits, ", ")+")")
	}
	if o, ok := repo.(jsjson.Object); ok {
		tier := ""
		if t := o.Value("tier"); jsjson.Truthy(t) {
			tier = ", tier " + jsjson.String(t)
		}
		lines = append(lines,
			"",
			"Repo          "+jsjson.String(o.Value("repoRoot")),
			"Project       "+jsjson.String(o.Value("organization"))+"/"+jsjson.String(o.Value("project")),
			"Environment   "+jsjson.String(o.Value("environment"))+" ("+jsjson.String(o.Value("environmentSource"))+tier+")",
		)
	}
	for i, line := range lines {
		lines[i] = Printable(line)
	}
	return strings.Join(lines, "\n")
}

// serverUsage is serverCommand.ts's SERVER_USAGE.
const serverUsage = "Usage: varlatch server [--json]          the server commands here use, and the remembered default\n" +
	"       varlatch server use <url>         make <url>, which you are signed in to, the default"

// serverSourceWords is serverCommand.ts's SERVER_SOURCE_WORDS.
var serverSourceWords = map[string]string{
	clientctx.ServerFlag:           "from --server",
	clientctx.ServerEnvVar:         "from VARLATCH_SERVER",
	clientctx.ServerLocalOverride:  "from .varlatch/local.json",
	clientctx.ServerRepository:     "from varlatch.toml",
	clientctx.ServerDefault:        "the default server",
	clientctx.ServerOnlyCredential: "the only server you are signed in to",
}

// strictOptions is main.ts's strictOptions: the command line parsed
// strictly, or exit 64 naming the problem, then the usage.
func strictOptions(command string, args []string, spec OptionSpec, usage string) (*ParsedOptions, error) {
	parsed, err := ParseOptions(args, spec)
	if err != nil {
		var o *OptionsError
		if errors.As(err, &o) {
			return nil, UsageError("varlatch " + command + ": " + o.Message + "\n" + usage)
		}
		return nil, err
	}
	return parsed, nil
}

// serverCommand is `varlatch server [--json]` and `varlatch server use
// <url> [--json]` (ADR-0058 Decision 1).
func serverCommand(r *Run) error {
	if len(r.Args) > 0 && r.Args[0] == "use" {
		parsed, err := strictOptions("server use", r.Args[1:], OptionSpec{Booleans: []string{"--json"}, Positionals: 1}, serverUsage)
		if err != nil {
			return err
		}
		if len(parsed.Positionals) == 0 {
			return UsageError(serverUsage)
		}
		return r.useServer(parsed.Positionals[0], parsed.Has("--json"))
	}
	parsed, err := strictOptions("server", r.Args, OptionSpec{Booleans: []string{"--json"}}, serverUsage)
	if err != nil {
		return err
	}
	return r.showServer(parsed.Has("--json"))
}

// showServer is serverCommand.ts's showServer: what a command here would
// use, the default, and the servers signed in to.
func (r *Run) showServer(asJSON bool) error {
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	resolved, err := clientctx.ResolveServer(cwd, "", r.Env)
	problem := ""
	if err != nil {
		message, ok := clientctx.IsContextError(err)
		if !ok {
			return err
		}
		resolved, problem = nil, message
	}
	remembered, err := clientctx.DefaultServer(r.Env)
	if err != nil {
		return err
	}
	signedIn, err := clientctx.StoredServers(r.Env)
	if err != nil {
		return err
	}
	if asJSON {
		var server, source, def any
		if resolved != nil {
			server, source = clientctx.MaskServer(resolved.Server), resolved.Source
		}
		if remembered != "" {
			def = clientctx.MaskUserinfo(remembered)
		}
		list := make([]any, len(signedIn))
		for i, s := range signedIn {
			list[i] = clientctx.MaskUserinfo(s)
		}
		return r.printJSON(jsjson.Object{
			{Key: "version", Value: 1},
			{Key: "server", Value: server},
			{Key: "serverSource", Value: source},
			{Key: "defaultServer", Value: def},
			{Key: "signedIn", Value: list},
		})
	}
	here := "Server here: none"
	if resolved != nil {
		here = "Server here: " + jsjson.String(clientctx.MaskServer(resolved.Server)) + " (" + serverSourceWords[resolved.Source] + ")"
	} else if problem != "" {
		here += " (" + problem + ")"
	}
	def := clientctx.MaskUserinfo(remembered)
	if def == "" {
		def = "none"
	}
	in := "none"
	if len(signedIn) > 0 {
		in = strings.Join(maskAll(signedIn), ", ")
	}
	return r.println(here + "\nDefault server: " + def + "\nSigned in to: " + in)
}

// useServer is serverCommand.ts's useServer: only a server with a stored
// credential, matched exactly in the form credentials.json keys on
// (trailing slashes removed, path kept).
func (r *Run) useServer(server string, asJSON bool) error {
	if _, ok := whatwg.ParseURL(server); !ok {
		return UsageError("varlatch server use: not a URL: " + clientctx.MaskUserinfo(server))
	}
	key := clientctx.StoredServerKey(server)
	signedIn, err := clientctx.StoredServers(r.Env)
	if err != nil {
		return err
	}
	if !slices.Contains(signedIn, key) {
		shown := clientctx.MaskUserinfo(key)
		message := "varlatch server use: you are not signed in to " + shown + ". Sign in first: varlatch login --server " + shown
		if len(signedIn) > 0 {
			message += "\nSigned in to: " + strings.Join(maskAll(signedIn), ", ")
		}
		return UsageError(message)
	}
	if err := clientctx.SetDefaultServer(key, true, r.Env); err != nil {
		return contextError(err)
	}
	if asJSON {
		return r.printJSON(jsjson.Object{{Key: "version", Value: 1}, {Key: "defaultServer", Value: clientctx.MaskUserinfo(key)}})
	}
	return r.println("Default server: " + clientctx.MaskUserinfo(key))
}

// maskAll is MaskUserinfo of each server.
func maskAll(servers []string) []string {
	out := make([]string, len(servers))
	for i, s := range servers {
		out[i] = clientctx.MaskUserinfo(s)
	}
	return out
}

// placeholderValue is agentRun.ts's PLACEHOLDER_VALUE.
var placeholderValue = regexp.MustCompile(`^vlch_ph_v1_[0-9a-f]{32}$`)

// placeholderNames is agentRun.ts's placeholderNames: the variables that
// hold Placeholders, names only, sorted.
func placeholderNames(env map[string]string) []string {
	var names []string
	for name, value := range env {
		if placeholderValue.MatchString(value) {
			names = append(names, name)
		}
	}
	slices.SortFunc(names, jsval.CompareUTF16)
	return names
}

// contextCommand is `varlatch context [--json]`: the resolved context, and
// inside an agent-safe run which variables hold Placeholders.
func contextCommand(r *Run) error {
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return contextError(err)
	}
	repo, err := repoStatus(ctx, clientctx.LoadLocalState(ctx.RepoRoot))
	if err != nil {
		return err
	}
	runID := clientctx.AgentRunOf(r.Env)
	var placeholders []string
	if runID != "" {
		placeholders = placeholderNames(r.Environ())
	}
	if hasArg(r.Args, "--json") {
		doc := append(jsjson.Object{{Key: "version", Value: statusSchemaVersion}}, repo...)
		if runID != "" {
			list := make([]any, len(placeholders))
			for i, p := range placeholders {
				list[i] = p
			}
			doc = append(doc, jsjson.Member{Key: "agentRun", Value: jsjson.Object{{Key: "id", Value: runID}, {Key: "placeholders", Value: list}}})
		}
		return r.printJSON(doc)
	}
	lines := []string{
		"Server        " + jsjson.String(clientctx.MaskServer(ctx.Server)),
		"Organization  " + ctx.Organization,
		"Project       " + ctx.Project,
		"Environment   " + jsjson.String(ctx.Environment),
		"Source        " + ctx.EnvironmentSource,
	}
	if tier := repo.Value("tier"); jsjson.Truthy(tier) {
		lines = append(lines, "Tier          "+Printable(jsjson.String(tier))+" (cached "+Printable(jsjson.String(repo.Value("tierCachedAt")))+")")
	}
	lines = append(lines, "Repo root     "+ctx.RepoRoot)
	if runID != "" {
		shown := strings.Join(placeholders, ", ")
		if shown == "" {
			shown = "none"
		}
		lines = append(lines, "Agent run     "+runID+" (Placeholders: "+shown+")")
	}
	return r.println(strings.Join(lines, "\n"))
}
