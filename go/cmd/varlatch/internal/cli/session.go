// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The session commands of slice 5.1e (internal docs/design/go-cli.md):
// `login --token` and `login --token-stdin`, `logout` (revoke.ts),
// `whoami` (whoami.ts), `env list` and `env use`, ported from main.ts at
// v0.22.0. The other ways of signing in (the browser, --oidc, --start and
// --wait) are slice 5.2's: signin.go and devicelogin.go.

// shownServer is a server URL as the Go CLI prints it: its allow-listed
// display form (clientctx.DisplayServer; go/README.md, the accepted
// difference "server-display"), so an ordinary URL is printed as it is.
func shownServer(server string) string { return clientctx.DisplayServer(server) }

// shownServers is shownServer for each, joined with ", ".
func shownServers(servers []string) string {
	shown := make([]string, len(servers))
	for i, s := range servers {
		shown[i] = shownServer(s)
	}
	return strings.Join(shown, ", ")
}

// shownValue is a value from a server's answer, the tier cache or stored
// metadata as human output shows it:
// a URL's user name and password masked (clientctx.MaskURLInValue), any
// other value as it is. Tokens are redacted for every stdout line by
// RedactOutput.
func shownValue(v string) string { return clientctx.MaskURLInValue(v) }

// serverString is a resolved server as the code that uses it reads it: a
// string. .varlatch/local.json's serverOverride can hold any JSON, and
// TypeScript's `server.replace(...)` throws a TypeError for anything else.
func serverString(server any) (string, error) {
	if s, ok := server.(string); ok {
		return s, nil
	}
	return "", &clientctx.TypeError{Message: "server.replace is not a function"}
}

// loginOptions is main.ts's LOGIN_OPTIONS: login is parsed strictly, so a
// misspelled option never starts a different sign-in.
var loginOptions = OptionSpec{
	Values:   []string{"--server", "--token", "--ttl", "--org", "--audience", "--oidc-token", "--timeout"},
	Booleans: []string{"--token-stdin", "--oidc", "--start", "--wait", "--json"},
}

// loginCommand is `varlatch login` (main.ts): a credential given with
// --token, or read from standard input with --token-stdin (ADR-0043
// Decision 2), verified against the server and stored; a credential it
// replaces is revoked once the new one is stored (ADR-0032).
func loginCommand(r *Run) error {
	// No human sign-in inside an agent-safe run (ADR-0043 Decision 5),
	// whatever the method: refused before any request and before any
	// sign-in state is read or written.
	if run := clientctx.AgentRunOf(r.Env); run != "" {
		return UsageError("varlatch login: this command runs inside agent-safe run " + run + ", which has no human sign-in, and a " +
			"human's credential never replaces the run's agent identity. Nothing was requested, and no sign-in state " +
			"was read or written.\nFor read access to configuration metadata, the operator relaunches the run with --agent-metadata.")
	}
	usage, _ := CommandHelp("login")
	login, err := strictOptions("login", r.Args, loginOptions, usage)
	if err != nil {
		return err
	}
	// Without --server: the server a command here would use, so signing in
	// again needs no address (ADR-0058 Decision 1).
	var server any
	if flag, ok := login.Value("--server"); ok {
		server = flag
	} else {
		cwd, err := Cwd()
		if err != nil {
			return err
		}
		resolved, err := clientctx.ResolveServer(cwd, "", r.Env)
		if err != nil {
			return contextError(err)
		}
		if resolved == nil {
			return UsageErrorWithUsage("varlatch login: no server; pass --server <url> the first time", "\n"+usage)
		}
		server = resolved.Server
	}
	var given []string
	for _, m := range []string{"--token", "--token-stdin", "--oidc", "--start", "--wait"} {
		_, isValue := login.Value(m)
		if m == "--token" && isValue || m != "--token" && login.Has(m) {
			given = append(given, m)
		}
	}
	if len(given) > 1 {
		return UsageError("varlatch login: give one of --token-stdin, --token, --oidc, --start, or --wait, not more than one (" + strings.Join(given, ", ") + ")")
	}
	// Assisted mode: with no method given, a coding agent cannot wait for
	// the browser loopback, so login starts a device sign-in.
	device := ""
	if len(given) == 1 && (given[0] == "--start" || given[0] == "--wait") {
		device = given[0]
	} else if len(given) == 0 && r.Assisted.On {
		device = "--start"
	}
	ttlFlag, hasTTL := login.Value("--ttl")
	if device != "" {
		for _, option := range []string{"--org", "--audience", "--oidc-token"} {
			if _, ok := login.Value(option); ok {
				return UsageErrorWithUsage("varlatch login: "+option+" applies to --oidc, not to "+device, "\n"+usage)
			}
		}
		io := deviceIO{json: login.Has("--json"), cli: "varlatch", assisted: r.Assisted.On}
		if r.Assisted.On {
			io.cli = "varlatch --assisted"
		}
		serverText, err := serverString(server)
		if err != nil {
			return err
		}
		if device == "--start" {
			if _, ok := login.Value("--timeout"); ok {
				return UsageError("varlatch login: --timeout applies to --wait")
			}
			var ttl *float64
			if hasTTL {
				n, err := loginSeconds(ttlFlag, 60, 86_400, "--ttl")
				if err != nil {
					return err
				}
				ttl = &n
			}
			return r.startDeviceLogin(serverText, ttl, io)
		}
		if hasTTL {
			return UsageError("varlatch login: --ttl applies to --start; the sign-in's lifetime was set when it started")
		}
		timeout := float64(waitDefaultSeconds)
		if value, ok := login.Value("--timeout"); ok {
			if timeout, err = loginSeconds(value, 1, waitMaxSeconds, "--timeout"); err != nil {
				return err
			}
		}
		return r.waitDeviceLogin(serverText, int(timeout), io)
	}
	if login.Has("--json") {
		return UsageError("varlatch login: --json applies to --start and --wait")
	}
	if _, ok := login.Value("--timeout"); ok {
		return UsageError("varlatch login: --timeout applies to --wait")
	}
	token, _ := login.Value("--token")
	if login.Has("--token-stdin") {
		if token, err = r.readTokenStdin(); err != nil {
			return err
		}
	}
	// A server echoing the credential back in an error message gets it
	// masked (issue #119), and no output or diagnostic shows it, whatever
	// its length: the person gave it (--token or --token-stdin).
	r.holdCredential(token, true)
	// Issuance metadata (ADR-0032): stored so expiry is knowable offline.
	// An explicit --token has none: its entry stays metadata-free.
	var issued any
	ttlInput := jsjson.Object{}
	if hasTTL && ttlFlag != "" {
		ttlInput = jsjson.Object{{Key: "ttlSeconds", Value: apiclient.Number(ttlFlag)}}
	}
	if token == "" && login.Has("--oidc") {
		// CI federation (capability auth.oidc): exchange the platform's OIDC
		// ID token for a short-lived credential; nothing stored in the
		// pipeline's secrets at all.
		organization, ok := login.Value("--org")
		if !ok {
			return UsageError("OIDC login requires --org <organization>")
		}
		explicit, _ := login.Value("--oidc-token")
		audience, _ := login.Value("--audience")
		idToken, err := r.oidcIDToken(explicit, audience)
		if err != nil {
			return err
		}
		r.holdSecret(idToken)
		serverText, err := serverString(server)
		if err != nil {
			return err
		}
		input := append(jsjson.Object{{Key: "token", Value: idToken}, {Key: "organization", Value: organization}}, ttlInput...)
		if issued, err = r.plainClient(serverText, "").ExchangeOidcToken(context.Background(), input); err != nil {
			return err
		}
		if token, err = r.issuedToken(issued); err != nil {
			return err
		}
		if err := r.println("OIDC exchange succeeded (credential expires " + templateTime(jsUndefinedOr(jsval.Get(issued, "expiresAt"))) + ")."); err != nil {
			return err
		}
	}
	if token == "" {
		// Browser hand-off (ADR-0017): loopback listener and passkey sign-in.
		// The callback delivers a 15-minute session bearer, exchanged at once
		// for a longer-lived CLI credential (ADR-0024; the exchange revokes
		// the bearer).
		serverText, err := serverString(server)
		if err != nil {
			return err
		}
		handoff, err := r.browserLogin(serverText)
		if err != nil {
			return err
		}
		r.holdSecret(handoff)
		// The CLI's User-Agent lets the server label the credential.
		if issued, err = r.plainClient(serverText, handoff).ExchangeCliCredential(context.Background(), ttlInput); err != nil {
			return err
		}
		if token, err = r.issuedToken(issued); err != nil {
			return err
		}
		if err := r.println("Issued CLI credential (expires " + templateTime(jsUndefinedOr(jsval.Get(issued, "expiresAt"))) + ")."); err != nil {
			return err
		}
	}
	return r.loginWithToken(server, token, issued)
}

// issuedToken is an issued credential's token, held as a secret in flight.
func (r *Run) issuedToken(issued any) (string, error) {
	token, ok, err := read(issued, issued != apiclient.Undefined, "token")
	if err != nil {
		return "", err
	}
	text := jsTemplate(token, ok)
	r.holdSecret(text)
	return text, nil
}

// loginSeconds is --ttl and --timeout's check: whole seconds from low to
// high, else a usage error naming the option.
func loginSeconds(value string, low, high float64, option string) (float64, error) {
	n := apiclient.Number(value)
	if !digitsOnly.MatchString(value) || n < low || n > high {
		return 0, UsageError("varlatch login: " + option + " takes whole seconds from " + strconv.FormatFloat(low, 'f', -1, 64) + " to " +
			strconv.FormatFloat(high, 'f', -1, 64) + ", not " + shownValue(value))
	}
	return n, nil
}

var digitsOnly = regexp.MustCompile(`^\d+$`)

// readTokenStdin is --token-stdin: a credential from a pipe or a file,
// never the command line, where process lists, shell history and a coding
// agent's transcript would keep it (ADR-0043 Decision 2). One line break
// at the end is dropped. What was read is never echoed, and no message
// quotes it.
func (r *Run) readTokenStdin() (string, error) {
	if isTerminal(r.Stdin) {
		return "", UsageError("varlatch login: --token-stdin reads the credential from a pipe or a file; in a terminal, leave it out to sign in in the browser")
	}
	data, err := io.ReadAll(r.Stdin)
	if err != nil {
		return "", err
	}
	piped := jsval.DecodeUTF8(data) // Buffer's toString("utf8"): malformed bytes as U+FFFD, a byte order mark kept
	if strings.HasSuffix(piped, "\r\n") {
		piped = piped[:len(piped)-2]
	} else if strings.HasSuffix(piped, "\n") {
		piped = piped[:len(piped)-1]
	}
	if piped == "" {
		return "", UsageError("varlatch login: --token-stdin read no credential")
	}
	if strings.ContainsFunc(piped, isJSWhitespace) {
		return "", UsageError("varlatch login: the credential on stdin contains whitespace; give one credential on one line")
	}
	return piped, nil
}

// isJSWhitespace is a character JavaScript's \s matches: the white space
// and line terminators of ECMA-262.
func isJSWhitespace(c rune) bool { return jsval.IsWhitespace(c) }

// loginWithToken verifies the credential (GET /v1/meta, then GET
// /v1/organizations), stores it with the time of the sign-in, says so, makes
// the server the default when none is set, and revokes the credential it
// replaced, only after the new one is stored: a failed or abandoned login
// never leaves the person signed out.
func (r *Run) loginWithToken(serverValue any, token string, issued any) error {
	server, err := serverString(serverValue)
	if err != nil {
		return err
	}
	probe := r.plainClient(server, token)
	ctx := context.Background()
	meta, err := probe.Meta(ctx)
	if err != nil {
		return err
	}
	if _, err := probe.ListOrganizations(ctx); err != nil {
		return err
	}
	previous, err := clientctx.LoadCredential(server, r.Env)
	if err != nil {
		return err
	}
	replaced := replacedCredential(previous, token, nowMS())
	// A credential given with --token carries no issuance metadata: its
	// entry is the token and the time of the sign-in. An issued one names
	// its expiry and id.
	entry := jsjson.Object{{Key: "token", Value: token}, {Key: "issuedAt", Value: isoString(time.Now().UTC())}}
	if issued != nil {
		for _, field := range [][2]string{{"expiresAt", "expiresAt"}, {"id", "credentialId"}} {
			if v, ok := jsval.Get(issued, field[0]); ok && v != apiclient.Undefined {
				entry = append(entry, jsjson.Member{Key: field[1], Value: v})
			}
		}
	}
	if err := clientctx.SaveCredential(server, entry, r.Env); err != nil {
		return err
	}
	shownVersion, api, err := r.serverSummary(meta)
	if err != nil {
		return err
	}
	if err := r.println("Logged in to " + shownServer(server) + " (server " + shownVersion + ", " + api + ")."); err != nil {
		return err
	}
	r.noteDefaultServer(server)
	if replaced == nil {
		return nil
	}
	failure, err := r.revokeStored(server, replaced)
	if err != nil {
		return err
	}
	if failure == "" {
		return r.println("Previous credential revoked.")
	}
	_ = r.warn("varlatch: previous credential not revoked (" + failure + ") — it may remain live" + liveUntil(replaced) + ".")
	return nil
}

// serverSummary is the server's version and API major as a sign-in names
// them: only fields of the expected shape (issue #119), since a server
// could put anything in them.
func (r *Run) serverSummary(meta any) (version, api string, err error) {
	major, _, err := read(meta, meta != apiclient.Undefined, "apiMajor")
	if err != nil {
		return "", "", err
	}
	raw, _, err := read(meta, true, "serverVersion")
	if err != nil {
		return "", "", err
	}
	version, ok := r.Secrets.SafeVersion(raw)
	if !ok {
		version = UnrecognizedVersion
	}
	api = "an unrecognized API version"
	if n, ok := SafeAPIMajor(major); ok {
		api = fmt.Sprintf("API v%d", n)
	}
	return version, api, nil
}

// liveUntil is ` until <time>` for a credential with a truthy expiresAt.
func liveUntil(credential any) string {
	if expiresAt, ok := jsval.Get(credential, "expiresAt"); ok && jsjson.Truthy(expiresAt) {
		return " until " + templateTime(expiresAt)
	}
	return ""
}

// noteDefaultServer is serverCommand.ts's noteDefaultServer: after a
// sign-in stored its credential, the server becomes the default when none
// is set, said on stderr only. A failure to write the setting never fails
// the sign-in, which already succeeded.
func (r *Run) noteDefaultServer(server string) {
	set, err := clientctx.RememberServerIfUnset(server, r.Env)
	if err != nil {
		_ = r.warn("varlatch: the default server was not saved (" + err.Error() + "); the sign-in is stored.")
		return
	}
	if set {
		_ = r.warn("Default server: " + shownServer(clientctx.StoredServerKey(server)) + ", for commands outside a repository. Change it with: varlatch server use <url>")
	}
}

// replacedCredential is revoke.ts's replacedCredential: the stored entry a
// fresh login is about to overwrite, when it may still be live: not when
// it holds the same token, nor when its expiry has passed. Without this,
// every re-login would orphan a working credential until it expires.
func replacedCredential(previous any, next string, now float64) any {
	if !jsjson.Truthy(previous) {
		return nil
	}
	if token, ok := jsval.Get(previous, "token"); ok && jsval.StrictEqual(token, next) {
		return nil
	}
	if expiresAt, ok := jsval.Get(previous, "expiresAt"); ok && jsjson.Truthy(expiresAt) {
		if at, valid := jsval.DateParse(jsjson.String(expiresAt)); valid && at <= now {
			return nil
		}
	}
	return previous
}

// revokeStored is revoke.ts's revokeStoredCredential: the stored
// credential revokes itself (DELETE /v1/me/credentials/<id>), whichever
// identity it belongs to. It returns "" when revoked, else why not, to say
// as it is; callers never stop on it. A credential that is not an object
// fails as TypeScript's property read does.
func (r *Run) revokeStored(server string, credential any) (string, error) {
	return r.revokeStoredWith(context.Background(), r.plainClient, server, credential)
}

// revokeStoredWith is revokeStored with the request's context and client
// (a device sign-in's are bounded by its deadline).
func (r *Run) revokeStoredWith(ctx context.Context, client func(server, token string) *apiclient.Client, server string, credential any) (string, error) {
	id, idOK, err := read(credential, true, "credentialId")
	if err != nil {
		return "", err
	}
	if !idOK || !jsjson.Truthy(id) {
		return "no credential id recorded by this login", nil
	}
	token, tokenOK := jsval.Get(credential, "token")
	bearer := ""
	if tokenOK && jsjson.Truthy(token) {
		bearer = jsjson.String(token)
	}
	if _, err := client(server, bearer).RevokeMyCredential(ctx, jsjson.String(id)); err != nil {
		if api, ok := err.(*apiclient.APIError); ok {
			return safeCode(api.Code), nil
		}
		// The reason is printed (logout on stdout, login on stderr): no
		// Varlatch token in it, whatever made it.
		return varlatchToken.ReplaceAllLiteralString(clientctx.MaskURLInValue(err.Error()), Redacted), nil
	}
	return "", nil
}

// logoutCommand is `varlatch logout [--server <url> | --all]` (ADR-0032):
// revoke server-side, remove locally regardless, and say exactly which of
// the two happened. Its options are read leniently, as main.ts's has() and
// flag() read them.
func logoutCommand(r *Run) error {
	stored, err := clientctx.ListCredentials(r.Env)
	if err != nil {
		return err
	}
	if len(stored) == 0 {
		return Fail("No stored credentials.", ExitFailure)
	}
	targets := stored
	if !hasArg(r.Args, "--all") {
		// --server, else the server a command here would use (ADR-0058
		// Decision 1): inside a repository only its own server; outside one
		// the default, else the only stored credential.
		cwd, err := Cwd()
		if err != nil {
			return err
		}
		flag, _ := flagArg(r.Args, "--server")
		resolved, err := clientctx.ResolveServer(cwd, flag, r.Env)
		if err != nil {
			if _, isContext := clientctx.IsContextError(err); !isContext {
				return err
			}
			resolved = nil
		}
		names := make([]string, len(stored))
		for i, s := range stored {
			names[i] = s.Server
		}
		if resolved == nil {
			list := shownServers(names)
			if len(stored) > 1 {
				return UsageError("Multiple servers stored (" + list + "). Pass --server <url> or --all.")
			}
			return UsageError("No server here: pass --server <url> or --all (stored: " + list + ").")
		}
		server, err := serverString(resolved.Server)
		if err != nil {
			return err
		}
		key := clientctx.StoredServerKey(server)
		targets = nil
		for _, s := range stored {
			if s.Server == key {
				targets = []clientctx.Entry{s}
				break
			}
		}
		if targets == nil {
			return Fail("No stored credential for "+shownServer(server), ExitFailure)
		}
	}
	for _, t := range targets {
		failure, err := r.revokeStored(t.Server, t.Credential)
		if err != nil {
			return err
		}
		if _, err := clientctx.DeleteCredential(t.Server, r.Env); err != nil {
			return err
		}
		if failure == "" {
			if err := r.println(shownServer(t.Server) + ": credential revoked and removed."); err != nil {
				return err
			}
			continue
		}
		if err := r.println(shownServer(t.Server) + ": removed locally; server revocation failed (" + failure + ") — the credential may remain live" + liveUntil(t.Credential) + "."); err != nil {
			return err
		}
	}
	return nil
}

// whoamiUsage is main.ts's WHOAMI_USAGE.
const whoamiUsage = "Usage: varlatch whoami [--server <url>] [--json]"

// envUsage and envUseUsage are main.ts's env usage lines.
const (
	envUsage    = "Usage: varlatch env <use|list>"
	envUseUsage = "Usage: varlatch env use <environment>"
)

// whoamiCommand is `varlatch whoami [--server <url>] [--json]` (capability
// identity.whoami): which identity the credential this CLI would use
// belongs to, with its organization and the credential's own name, as GET
// /v1/me answers. Names and identifiers only, never a token.
func whoamiCommand(r *Run) error {
	parsed, err := strictOptions("whoami", r.Args, OptionSpec{Values: []string{"--server"}, Booleans: []string{"--json"}}, whoamiUsage)
	if err != nil {
		return err
	}
	stored, err := clientctx.StoredServers(r.Env)
	if err != nil {
		return err
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	flag, _ := parsed.Value("--server")
	// whoami.ts's whoamiServer: inside a repository only its own server;
	// the default and the only stored credential apply outside one. An
	// unreadable varlatch.toml with nothing overriding it names none.
	resolved, err := clientctx.ResolveServer(cwd, flag, r.Env)
	if err != nil {
		if _, isContext := clientctx.IsContextError(err); !isContext {
			return err
		}
		resolved = nil
	}
	if resolved == nil {
		if len(stored) > 1 {
			return UsageErrorWithUsage("varlatch whoami: credentials are stored for "+shownServers(stored)+"; pass --server <url>", "\n"+whoamiUsage)
		}
		return UsageErrorWithUsage("varlatch whoami: no server; pass --server <url>, set VARLATCH_SERVER, or run inside a varlatch repository", "\n"+whoamiUsage)
	}
	server, err := serverString(resolved.Server)
	if err != nil {
		return err
	}
	api, err := r.connectClient(server)
	if err != nil {
		return err
	}
	caller, err := r.fetchWhoami(api)
	if err != nil {
		return err
	}
	base := strings.TrimRight(server, "/")
	if parsed.Has("--json") {
		return r.printJSON(whoamiDocument(shownServer(base), caller))
	}
	text, err := formatWhoamiHuman(shownServer(base), caller)
	if err != nil {
		return err
	}
	return r.println(text)
}

// whoamiFields is the WhoAmI document of the API (packages/protocol
// openapi.yaml): the fields `whoami --json` shows, each object's own
// fields beside it. Nothing else /v1/me answers is shown.
var whoamiFields = map[string][]string{
	"identity":     {"id", "name", "kind", "email"},
	"organization": {"id", "slug", "name", "createdAt"},
	"credential":   {"id", "name", "kind", "expiresAt"},
	"listener":     nil,
	"tailnet":      {"recognized", "reason", "tailnet", "nodeId", "nodeName", "tags", "userLogin"},
}

// whoamiDocument is `whoami --json`'s document: the schema version, the
// server (masked, and never replaced by the answer), then the fields of the
// WhoAmI document the answer holds, in the answer's order, each object
// keeping only its own documented fields. The TypeScript CLI spreads the
// whole answer after the server (go/README.md, "whoami --json shows only
// the documented fields").
func whoamiDocument(server string, caller any) jsjson.Object {
	doc := jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "server", Value: server}}
	for _, m := range spread(caller) {
		fields, known := whoamiFields[m.Key]
		if !known {
			continue
		}
		if v, ok := documented(m.Value, fields); ok {
			doc = append(doc, jsjson.Member{Key: m.Key, Value: v})
		}
	}
	return doc
}

// documented is v as the WhoAmI document defines it: an object with only
// its named fields, each a scalar (tags a list of scalars); a field defined
// as a scalar (nil fields) only when it is one. An object or array where a
// scalar is defined is left out, never passed through (false).
func documented(v any, fields []string) (any, bool) {
	o, isObject := v.(jsjson.Object)
	if fields == nil || !isObject {
		return scalar(v) // null (an Organization of none) is kept, as the API sends it
	}
	out := jsjson.Object{}
	for _, m := range o {
		if !slices.Contains(fields, m.Key) {
			continue
		}
		if m.Key == "tags" {
			if list, isList := m.Value.([]any); isList {
				tags := []any{}
				for _, e := range list {
					if t, ok := scalar(e); ok {
						tags = append(tags, t)
					}
				}
				out = append(out, jsjson.Member{Key: m.Key, Value: tags})
			}
			continue
		}
		if s, ok := scalar(m.Value); ok {
			out = append(out, jsjson.Member{Key: m.Key, Value: s})
		}
	}
	return out, true
}

// fetchWhoami is whoami.ts's fetchWhoami: ask the server, after checking
// that it can answer (ADR-0018 §3: capabilities, not versions).
func (r *Run) fetchWhoami(api *apiclient.Client) (any, error) {
	ctx := context.Background()
	meta, err := api.Meta(ctx)
	if err != nil {
		return nil, err
	}
	capabilities, capOK, err := read(meta, meta != apiclient.Undefined, "capabilities")
	if err != nil {
		return nil, err
	}
	has, err := includes(capabilities, capOK, whoamiCapability, "meta.capabilities.includes")
	if err != nil {
		return nil, err
	}
	if !has {
		version, _ := jsval.Get(meta, "serverVersion")
		shown, ok := r.Secrets.SafeVersion(version)
		if !ok {
			shown = "an older release"
		}
		return nil, Fail("varlatch whoami: this server ("+shown+") cannot say which identity a credential belongs to "+
			"(it lacks the "+whoamiCapability+" capability); upgrade the server. "+
			"varlatch status --probe still says whether a stored credential is valid.", ExitFailure)
	}
	return api.WhoAmI(ctx)
}

// field is `${base.key}` for a value read from a server's answer: V8's
// TypeError when base is null or undefined.
func field(base any, key string) (string, error) {
	v, ok, err := read(base, true, key)
	if err != nil {
		return "", err
	}
	return shownValue(jsTemplate(v, ok)), nil
}

// formatWhoamiHuman is whoami.ts's formatWhoamiHuman: one labeled line per
// fact, as `varlatch context` prints. Names, ids and the device's details
// come from the server: every line escaped (issue #119).
func formatWhoamiHuman(server string, caller any) (string, error) {
	if caller == apiclient.Undefined || caller == nil {
		what := "undefined"
		if caller == nil {
			what = "null"
		}
		return "", &clientctx.TypeError{Message: "Cannot destructure property 'identity' of 'caller' as it is " + what + "."}
	}
	identity, identityOK := jsval.Get(caller, "identity")
	organization, organizationOK := jsval.Get(caller, "organization")
	credential, credentialOK := jsval.Get(caller, "credential")
	var org string
	if organizationOK && jsjson.Truthy(organization) {
		slug, err := field(organization, "slug")
		if err != nil {
			return "", err
		}
		name, _ := field(organization, "name")
		id, _ := field(organization, "id")
		org = slug + " (" + name + ", " + id + ")"
	} else {
		kind, kindOK, err := read(identity, identityOK, "kind")
		if err != nil {
			return "", err
		}
		if kindOK && kind == "human" {
			org = "none: a person joins organizations as a member (varlatch org list)"
		} else {
			org = "none"
		}
	}
	if _, _, err := read(identity, identityOK, "name"); err != nil {
		return "", err
	}
	name, _ := field(identity, "name")
	kind, _ := field(identity, "kind")
	id, _ := field(identity, "id")
	lines := []string{"Identity      " + name + " (" + kind + ", " + id + ")"}
	if email, ok := jsval.Get(identity, "email"); ok && jsjson.Truthy(email) {
		lines = append(lines, "Email         "+shownValue(jsjson.String(email)))
	}
	lines = append(lines, "Organization  "+org)
	credName, credNameOK, err := read(credential, credentialOK, "name")
	if err != nil {
		return "", err
	}
	shownName := "unnamed"
	if credNameOK && credName != nil {
		shownName = shownValue(jsjson.String(credName))
	}
	credKind, _ := field(credential, "kind")
	credID, _ := field(credential, "id")
	expiry := "no expiry"
	if expiresAt, ok := jsval.Get(credential, "expiresAt"); ok && jsjson.Truthy(expiresAt) {
		expiry = "expires " + templateTime(expiresAt)
	}
	lines = append(lines, "Credential    "+shownName+" ("+credKind+", "+credID+"), "+expiry)
	listener, listenerOK := jsval.Get(caller, "listener")
	lines = append(lines, "Server        "+server+" ("+shownValue(jsTemplate(listener, listenerOK))+" listener)")
	if tailnet, ok := jsval.Get(caller, "tailnet"); ok && jsjson.Truthy(tailnet) {
		device, err := describeDevice(tailnet)
		if err != nil {
			return "", err
		}
		lines = append(lines, "Device        "+device)
	}
	for i, line := range lines {
		lines[i] = Printable(line)
	}
	return strings.Join(lines, "\n"), nil
}

// describeDevice is whoami.ts's describeDevice: the tailnet device the
// request came from.
func describeDevice(device any) (string, error) {
	get := func(key string) (any, bool) { return jsval.Get(device, key) }
	if recognized, ok := get("recognized"); !ok || !jsjson.Truthy(recognized) {
		reason, ok := get("reason")
		shown := "unrecognized"
		if ok && reason != nil {
			shown = shownValue(jsjson.String(reason))
		}
		return "not recognized (" + shown + ")", nil
	}
	nodeID, nodeIDOK := get("nodeId")
	var node string
	if nodeName, ok := get("nodeName"); ok && jsjson.Truthy(nodeName) {
		node = shownValue(jsjson.String(nodeName)) + " (" + shownValue(jsTemplate(nodeID, nodeIDOK)) + ")"
	} else {
		node = "node " + shownValue(jsTemplate(nodeID, nodeIDOK))
	}
	var who string
	tags, tagsOK := get("tags")
	length := any(nil)
	if tagsOK && tags != nil {
		length, _ = jsval.Get(tags, "length")
	}
	if jsjson.Truthy(length) {
		list, isArray := tags.([]any)
		if !isArray {
			return "", &clientctx.TypeError{Message: "device.tags.join is not a function"}
		}
		parts := make([]string, len(list))
		for i, t := range list {
			if t != nil {
				parts[i] = shownValue(jsjson.String(t))
			}
		}
		who = "tags " + strings.Join(parts, ", ")
	} else if login, ok := get("userLogin"); ok && jsjson.Truthy(login) {
		who = "user " + shownValue(jsjson.String(login))
	} else {
		who = "no tags"
	}
	tailnet, tailnetOK := get("tailnet")
	return node + ", " + who + ", on " + shownValue(jsTemplate(tailnet, tailnetOK)), nil
}

// envCommand is `varlatch env list` and `varlatch env use <environment>`.
func envCommand(r *Run) error {
	sub := ""
	hasSub := len(r.Args) > 0
	if hasSub {
		sub = r.Args[0]
	}
	if hasSub && sub == "use" {
		return r.envUse()
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return contextError(err)
	}
	if !hasSub || sub != "list" {
		return UsageOnly(envUsage)
	}
	return r.envList(ctx)
}

// envList is `varlatch env list [--json]`. Its human format is frozen
// (ADR-0032): scripts parse each line, `<name>  (<tier>, <kind>[, selected])`.
func (r *Run) envList(ctx *clientctx.Context) error {
	server, err := serverString(ctx.Server)
	if err != nil {
		return err
	}
	api, err := r.connectClient(server)
	if err != nil {
		return err
	}
	envs, err := api.ListEnvironments(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		return err
	}
	items, itemsOK, err := read(envs, envs != apiclient.Undefined, "items")
	if err != nil {
		return err
	}
	selected := func(e any) bool {
		name, ok := jsval.Get(e, "name")
		return ok && jsval.StrictEqual(name, ctx.Environment)
	}
	if hasArg(r.Args, "--json") {
		// The machine surface (ADR-0032).
		list, isArray := items.([]any)
		if !isArray {
			if !itemsOK || items == nil {
				return typeErrorRead(items, itemsOK, "map")
			}
			return &clientctx.TypeError{Message: "envs.items.map is not a function"}
		}
		environments := make([]any, len(list))
		for i, e := range list {
			entry := jsjson.Object{}
			for _, key := range []string{"name", "tier", "kind"} {
				v, ok, err := read(e, true, key)
				if err != nil {
					return err
				}
				// undefined is left out, as JSON.stringify does; so is an
				// object or array where the API defines a string.
				if s, isScalar := scalar(v); ok && isScalar {
					entry = append(entry, jsjson.Member{Key: key, Value: s})
				}
			}
			environments[i] = append(entry, jsjson.Member{Key: "selected", Value: selected(e)})
		}
		return r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "environments", Value: environments}})
	}
	if !itemsOK || items == nil {
		return &clientctx.TypeError{Message: "envs.items is not iterable"}
	}
	list, err := iterate(items, "envs.items")
	if err != nil {
		return err
	}
	for _, e := range list {
		name, nameOK, err := read(e, true, "name")
		if err != nil {
			return err
		}
		tier, _ := jsval.Get(e, "tier")
		kind, _ := jsval.Get(e, "kind")
		var marks []string
		for _, m := range []any{tier, kind} {
			if jsjson.Truthy(m) {
				marks = append(marks, shownValue(jsjson.String(m)))
			}
		}
		if selected(e) {
			marks = append(marks, "selected")
		}
		if err := r.println(Printable(shownValue(jsTemplate(name, nameOK))) + "  (" + Printable(strings.Join(marks, ", ")) + ")"); err != nil {
			return err
		}
	}
	return nil
}

// envUse is `varlatch env use <environment>`: the repository's local
// selection, and its tier cached (ADR-0032) when the server can be asked.
// Caching is best effort: offline or unauthenticated selection still
// succeeds, without a tier. `env use` is the only writer of the cache;
// `env list` runs in CI across tracked directories and never writes.
func (r *Run) envUse() error {
	if len(r.Args) < 2 {
		return UsageOnly(envUseUsage)
	}
	name := r.Args[1]
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	root := clientctx.FindRepoRoot(cwd)
	if root == "" {
		return Fail("No "+clientctx.RepoConfigFile+" found", ExitFailure)
	}
	tier, hasTier := r.selectedTier(cwd, name)
	state := spread(clientctx.LoadLocalState(root)).Set("selectedEnvironment", name)
	kept := jsjson.Object{}
	for _, m := range state {
		if m.Key != "selectedTier" && m.Key != "tierCachedAt" {
			kept = append(kept, m)
		}
	}
	state = kept
	note := ""
	if hasTier && jsjson.Truthy(tier) {
		// The server's word, with the bearer and every other value the run
		// holds (and any Varlatch token) taken out before it is kept, so no
		// later command, offline, can print one; what is shown is masked
		// again when it is printed.
		if text, ok := tier.(string); ok {
			tier = RedactOutput(text, r.inFlight...)
		} else if tier, err = RedactValue(tier, r.inFlight...); err != nil {
			return err
		}
		state = state.Set("selectedTier", tier).Set("tierCachedAt", isoString(time.Now().UTC()))
		note = " (tier " + Printable(shownValue(jsjson.String(tier))) + ")"
	}
	if err := clientctx.SaveLocalState(root, state); err != nil {
		return err
	}
	return r.println("Selected " + shownValue(name) + " for this repository" + note + ".")
}

// selectedTier is the tier of the Environment named name, as the server
// lists it, when there is a credential to ask with; any failure leaves it
// unknown (false).
func (r *Run) selectedTier(cwd, name string) (any, bool) {
	ctx, err := clientctx.ResolveContext(clientctx.ResolveOptions{Cwd: cwd, Environment: name}, r.Env)
	if err != nil {
		return nil, false
	}
	server, err := serverString(ctx.Server)
	if err != nil {
		return nil, false
	}
	token, err := r.loadToken(server)
	if err != nil || token == "" {
		return nil, false
	}
	api := r.newClient(apiclient.Options{
		Server:              server,
		Token:               token,
		UserAgent:           r.UserAgent(),
		OnMaintenance:       r.maintenanceNotice,
		OnCredentialExpires: r.credentialExpiryNotice(server, token),
		Env:                 r.Env,
	})
	envs, err := api.ListEnvironments(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		return nil, false
	}
	items, ok := getOptional(envs, "items")
	list, isArray := items.([]any)
	if !ok || !isArray {
		return nil, false // `.find` on anything else throws, and the throw is swallowed
	}
	for _, e := range list {
		if e == nil {
			return nil, false // e.name throws
		}
		if v, ok := jsval.Get(e, "name"); ok && jsval.StrictEqual(v, name) {
			return jsval.Get(e, "tier")
		}
	}
	return nil, false
}

// shellSafe is members.ts's shellWord's set of characters a POSIX shell
// reads as they are.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// shellWord is members.ts's shellWord: word as one POSIX shell word, as it
// is when it holds only characters a shell reads as they are, else in
// single quotes.
func shellWord(word string) string {
	if shellSafe.MatchString(word) {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

// commandServer is a server as a suggested command names it: its display
// form (shownServer), as one shell word, so a command copied from the
// message runs as shown (an IPv6 address's brackets are quoted).
func commandServer(server string) string { return shellWord(shownServer(server)) }

// loginCommandFor is `varlatch login --server <server>` and suffix.
func loginCommandFor(server, suffix string) string {
	return "varlatch login --server " + commandServer(server) + suffix
}
