// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The audit export to object storage (slice 5.7c of internal
// docs/design/go-cli.md): main.ts's auditExportCommand with auditExport.ts
// (ADR-0056), and `audit export [--deleted-org]` (ADR-0051 Decision 8).
// The secret access key comes from standard input, a file or a hidden
// prompt, never the command line; it is held for the run, so no output
// shows it. Everything the command line can get wrong is refused before
// any request, and removal names the Organization again with --confirm.

var auditExportUsage = func() string {
	destination := "[--endpoint <url>] [--region <region>] [--bucket <bucket>] [--prefix <prefix>] [--path-style | --no-path-style]"
	key := "--access-key-id <id> [--secret-stdin | --secret-file <path>]"
	scope := "[--org <organization>] [--server <url>]"
	return strings.Join([]string{
		"Usage: varlatch audit-export show [--json] " + scope,
		"       varlatch audit-export create --endpoint <url> --region <region> --bucket <bucket> [--prefix <prefix>] [--path-style]",
		"                                    " + key + " [--retention <compliance|governance>:<days>] [--from <beginning|now>] [--json] " + scope,
		"       varlatch audit-export change " + destination,
		"                                    [--retention <mode>:<days> | --no-retention] [--json] " + scope,
		"       varlatch audit-export change " + key + " [--json] " + scope,
		"       varlatch audit-export remove --confirm <organization> [--json] " + scope,
		"       varlatch audit-export check [" + destination[1:len(destination)-1] + "] [" + key + "] [--retention <mode>:<days>] [--json] " + scope,
	}, "\n")
}()

const deletedOrgExportUsage = "Usage: varlatch audit export --deleted-org <organization-id> [--server <url>]"

var auditExportSubcommands = []string{"show", "create", "change", "remove", "check"}

// auditExportFailure is AuditExportError: nothing to act on (1).
type auditExportFailure struct{ message string }

func (e *auditExportFailure) Error() string { return e.message }

var retentionPattern = regexp.MustCompile(`^(compliance|governance):([1-9][0-9]{0,3})$`)

// parseRetention is auditExport.ts's parseRetention: `<mode>:<days>`.
func parseRetention(raw string) (jsjson.Object, error) {
	m := retentionPattern.FindStringSubmatch(raw)
	days := 0.0
	if m != nil {
		days, _ = strconv.ParseFloat(m[2], 64)
	}
	if m == nil || days > 3650 {
		return nil, errors.New("--retention takes <compliance|governance>:<days>, days from 1 to 3650: " + raw)
	}
	return jsjson.Object{{Key: "mode", Value: m[1]}, {Key: "days", Value: days}}, nil
}

// destinationFields is auditExport.ts's destinationFields: the fields the
// command line names, in the TypeScript object's order.
func destinationFields(parsed *ParsedOptions) (jsjson.Object, error) {
	if parsed.Has("--path-style") && parsed.Has("--no-path-style") {
		return nil, errors.New("--path-style and --no-path-style cannot both be given")
	}
	out := jsjson.Object{}
	for _, f := range []string{"endpoint", "region", "bucket", "prefix"} {
		if v, ok := parsed.Value("--" + f); ok {
			out = append(out, jsjson.Member{Key: f, Value: v})
		}
	}
	if parsed.Has("--path-style") {
		out = append(out, jsjson.Member{Key: "pathStyle", Value: true})
	}
	if parsed.Has("--no-path-style") {
		out = append(out, jsjson.Member{Key: "pathStyle", Value: false})
	}
	return out, nil
}

// keyRequested is auditExport.ts's keyRequested: whether the command line
// names a key; then one secret source comes with it.
func keyRequested(parsed *ParsedOptions) (bool, error) {
	_, file := parsed.Value("--secret-file")
	stdin := parsed.Has("--secret-stdin")
	_, id := parsed.Value("--access-key-id")
	if stdin && file {
		return false, errors.New("give the secret access key one way only: --secret-stdin or --secret-file <path>")
	}
	if (stdin || file) && !id {
		return false, errors.New("--secret-stdin and --secret-file go with --access-key-id")
	}
	return id, nil
}

// createInput is auditExport.ts's createInput: create's body without the key.
func createInput(parsed *ParsedOptions) (jsjson.Object, string, error) {
	d, err := destinationFields(parsed)
	if err != nil {
		return nil, "", err
	}
	if parsed.Has("--no-path-style") {
		return nil, "", errors.New("create takes --path-style or nothing (virtual-hosted)")
	}
	for _, flag := range []string{"--endpoint", "--region", "--bucket"} {
		if _, ok := parsed.Value(flag); !ok {
			return nil, "", errors.New("create needs " + flag)
		}
	}
	if _, ok := parsed.Value("--access-key-id"); !ok {
		return nil, "", errors.New("create needs --access-key-id, and the secret by --secret-stdin, --secret-file or the prompt")
	}
	if parsed.Has("--no-retention") {
		return nil, "", errors.New("--no-retention goes with change; create without --retention sets none")
	}
	from, ok := parsed.Value("--from")
	if !ok {
		from = "beginning"
	}
	if from != "beginning" && from != "now" {
		return nil, "", errors.New("--from takes beginning or now: " + from)
	}
	var retention any // null
	if raw, ok := parsed.Value("--retention"); ok {
		if retention, err = parseRetention(raw); err != nil {
			return nil, "", err
		}
	}
	return jsjson.Object{{Key: "destination", Value: d}, {Key: "retention", Value: retention}, {Key: "from", Value: from}}, from, nil
}

// changeRequest is auditExport.ts's ChangeRequest: the destination and
// retention, or the key on its own.
type changeRequest struct {
	key          bool
	destination  jsjson.Object
	retention    any // jsjson.Object, nil for --no-retention
	hasRetention bool
}

func parseChangeRequest(parsed *ParsedOptions) (*changeRequest, error) {
	destination, err := destinationFields(parsed)
	if err != nil {
		return nil, err
	}
	raw, hasRaw := parsed.Value("--retention")
	if hasRaw && parsed.Has("--no-retention") {
		return nil, errors.New("--retention and --no-retention cannot both be given")
	}
	req := &changeRequest{destination: destination}
	switch {
	case hasRaw:
		if req.retention, err = parseRetention(raw); err != nil {
			return nil, err
		}
		req.hasRetention = true
	case parsed.Has("--no-retention"):
		req.hasRetention = true
	}
	settings := len(destination) > 0 || req.hasRetention
	key, err := keyRequested(parsed)
	if err != nil {
		return nil, err
	}
	if key {
		if settings {
			return nil, errors.New("change the key on its own: each change is approved separately")
		}
		return &changeRequest{key: true}, nil
	}
	if !settings {
		return nil, errors.New("name what changes: destination options, --retention or --no-retention, or a new key with --access-key-id")
	}
	return req, nil
}

// changeBody is auditExport.ts's changeInput: the change at the export's
// current version.
func changeBody(req *changeRequest, current any) jsjson.Object {
	body := member(jsjson.Object{}, "expectedVersion", at(current, "version"), true)
	if len(req.destination) > 0 {
		body = append(body, jsjson.Member{Key: "destination", Value: req.destination})
	}
	if req.hasRetention {
		body = append(body, jsjson.Member{Key: "retention", Value: req.retention})
	}
	return body
}

// checkInput is auditExport.ts's checkInput: the destination named, the
// export's own where none is; the retention named, else the export's.
func checkInput(parsed *ParsedOptions, current any) (jsjson.Object, error) {
	named, err := destinationFields(parsed)
	if err != nil {
		return nil, err
	}
	// `{ ...(base ?? {}), ...named }`: the export's fields keep their places
	// (undefined ones too, which JSON.stringify then leaves out).
	destination := jsjson.Object{}
	if current != nil {
		d := at(current, "destination")
		for _, k := range []string{"endpoint", "region", "bucket", "prefix", "pathStyle"} {
			destination = append(destination, jsjson.Member{Key: k, Value: at(d, k)})
		}
	}
	for _, m := range named {
		destination = destination.Set(m.Key, m.Value)
	}
	for _, k := range []string{"endpoint", "region", "bucket"} {
		v, ok := destination.Get(k)
		if !ok || !truthy(v) {
			return nil, errors.New("there is no export to check: give --endpoint, --region and --bucket, and a key")
		}
	}
	destination = slices.DeleteFunc(destination, func(m jsjson.Member) bool { return m.Value == undef })
	var retention any // null
	if raw, ok := parsed.Value("--retention"); ok {
		if retention, err = parseRetention(raw); err != nil {
			return nil, err
		}
	} else if current != nil {
		retention = coalesce(at(current, "retention"), nil)
	}
	return jsjson.Object{{Key: "destination", Value: destination}, {Key: "retention", Value: retention}}, nil
}

// liveExport is auditExport.ts's liveExport: the export when it is active
// or draining, else the failure naming what to do.
func liveExport(status any, organization string) any {
	e := at(status, "export")
	state := optAt(e, "state")
	if !truthy(e) || (!strictEq(state, "active") && !strictEq(state, "draining")) {
		throwJS(&auditExportFailure{organization + " has no audit export. Create one with: varlatch audit-export create ... Nothing was changed."})
	}
	return e
}

// checkLines is auditExport.ts's checkLines.
func (r *Run) checkLines(check any) []string {
	if !truthy(at(check, "ok")) {
		message := at(check, "message")
		reason := "no reason given"
		if !isNullish(message) {
			text, ok := message.(string)
			if !ok {
				throwType("text.replace is not a function")
			}
			reason = r.Secrets.ServerMessage(text)
		}
		return []string{"The destination check failed: " + reason, "Nothing was saved."}
	}
	lock := "not checked"
	if l := at(check, "objectLock"); l != nil {
		lock = wordOf(auditLockWords, l)
	}
	key := "may or may not read objects (not determined)"
	switch canRead := at(check, "keyCanRead"); {
	case canRead == nil:
	case truthy(canRead):
		key = "can read objects"
	default:
		key = "cannot read objects (write-only)"
	}
	return []string{
		"The destination passed the check: it refuses to overwrite an existing object (If-None-Match).",
		"Object Lock: " + lock + ".",
		"The key " + key + ".",
		"Nothing was saved.",
	}
}

// auditExportCommand is main.ts's auditExportCommand.
func auditExportCommand(r *Run) error {
	args := r.Args
	sub, _ := arg(args, 0)
	if !slices.Contains(auditExportSubcommands, sub) {
		return UsageOnly(auditExportUsage)
	}
	destinationValues := []string{"--endpoint", "--region", "--bucket", "--prefix"}
	keyValues := []string{"--access-key-id", "--secret-file"}
	scope := []string{"--server", "--org"}
	join := func(lists ...[]string) []string { return slices.Concat(lists...) }
	specs := map[string]OptionSpec{
		"show":   {Values: scope, Booleans: []string{"--json"}, Positionals: 1},
		"create": {Values: join(scope, destinationValues, keyValues, []string{"--retention", "--from"}), Booleans: []string{"--json", "--path-style", "--no-path-style", "--secret-stdin", "--no-retention"}, Positionals: 1},
		"change": {Values: join(scope, destinationValues, keyValues, []string{"--retention"}), Booleans: []string{"--json", "--path-style", "--no-path-style", "--secret-stdin", "--no-retention"}, Positionals: 1},
		"remove": {Values: join(scope, []string{"--confirm"}), Booleans: []string{"--json"}, Positionals: 1},
		"check":  {Values: join(scope, destinationValues, keyValues, []string{"--retention"}), Booleans: []string{"--json", "--path-style", "--no-path-style", "--secret-stdin"}, Positionals: 1},
	}
	parsed, err := strictOptions("audit-export "+sub, args, specs[sub], auditExportUsage)
	if err != nil {
		return err
	}
	wrong := func(err error) error {
		return UsageErrorWithUsage("varlatch audit-export "+sub+": "+err.Error(), "\n"+auditExportUsage)
	}
	// Everything the command line can get wrong, before any request.
	var create jsjson.Object
	var from string
	var change *changeRequest
	withKey := false
	switch sub {
	case "create":
		if create, from, err = createInput(parsed); err != nil {
			return wrong(err)
		}
	case "change":
		if change, err = parseChangeRequest(parsed); err != nil {
			return wrong(err)
		}
	}
	if sub == "create" || sub == "change" || sub == "check" {
		if withKey, err = keyRequested(parsed); err != nil {
			return wrong(err)
		}
	}
	if raw, ok := parsed.Value("--retention"); sub == "check" && ok {
		if _, err := parseRetention(raw); err != nil {
			return wrong(err)
		}
	}
	org, hasOrg := parsed.Value("--org")
	known, err := r.organizationTarget(parsed, org, hasOrg, true)
	if err != nil {
		return err
	}
	if sub == "remove" {
		confirm, confirmed := parsed.Value("--confirm")
		if confirmed && known.hasOrganization && confirm != known.organization {
			return UsageErrorWithUsage("varlatch audit-export remove: --confirm names "+confirm+", but this removes the audit export of "+known.organization+".", "\n"+auditExportUsage)
		}
		if !confirmed {
			named, plain, whose := "<organization>", "<organization>", "the organization"
			if known.hasOrganization {
				named, plain, whose = shellWord(known.organization), known.organization, known.organization
			}
			command := "varlatch audit-export remove --confirm " + named + " --org " + named + known.serverOption
			what := "Removing the audit export of " + whose + " stops the copy of its audit log; " +
				"what was delivered stays in the bucket, and a new export starts with no history unless it backfills"
			if r.Assisted.On {
				return Fail("varlatch audit-export remove: "+what+". That is the human's decision. With their approval, add --confirm "+plain+". "+
					"Or the human runs, in their own terminal:\n  "+command+"\nNothing was changed.", ExitConfig)
			}
			return UsageError(what + ". Name the organization again to confirm:\n  " + command + "\nNothing was changed.")
		}
	}
	// The secret access key: never from the command line.
	var credential jsjson.Object
	if withKey {
		secret, err := r.auditExportSecret(sub, parsed)
		if err != nil {
			return err
		}
		id, _ := parsed.Value("--access-key-id")
		credential = jsjson.Object{{Key: "accessKeyId", Value: id}, {Key: "secretAccessKey", Value: secret}}
		// A server echoing the key back gets it masked (issue #119); no output shows it.
		r.Secrets.Remember(secret)
		r.holdValue(secret)
	}
	target, err := r.requiredTarget(parsed, org, hasOrg)
	if err != nil {
		return err
	}
	api, err := (&lazyAPI{r: r, server: target.server}).get()
	if err != nil {
		return err
	}
	if _, err := r.requireCapability(api, auditExportCapability, "has no audit export to object storage; upgrade the server. Nothing was changed."); err != nil {
		return err
	}
	err = r.auditExportAct(api, sub, target.organization, parsed.Has("--json"), create, from, change, credential, parsed)
	var failure *auditExportFailure
	if errors.As(err, &failure) {
		return Fail("varlatch audit-export "+sub+": "+failure.message, ExitFailure)
	}
	var usage *auditExportUsageError
	if errors.As(err, &usage) {
		return wrong(usage.err)
	}
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) && apiErr.CodeIs("VERSION_CONFLICT") {
		return Fail("varlatch audit-export "+sub+": the export changed while this ran: "+r.Secrets.ServerMessage(apiErr.Message)+". Nothing was changed; run the command again.", ExitFailure)
	}
	return err
}

// auditExportUsageError carries a usage error found after a request (check's input).
type auditExportUsageError struct{ err error }

func (e *auditExportUsageError) Error() string { return e.err.Error() }

// auditExportSecret is main.ts's reading of the secret access key:
// --secret-stdin, --secret-file, or a hidden prompt on a terminal (never in
// assisted mode).
func (r *Run) auditExportSecret(sub string, parsed *ParsedOptions) (string, error) {
	var secret string
	var err error
	path, fromFile := parsed.Value("--secret-file")
	switch {
	case parsed.Has("--secret-stdin"):
		var b []byte
		if b, err = readAllStdin(r.Stdin); err == nil {
			secret, err = secretinput.FromBytes(b, "standard input")
		}
	case fromFile:
		secret, err = secretinput.ReadFile(path)
	case r.Assisted.On || !secretinput.IsTerminal(r.Stdin):
		assisted := ""
		if r.Assisted.On {
			assisted = "; assisted mode never prompts"
		}
		return "", UsageErrorWithUsage("varlatch audit-export "+sub+": give the secret access key with --secret-stdin or --secret-file <path>"+assisted+". Nothing was sent.", "\n"+auditExportUsage)
	default:
		secret, err = r.promptHidden("Secret access key (input hidden): ")
	}
	if err != nil {
		if _, cancelled := err.(secretinput.Cancelled); cancelled {
			return "", ExitWith(ExitInterrupted)
		}
		var s *secretinput.Error
		if errors.As(err, &s) {
			code := ExitFailure
			if s.Usage {
				code = ExitUsage
			}
			return "", Fail("varlatch audit-export "+sub+": "+s.Message+". Nothing was sent.", code)
		}
		return "", err
	}
	return secret, nil
}

// auditExportAct is the part of auditExportCommand inside its try: each
// subcommand's requests and output.
func (r *Run) auditExportAct(api *apiclient.Client, sub, org string, asJSON bool, create jsjson.Object, from string, change *changeRequest, credential jsjson.Object, parsed *ParsedOptions) error {
	head := jsjson.Object{{Key: "organization", Value: org}}
	lines := func(build func() []string) error {
		var out []string
		if err := catchJS(func() { out = build() }); err != nil {
			return err
		}
		return r.println(strings.Join(out, "\n"))
	}
	switch sub {
	case "show":
		status, err := api.GetAuditExport(bg, org)
		if err != nil {
			return err
		}
		if asJSON {
			return r.printDoc(spreadOnto(head, status))
		}
		return lines(func() []string { return r.auditExportLines(org, status) })
	case "create":
		created, err := api.CreateAuditExport(bg, org, append(slices.Clone(create), jsjson.Member{Key: "credential", Value: credential}))
		if err != nil {
			return err
		}
		if asJSON {
			return r.printDoc(member(head, "export", created, true))
		}
		start := "backfills the whole audit log"
		if from == "now" {
			start = "starts at its creation"
		}
		if err := r.println("Audit export of " + org + " created: it " + start + ", then copies every new event within about a minute."); err != nil {
			return err
		}
		return lines(func() []string {
			status := jsjson.Object{{Key: "enabled", Value: true}}
			status = member(status, "export", created, true)
			out := r.auditExportLines(org, status)
			if len(out) > 0 {
				out = out[1:]
			}
			return out
		})
	case "check":
		var current any
		if credential == nil {
			status, err := api.GetAuditExport(bg, org)
			if err != nil {
				return err
			}
			if err := catchJS(func() { current = liveExport(status, org) }); err != nil {
				return err
			}
		}
		var input jsjson.Object
		var wrongInput error
		if err := catchJS(func() { input, wrongInput = checkInput(parsed, current) }); err != nil {
			return err
		}
		if wrongInput != nil {
			return &auditExportUsageError{wrongInput}
		}
		if credential != nil {
			input = append(input, jsjson.Member{Key: "credential", Value: credential})
		}
		checked, err := api.CheckAuditExport(bg, org, input)
		if err != nil {
			return err
		}
		if asJSON {
			if err := r.printDoc(spreadOnto(head, checked)); err != nil {
				return err
			}
		} else if err := lines(func() []string { return r.checkLines(checked) }); err != nil {
			return err
		}
		if !truthy(optAtValue(checked, "ok")) {
			return ExitWith(ExitFailure)
		}
		return nil
	}
	status, err := api.GetAuditExport(bg, org)
	if err != nil {
		return err
	}
	var current any
	if err := catchJS(func() { current = liveExport(status, org) }); err != nil {
		return err
	}
	version, hasVersion := jsjsonGet(current, "version")
	if sub == "remove" {
		removed, err := api.RemoveAuditExport(bg, org, version, hasVersion)
		if err != nil {
			return err
		}
		if asJSON {
			return r.printDoc(member(head, "export", removed, true))
		}
		return r.println("The audit export of " + org + " was removed; its key was cleared. What it delivered stays in the bucket.")
	}
	if change.key {
		body := member(jsjson.Object{}, "expectedVersion", version, hasVersion)
		replaced, err := api.ReplaceAuditExportCredential(bg, org, append(body, jsjson.Member{Key: "credential", Value: credential}))
		if err != nil {
			return err
		}
		if asJSON {
			return r.printDoc(member(head, "export", replaced, true))
		}
		return lines(func() []string {
			return []string{"The key of the audit export of " + Printable(org) + " was replaced; delivery continues with it (version " + safeOf(at(replaced, "version")) + ")."}
		})
	}
	var body jsjson.Object
	if err := catchJS(func() { body = changeBody(change, current) }); err != nil {
		return err
	}
	result, err := api.ChangeAuditExport(bg, org, body)
	if err != nil {
		return err
	}
	if asJSON {
		return r.printDoc(spreadOnto(head, result))
	}
	return r.printLinesOf(func() []string {
		if !truthy(at(result, "changed")) {
			return []string{"The audit export of " + org + " already has these settings. Nothing was changed."}
		}
		e := at(result, "export")
		line := "The audit export of " + Printable(org) + " was changed (version " + safeOf(at(e, "version")) + ")"
		if truthy(at(result, "loosened")) {
			line += "; your approval was used"
		}
		out := []string{line + "."}
		if !strictEq(at(e, "streamId"), at(current, "streamId")) {
			out = append(out, "It now writes a new stream, "+safeOf(at(e, "streamId"))+", from position "+safeOf(at(e, "cursor"))+"; the old bucket keeps what it received.")
		}
		return out
	})
}

// jsjsonGet is x[key] with whether x has it, for a JSON object.
func jsjsonGet(x any, key string) (any, bool) {
	if o, ok := x.(jsjson.Object); ok {
		return o.Get(key)
	}
	return nil, false
}

// auditExportEvents is main.ts's `audit export` with and without
// --deleted-org: the log as NDJSON, written as the server sent it (through
// the fail-safe).
func (r *Run) auditExportEvents() error {
	if slices.Contains(r.Args, "--deleted-org") {
		// ADR-0051 Decision 8: a deleted Organization's log, for its readers;
		// no repository or live Organization is involved.
		parsed, err := strictOptions("audit export", r.Args, OptionSpec{Values: []string{"--deleted-org", "--server"}, Positionals: 1}, deletedOrgExportUsage)
		if err != nil {
			return err
		}
		organizationID, ok := parsed.Value("--deleted-org")
		if !ok {
			return UsageOnly(deletedOrgExportUsage)
		}
		cwd, err := Cwd()
		if err != nil {
			return err
		}
		given, _ := parsed.Value("--server")
		resolved, err := clientctx.ResolveServer(cwd, given, r.Env)
		if err != nil {
			return contextError(err)
		}
		if resolved == nil {
			return UsageErrorWithUsage("Provide --server <url>", "\n"+deletedOrgExportUsage)
		}
		server, err := serverString(resolved.Server)
		if err != nil {
			return err
		}
		api, err := (&lazyAPI{r: r, server: server}).get()
		if err != nil {
			return err
		}
		text, err := api.ExportDeletedOrganizationAuditEventsNDJSON(bg, organizationID)
		if err != nil {
			return err
		}
		return r.out(text)
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	text, err := api.ExportAuditEventsNDJSON(bg, ctx.Organization)
	if err != nil {
		return err
	}
	return r.out(text)
}
