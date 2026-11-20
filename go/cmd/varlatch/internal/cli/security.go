// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The security commands (slice 5.7b of internal docs/design/go-cli.md):
// `security status` (securityStatus.ts), `security report`
// (securityReport.ts), `security controls` and `security set`
// (securityControls.ts), and main.ts's `case "security"`. Loosening a
// control goes through the client's step-up handling (approvals.go), as
// the TypeScript CLI's does.

const (
	securityReportUsage   = "Usage: varlatch security report [--json] [--org <organization>] [--server <url>]"
	securityStatusUsage   = "Usage: varlatch security status [--json] [--org <organization>] [--server <url>]"
	securityControlsUsage = "Usage: varlatch security controls [--json] [--org <organization>] [--server <url>]"
	securitySetUsage      = "Usage: varlatch security set <control> <off|report|enforce> [--default-ttl <seconds>] [--max-ttl <seconds>] [--clear-config] " +
		"[--approval <id>] [--json] [--org <organization>] [--server <url>]"
)

const (
	securityControlsCapability       = "security.controls"
	credentialReviewCapability       = "security.credential-review"
	refusedDestinationsCapability    = "security.refused-destinations"
	securityDocs                     = "https://docs.varlatch.com"
	securityStatusEntriesShownAsText = 3
)

var (
	controlNames = []string{"requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"}
	controlModes = []string{"off", "report", "enforce"}
)

// securityUsageError is SecurityUsageError: a command line that cannot be
// right (64).
type securityUsageError struct{ message string }

func (e *securityUsageError) Error() string { return e.message }

// securityFailure is SecurityControlsError, SecurityStatusUnsupportedError
// and CredentialReviewUnsupportedError: the server cannot do it (1).
type securityFailure struct{ message string }

func (e *securityFailure) Error() string { return e.message }

// securityCommand is main.ts's `case "security"`.
func securityCommand(r *Run) error {
	args := r.Args
	sub, _ := arg(args, 0)
	if sub == "controls" || sub == "set" {
		return r.securityControls(sub, args[1:])
	}
	if sub == "status" {
		parsed, err := strictOptions("security status", args[1:], OptionSpec{Values: []string{"--server", "--org"}, Booleans: []string{"--json"}}, securityStatusUsage)
		if err != nil {
			return err
		}
		server, organization, err := r.securityScope("status", parsed, securityStatusUsage)
		if err != nil {
			return err
		}
		lazy := &lazyAPI{r: r, server: server}
		status, err := r.fetchSecurityStatus(lazy, organization)
		if err != nil {
			return r.securityError(err, "")
		}
		if parsed.Has("--json") {
			return r.printDoc(status)
		}
		var lines []string
		if err := catchJS(func() { lines = r.securityStatusLines(status, nowMS()) }); err != nil {
			return err
		}
		return r.println(strings.Join(lines, "\n"))
	}
	// Visibility only (ADR-0054 Decision 8): a report, never a change.
	command := strings.TrimSpace("security " + sub)
	parsed, err := strictOptions(command, args, OptionSpec{Values: []string{"--server", "--org"}, Booleans: []string{"--json"}, Positionals: 1}, securityReportUsage)
	if err != nil {
		return err
	}
	if p, _ := arg(parsed.Positionals, 0); p != "report" {
		return UsageOnly(securityReportUsage)
	}
	server, organization, err := r.securityScope("report", parsed, securityReportUsage)
	if err != nil {
		return err
	}
	lazy := &lazyAPI{r: r, server: server}
	review, refused, err := r.fetchSecurityReport(lazy, organization)
	if err != nil {
		return r.securityError(err, "")
	}
	if parsed.Has("--json") {
		doc := jsjson.Object{{Key: "organization", Value: organization}}
		doc = member(doc, "credentialReview", review, true)
		switch {
		case refused.shown:
			doc = member(doc, "refusedDestinations", refused.destinations, true)
		case refused.reason == "not-permitted":
			doc = append(doc, jsjson.Member{Key: "refusedDestinations", Value: nil})
		}
		return r.printDoc(doc)
	}
	var lines []string
	if err := catchJS(func() {
		now := nowMS()
		lines = append(credentialReviewLines(organization, review, now), refusedDestinationLines(organization, refused, now)...)
	}); err != nil {
		return err
	}
	return r.println(strings.Join(lines, "\n"))
}

// securityScope is main.ts's securityScope: the organization and server
// from the options, else the repository. Outside a repository a default
// server (ADR-0058 Decision 1) may name the server; --org stays required.
func (r *Run) securityScope(sub string, parsed *ParsedOptions, usage string) (string, string, error) {
	cwd, err := Cwd()
	if err != nil {
		return "", "", err
	}
	server, hasServer := parsed.Value("--server")
	if !hasServer {
		server, hasServer = r.Env.LookupEnv("VARLATCH_SERVER")
	}
	organization, hasOrg := parsed.Value("--org")
	inRepo := clientctx.FindRepoRoot(cwd) != ""
	if server == "" && !inRepo {
		resolved, err := clientctx.ResolveServer(cwd, "", r.Env)
		if err != nil {
			return "", "", contextError(err)
		}
		hasServer = false
		if resolved != nil {
			s, err := serverString(resolved.Server)
			if err != nil {
				return "", "", err
			}
			server, hasServer = s, true
		}
	}
	if server == "" || organization == "" {
		if !inRepo {
			return "", "", UsageErrorWithUsage("varlatch security "+sub+": run it inside a varlatch repository, or pass --org <organization> and --server <url>", "\n"+usage)
		}
		options := clientctx.ResolveOptions{Cwd: cwd, Environment: "(unused)"}
		if server != "" {
			options.Server = server
		}
		ctx, err := clientctx.ResolveContext(options, r.Env)
		if err != nil {
			return "", "", contextError(err)
		}
		if !hasServer {
			if server, err = serverString(ctx.Server); err != nil {
				return "", "", err
			}
		}
		if !hasOrg {
			organization = ctx.Organization
		}
	}
	return server, organization, nil
}

// securityError is main.ts's catch around the security commands: the
// failures they name (1), a usage error naming set's usage (64), the API
// errors `security set` words itself, and anything else as main.ts's
// catch maps it.
func (r *Run) securityError(err error, setUsage string) error {
	var wrong *securityUsageError
	if errors.As(err, &wrong) {
		return UsageErrorWithUsage("varlatch security set: "+wrong.message, "\n"+setUsage)
	}
	var failure *securityFailure
	if errors.As(err, &failure) {
		return Fail(failure.message, ExitFailure)
	}
	var api *apiclient.APIError
	if setUsage != "" && errors.As(err, &api) {
		if api.CodeIs("CONTROL_MODE_UNAVAILABLE") {
			return Fail("varlatch security set: "+r.Secrets.ServerMessage(api.Message)+". Nothing was changed."+r.requestNote(api), ExitFailure)
		}
		if api.CodeIs("VERSION_CONFLICT") {
			return Fail("varlatch security set: the control changed while this ran: "+r.Secrets.ServerMessage(api.Message)+". Nothing was changed; run the command again.", ExitFailure)
		}
	}
	return err
}

// metaCapabilities is `const meta = await api.meta()` and
// `meta.capabilities.includes(c)` for each c asked, with the server's
// version as safeVersion shows it ("an older release" when it does not).
type metaCapabilities struct {
	r       *Run
	meta    any
	version string
}

func (r *Run) readMeta(api *apiclient.Client) (*metaCapabilities, error) {
	meta, err := api.Meta(bg)
	if err != nil {
		return nil, err
	}
	version, _ := jsval.Get(meta, "serverVersion")
	shown, ok := r.Secrets.SafeVersion(version)
	if !ok {
		shown = "an older release"
	}
	return &metaCapabilities{r: r, meta: meta, version: shown}, nil
}

func (m *metaCapabilities) has(capability string) (bool, error) {
	capabilities, ok, err := read(m.meta, m.meta != apiclient.Undefined, "capabilities")
	if err != nil {
		return false, err
	}
	return includes(capabilities, ok, capability, "meta.capabilities.includes")
}

// ---------------------------------------------------------------------------
// security controls and security set

// setRequest is securityControls.ts's SetRequest.
type setRequest struct {
	control, mode      string
	defaultTTL, maxTTL float64
	hasDefault, hasMax bool
	clearConfig        bool
}

var ttlPattern = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)

func ttlSeconds(flag, raw string, given bool) (float64, bool, error) {
	if !given {
		return 0, false, nil
	}
	if !ttlPattern.MatchString(raw) {
		return 0, false, &securityUsageError{flag + " takes a whole number of seconds, more than 0: " + raw}
	}
	n, _ := strconv.ParseFloat(raw, 64)
	return n, true, nil
}

// parseSetRequest is securityControls.ts's parseSetRequest: `security
// set`'s arguments checked before any request.
func parseSetRequest(parsed *ParsedOptions) (*setRequest, error) {
	control, _ := arg(parsed.Positionals, 0)
	mode, _ := arg(parsed.Positionals, 1)
	if control == "" || mode == "" {
		return nil, &securityUsageError{"give the control and the mode"}
	}
	if !slices.Contains(controlNames, control) {
		return nil, &securityUsageError{"no control " + control + "; the controls are " + strings.Join(controlNames, ", ")}
	}
	if !slices.Contains(controlModes, mode) {
		return nil, &securityUsageError{"no mode " + mode + "; the modes are " + strings.Join(controlModes, ", ")}
	}
	req := &setRequest{control: control, mode: mode, clearConfig: parsed.Has("--clear-config")}
	var err error
	raw, given := parsed.Value("--default-ttl")
	if req.defaultTTL, req.hasDefault, err = ttlSeconds("--default-ttl", raw, given); err != nil {
		return nil, err
	}
	raw, given = parsed.Value("--max-ttl")
	if req.maxTTL, req.hasMax, err = ttlSeconds("--max-ttl", raw, given); err != nil {
		return nil, err
	}
	if (req.hasDefault || req.hasMax || req.clearConfig) && control != "credential-lifetime" {
		return nil, &securityUsageError{"--default-ttl, --max-ttl and --clear-config go with credential-lifetime only"}
	}
	if req.clearConfig && (req.hasDefault || req.hasMax) {
		return nil, &securityUsageError{"--clear-config cannot be combined with --default-ttl or --max-ttl"}
	}
	if req.hasDefault && req.hasMax && req.defaultTTL > req.maxTTL {
		return nil, &securityUsageError{"--default-ttl cannot be more than --max-ttl"}
	}
	return req, nil
}

// securityControls is main.ts's `security controls` and `security set`.
func (r *Run) securityControls(sub string, args []string) error {
	usage := securityControlsUsage
	spec := OptionSpec{Values: []string{"--server", "--org"}, Booleans: []string{"--json"}}
	if sub == "set" {
		usage = securitySetUsage
		spec = OptionSpec{Values: []string{"--server", "--org", "--default-ttl", "--max-ttl"}, Booleans: []string{"--json", "--clear-config"}, Positionals: 2}
	}
	parsed, err := strictOptions("security "+sub, args, spec, usage)
	if err != nil {
		return err
	}
	var request *setRequest
	if sub == "set" {
		if request, err = parseSetRequest(parsed); err != nil {
			return r.securityError(err, usage)
		}
	}
	server, organization, err := r.securityScope(sub, parsed, usage)
	if err != nil {
		return err
	}
	lazy := &lazyAPI{r: r, server: server}
	if request == nil {
		list, err := r.fetchControls(lazy, organization)
		if err != nil {
			return r.securityError(err, usage)
		}
		if parsed.Has("--json") {
			return r.printDoc(spreadOnto(jsjson.Object{{Key: "organization", Value: organization}}, list))
		}
		var lines []string
		if err := catchJS(func() { lines = controlsLines(organization, list) }); err != nil {
			return err
		}
		return r.println(strings.Join(lines, "\n"))
	}
	before, change, err := r.setControl(lazy, organization, request)
	if err != nil {
		return r.securityError(err, usage)
	}
	if parsed.Has("--json") {
		return r.printDoc(spreadOnto(jsjson.Object{{Key: "organization", Value: organization}}, change))
	}
	var lines []string
	if err := catchJS(func() { lines = setLines(organization, at(before, "mode"), change) }); err != nil {
		return err
	}
	return r.println(strings.Join(lines, "\n"))
}

// spreadOnto is `{ ...head, ...v }`: v's own properties after head's,
// replacing one of the same name in its place.
func spreadOnto(head jsjson.Object, v any) jsjson.Object {
	out := slices.Clone(head)
	for _, m := range spread(v) {
		out = out.Set(m.Key, m.Value)
	}
	return out
}

// requireControls is securityControls.ts's requireCapability.
func (r *Run) requireControls(api *apiclient.Client, command string) error {
	meta, err := r.readMeta(api)
	if err != nil {
		return err
	}
	ok, err := meta.has(securityControlsCapability)
	if err != nil {
		return err
	}
	if !ok {
		return &securityFailure{"varlatch " + command + ": this server (" + meta.version + ") has no security controls " +
			"(it lacks the " + securityControlsCapability + " capability); upgrade the server."}
	}
	return nil
}

// fetchControls is securityControls.ts's fetchControls.
func (r *Run) fetchControls(lazy *lazyAPI, organization string) (any, error) {
	api, err := lazy.get()
	if err != nil {
		return nil, err
	}
	if err := r.requireControls(api, "security controls"); err != nil {
		return nil, err
	}
	return api.ListSecurityControls(bg, organization)
}

// modesOf is securityControls.ts's modesOf: the control's own modes where
// the server gives them, the list's otherwise.
func modesOf(list, control any) any {
	return coalesce(at(control, "availableModes"), at(list, "availableModes"))
}

// enforceable is securityControls.ts's enforceable: the controls this
// server can enforce.
func enforceable(list any) []any {
	out := []any{}
	for _, c := range array(at(list, "items"), "list.items", "filter") {
		if has(modesOf(list, c), "enforce", "modesOf(...).includes") {
			out = append(out, at(c, "control"))
		}
	}
	return out
}

// setControl is securityControls.ts's setControl: the control's current
// version (and lifetimes) read, a mode this server does not offer
// refused, then the change sent. Every check comes before the one write.
func (r *Run) setControl(lazy *lazyAPI, organization string, request *setRequest) (before any, change any, err error) {
	api, err := lazy.get()
	if err != nil {
		return nil, nil, err
	}
	if err := r.requireControls(api, "security set"); err != nil {
		return nil, nil, err
	}
	list, err := api.ListSecurityControls(bg, organization)
	if err != nil {
		return nil, nil, err
	}
	var current any
	var body jsjson.Object
	var failure error
	if err := catchJS(func() {
		for _, c := range array(at(list, "items"), "list.items", "find") {
			if strictEq(at(c, "control"), request.control) {
				current = c
				break
			}
		}
		if current == nil {
			failure = &securityFailure{"varlatch security set: this server has no control " + request.control + ". Nothing was changed."}
			return
		}
		offered := modesOf(list, current)
		if !has(offered, request.mode, "offered.includes") {
			failure = &securityFailure{"varlatch security set: this server does not offer the mode " + request.mode + " for " + request.control + " yet " +
				"(it offers " + Printable(join(offered, ", ", "offered")) + "). Nothing was changed."}
			return
		}
		body, failure = changeInput(request, current)
	}); err != nil {
		return nil, nil, err
	}
	if failure != nil {
		return nil, nil, failure
	}
	change, err = api.ChangeSecurityControl(bg, organization, request.control, body)
	if err != nil {
		return nil, nil, err
	}
	return current, change, nil
}

// changeInput is securityControls.ts's changeInput: the requested mode,
// and the configuration it sets, keeps or clears.
func changeInput(request *setRequest, current any) (jsjson.Object, error) {
	input := jsjson.Object{{Key: "mode", Value: request.mode}}
	input = member(input, "expectedVersion", at(current, "version"), true)
	if request.clearConfig {
		return append(input, jsjson.Member{Key: "config", Value: nil}), nil
	}
	if !request.hasDefault && !request.hasMax {
		return input, nil
	}
	config := optAt(current, "config")
	var defaultTTL, maxTTL any = request.defaultTTL, request.maxTTL
	if !request.hasDefault {
		defaultTTL = optAt(config, "defaultTtlSeconds")
	}
	if !request.hasMax {
		maxTTL = optAt(config, "maxTtlSeconds")
	}
	if defaultTTL == undef || maxTTL == undef {
		return nil, &securityUsageError{"credential-lifetime has no lifetimes yet: give both --default-ttl and --max-ttl"}
	}
	if gt(defaultTTL, maxTTL) {
		return nil, &securityUsageError{"the default lifetime (" + js(defaultTTL) + " s) cannot be more than the maximum (" + js(maxTTL) + " s)"}
	}
	return append(input, jsjson.Member{Key: "config", Value: jsjson.Object{{Key: "defaultTtlSeconds", Value: defaultTTL}, {Key: "maxTtlSeconds", Value: maxTTL}}}), nil
}

// configWords is securityControls.ts's configWords.
func configWords(config any) string {
	if !truthy(config) {
		return ""
	}
	return "default " + lifetime(num(at(config, "defaultTtlSeconds"))) + ", at most " + lifetime(num(at(config, "maxTtlSeconds")))
}

// changedWords is securityControls.ts's changedWords.
func changedWords(c any) string {
	if strictEq(at(c, "version"), 0.0) || !truthy(at(c, "changedAt")) {
		return "never changed"
	}
	when, _ := SafeTime(at(c, "changedAt"))
	by := " by the host operator"
	if changedBy := at(c, "changedBy"); truthy(changedBy) {
		by = " by " + sval(coalesce(at(changedBy, "name"), at(changedBy, "id")))
	}
	return "changed " + when + by
}

// controlsLines is securityControls.ts's controlsLines.
func controlsLines(organization string, list any) []string {
	items := array(at(list, "items"), "list.items", "map")
	lengths := make([]any, len(items))
	for i, c := range items {
		lengths[i] = length(at(c, "control"))
	}
	width := maxLength(lengths)
	lines := []string{"Security controls for " + organization + ":"}
	for _, c := range items {
		config := configWords(at(c, "config"))
		line := "  " + shownValue(jsPadEnd(at(c, "control"), width, "c.control")) + "  " + shownValue(jsPadEnd(at(c, "mode"), 7, "c.mode"))
		if config != "" {
			line += "  " + config
		}
		lines = append(lines, line+"  (version "+sval(at(c, "version"))+", "+changedWords(c)+")")
	}
	enforcing := enforceable(list)
	modes := "Modes this server offers: " + join(at(list, "availableModes"), ", ", "list.availableModes")
	if len(enforcing) > 0 {
		modes += ", and enforce for " + join(enforcing, ", ", "enforcing") + "."
	} else {
		modes += ". enforce is not available yet."
	}
	lines = append(lines, "", modes,
		"Loosening a control (a mode towards off, a longer lifetime, cleared settings) needs your approval with a trusted passkey.")
	return printableLines(lines)
}

// setLines is securityControls.ts's setLines.
func setLines(organization string, before any, change any) []string {
	c := at(change, "control")
	configText := func() string {
		if config := at(c, "config"); truthy(config) {
			return " (" + configWords(config) + ")"
		}
		return ""
	}
	if !truthy(at(change, "changed")) {
		return []string{Printable(sval(at(c, "control")) + " in " + organization + " is already " + sval(at(c, "mode")) + configText() + ". Nothing was changed.")}
	}
	mode := at(c, "mode")
	from := ""
	if truthy(before) && !strictEq(before, mode) {
		from = sval(before) + " -> "
	}
	lines := []string{sval(at(c, "control")) + " in " + organization + ": " + from + sval(mode) + configText() + ", version " + sval(at(c, "version")) + "."}
	if truthy(at(change, "loosened")) {
		lines = append(lines, "This loosened the control; your approval was used.")
	}
	control := at(c, "control")
	if strictEq(control, "admin-step-up") && strictEq(mode, "enforce") && !strictEq(before, "enforce") {
		lines = append(lines,
			"From now on each administrative change in "+organization+" (machine identities and credentials, grants, roles, groups and teams,",
			"admins and members, integrations, deletion and .env export) needs the approval of the person asking, with a trusted passkey.",
			"Machine credentials are refused for these changes. Without a trusted passkey, the host operator can enroll one",
			"(varlatch admin reenroll) or turn the control off (varlatch admin security reset).",
		)
	}
	if strictEq(control, "passkey-verification") && strictEq(mode, "enforce") && !strictEq(before, "enforce") {
		lines = append(lines,
			"From now on "+organization+" refuses a person's sign-in that was not made with a trusted passkey that verified them (PIN, fingerprint or face),",
			"admins included, until they sign in again with one. Machine credentials are not affected.",
			"Someone whose passkeys cannot verify them gets back in only through the host operator: varlatch admin security reset.",
		)
	}
	return printableLines(lines)
}

// printableLines is `lines.map(printable)`.
func printableLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = Printable(l)
	}
	return out
}

// ---------------------------------------------------------------------------
// security report

// refusedPart is securityReport.ts's RefusedPart.
type refusedPart struct {
	shown        bool
	destinations any
	reason       string // "not-supported" or "not-permitted"
}

// notPermitted is a refusal (403) or a hiding (404).
func notPermitted(err error) bool {
	var api *apiclient.APIError
	return errors.As(err, &api) && (api.Status == 403 || api.Status == 404)
}

// fetchSecurityReport is securityReport.ts's fetchSecurityReport.
func (r *Run) fetchSecurityReport(lazy *lazyAPI, organization string) (any, refusedPart, error) {
	api, err := lazy.get()
	if err != nil {
		return nil, refusedPart{}, err
	}
	meta, err := r.readMeta(api)
	if err != nil {
		return nil, refusedPart{}, err
	}
	ok, err := meta.has(credentialReviewCapability)
	if err != nil {
		return nil, refusedPart{}, err
	}
	if !ok {
		return nil, refusedPart{}, &securityFailure{"varlatch security report: this server (" + meta.version + ") has no credential review " +
			"(it lacks the " + credentialReviewCapability + " capability); upgrade the server. " +
			"varlatch credential list <identity-id> shows one identity's credentials with their last use."}
	}
	review, err := api.CredentialReview(bg, organization)
	if err != nil {
		return nil, refusedPart{}, err
	}
	if ok, err := meta.has(refusedDestinationsCapability); err != nil {
		return nil, refusedPart{}, err
	} else if !ok {
		return review, refusedPart{reason: "not-supported"}, nil
	}
	destinations, err := api.RefusedDestinations(bg, organization)
	if err != nil {
		if notPermitted(err) {
			return review, refusedPart{reason: "not-permitted"}, nil
		}
		return nil, refusedPart{}, err
	}
	return review, refusedPart{shown: true, destinations: destinations}, nil
}

// ago is securityReport.ts's ago: "3 days ago", "5 hours ago", "just now".
func ago(when any, now float64) string {
	parsed, ok := jsval.DateParse(js(when))
	if !ok {
		parsed = math.NaN()
	}
	seconds := math.Max(0, math.Floor((now-parsed)/1000))
	unit := func(n float64, word string) string {
		s := jsNum(n) + " " + word
		if n != 1 {
			s += "s"
		}
		return s + " ago"
	}
	switch {
	case seconds < 60:
		return "just now"
	case seconds < 3600:
		return unit(math.Floor(seconds/60), "minute")
	case seconds < 86400:
		return unit(math.Floor(seconds/3600), "hour")
	}
	return unit(math.Floor(seconds/86400), "day")
}

// identityWords is securityReport.ts's identityWords.
func identityWords(identity any) string {
	state := ""
	switch {
	case strictEq(at(identity, "state"), "live"):
	case strictEq(at(identity, "disabledReason"), "organization-deletion"):
		state = ", suspended by the organization's deletion"
	default:
		state = ", " + sval(at(identity, "state"))
	}
	return sval(at(identity, "name")) + " (" + sval(at(identity, "id")) + ", " + sval(at(identity, "kind")) + state + ")"
}

// credentialLine is securityReport.ts's credentialLine.
func credentialLine(c any, now float64) string {
	lastUsed := "never"
	if v := at(c, "lastUsedAt"); truthy(v) {
		lastUsed = ago(v, now)
	}
	expires := "no expiry"
	if v := at(c, "expiresAt"); truthy(v) {
		expires = "expires " + templateTime(v)
	}
	facts := []string{"last used " + lastUsed, expires, "created " + ago(at(c, "createdAt"), now)}
	if issuedBy := at(c, "issuedBy"); truthy(issuedBy) {
		facts = append(facts, "issued by "+sval(at(issuedBy, "name")))
	}
	return "  " + sval(at(c, "id")) + "  " + sval(coalesce(at(c, "name"), "unnamed")) + "  for " + identityWords(at(c, "identity")) + ": " + strings.Join(facts, ", ")
}

// usagePolicyLine is securityReport.ts's usagePolicyLine.
func usagePolicyLine(review any) string {
	summary := at(review, "summary")
	listed := at(summary, "listed")
	of := "of " + pl(at(summary, "reviewed"), "machine credential", "machine credentials")
	if strictEq(listed, 0.0) {
		return "Use and expiry policy: none " + of + " is unused or without expiry."
	}
	verb := "are"
	if strictEq(listed, 1.0) {
		verb = "is"
	}
	return "Use and expiry policy: " + sval(listed) + " " + of + " " + verb + " never used, unused for " + sval(at(review, "idleDays")) + " days, or without expiry."
}

// expiryLine is securityReport.ts's expiryLine.
func expiryLine(expiry any) string {
	summary := at(expiry, "summary")
	soon, expired := at(summary, "soon"), at(summary, "expired")
	warningDays := sval(at(expiry, "warningDays"))
	if strictEq(soon, 0.0) && strictEq(expired, 0.0) {
		return "Expiry warnings: no service credential expires within " + warningDays + " days or has expired."
	}
	var parts []string
	if gt(soon, 0.0) {
		parts = append(parts, pl(soon, "service credential expires", "service credentials expire")+" within "+warningDays+" days")
	}
	if gt(expired, 0.0) {
		parts = append(parts, pl(expired, "has", "have")+" expired")
	}
	return "Expiry warnings: " + strings.Join(parts, ", ") + "."
}

// credentialReviewLines is securityReport.ts's credentialReviewLines.
func credentialReviewLines(organization string, review any, now float64) []string {
	summary := at(review, "summary")
	expiry := at(review, "expiry") // servers before 0.21.0 send none
	lines := []string{"Credential review for " + organization, "  " + usagePolicyLine(review)}
	if truthy(expiry) {
		lines = append(lines, "  "+expiryLine(expiry))
	}
	groups := []struct{ reason, title string }{
		{"never-used", "Never used"},
		{"idle", "Unused for " + sval(at(review, "idleDays")) + " days or more"},
		{"no-expiry", "No expiry"},
	}
	all := array(at(review, "items"), "review.items", "filter")
	for _, g := range groups {
		var items []any
		for _, c := range all {
			if has(at(c, "reasons"), g.reason, "c.reasons.includes") {
				items = append(items, c)
			}
		}
		if len(items) == 0 {
			continue
		}
		lines = append(lines, "", g.title+" ("+strconv.Itoa(len(items))+")")
		for _, c := range items {
			lines = append(lines, credentialLine(c, now))
		}
	}
	expiring := []any{}
	if items := coalesce(optAt(expiry, "items"), []any{}); true {
		if truthy(expiry) {
			expiring = array(items, "expiring", "map")
		}
	}
	if truthy(expiry) && len(expiring) > 0 {
		lines = append(lines, "", "Expires within "+sval(at(expiry, "warningDays"))+" days or expired ("+strconv.Itoa(len(expiring))+")")
		for _, c := range expiring {
			line := credentialLine(withReasons(c), now)
			if strictEq(at(c, "state"), "expired") {
				line += " (expired)"
			}
			lines = append(lines, line)
		}
	}
	last := "Reporting only: nothing is revoked or retired automatically."
	if !(strictEq(at(summary, "listed"), 0.0) && len(expiring) == 0) {
		last += " To revoke one: varlatch credential revoke <identity-id> <credential-id>"
	}
	lines = append(lines, "", last)
	return printableLines(lines)
}

// withReasons is `{ ...c, reasons: [] }`.
func withReasons(c any) any { return spreadOnto(jsjson.Object{}, c).Set("reasons", []any{}) }

// refusedKindWords is securityReport.ts's KIND_WORDS.
var refusedKindWords = map[string]string{"webhook": "webhook", "coolify": "Coolify", "convex": "Convex", "oidc-issuer": "OIDC issuer"}

// outboundRefusalLabels is @varlatch/protocol's OUTBOUND_REFUSAL_LABELS.
var outboundRefusalLabels = map[string]string{
	"private_address":   "private network address",
	"host_only_address": "loopback or link-local address",
	"never_address":     "reserved address",
	"mixed_answers":     "one of its addresses is not allowed",
	"scheme":            "plain http",
	"port":              "port not allowed",
}

// outboundHostNote is @varlatch/protocol's OUTBOUND_HOST_NOTE.
const outboundHostNote = "Private destinations are allowed by the host operator, with VARLATCH_OUTBOUND_ALLOW on the host, not in Varlatch. " +
	"Nothing waiting is lost: once the host operator allows a destination and restarts varlatchd, what waited for it is delivered."

// wordOf is `WORDS[key]` for a fixed table: "undefined" for a key it lacks.
func wordOf(table map[string]string, key any) string {
	if s, ok := key.(string); ok {
		if w, ok := table[s]; ok {
			return w
		}
	}
	return "undefined"
}

// refusedLine is securityReport.ts's refusedLine.
func refusedLine(d any, sinceDays any, now float64) string {
	what := wordOf(refusedKindWords, at(d, "kind"))
	if name := at(d, "name"); truthy(name) {
		what += ` "` + sval(name) + `"`
	}
	what += " (" + sval(at(d, "id")) + ")"
	since := "no refusal recorded in the last " + sval(sinceDays) + " days"
	if s := at(d, "since"); truthy(s) {
		since = "first recorded within the last " + sval(sinceDays) + " days: " + ago(s, now)
	}
	return "  " + what + "  " + sval(at(d, "scheme")) + "://" + sval(at(d, "host")) + ":" + sval(at(d, "port")) + "  " + wordOf(outboundRefusalLabels, at(d, "reason")) + ", " + since
}

// unresolvedLine is securityReport.ts's unresolvedLine.
func unresolvedLine(unresolved, checked any) string {
	of := ""
	if checked != undef {
		of = " of " + sval(checked)
	}
	plural := "s"
	if strictEq(unresolved, 1.0) && of == "" {
		plural = ""
	}
	names := "their names did"
	if strictEq(unresolved, 1.0) {
		names = "its name did"
	}
	return sval(unresolved) + of + " destination" + plural + " could not be checked: " + names + " not resolve. They are checked again when they connect."
}

// refusedDestinationLines is securityReport.ts's refusedDestinationLines.
func refusedDestinationLines(organization string, refused refusedPart, now float64) []string {
	if !refused.shown {
		if refused.reason == "not-permitted" {
			return []string{"", "Refused destinations: not shown, because your access does not include it (needs organization.manage)."}
		}
		return nil
	}
	d := refused.destinations
	items, sinceDays := at(d, "items"), at(d, "sinceDays")
	checked := at(d, "checked")
	unresolved := coalesce(at(d, "unresolved"), 0.0)
	if strictEq(length(items), 0.0) {
		if gt(unresolved, 0.0) {
			return printableLines([]string{"", "Refused destinations for " + organization + ": none of those checked.", "  " + unresolvedLine(unresolved, checked)})
		}
		if strictEq(checked, 0.0) {
			return []string{"", "Refused destinations for " + organization + ": none. The organization has no webhooks, Coolify or Convex connections, or OIDC issuers."}
		}
		return []string{"", "Refused destinations for " + organization + ": none. This installation connects to every destination the organization configured."}
	}
	list := array(items, "items", "map")
	lines := []string{"", "Refused destinations for " + organization + " (" + sval(length(items)) + ")"}
	for _, x := range list {
		lines = append(lines, refusedLine(x, sinceDays, now))
	}
	if gt(unresolved, 0.0) {
		lines = append(lines, "  "+unresolvedLine(unresolved, checked))
	}
	lines = append(lines, "", outboundHostNote)
	return printableLines(lines)
}

// ---------------------------------------------------------------------------
// security status

// statusSections are securityStatus.ts's StatusSection, with the words
// and permission each needs (SECTION_WORDS, NEEDS).
var (
	sectionWords = map[string]string{
		"controlReport":    "counts of the controls",
		"approvalKeys":     "admins' approval keys",
		"credentialReview": "credential review",
		"requirements":     "Tailnet Requirements",
	}
	sectionNeeds = map[string]string{
		"controlReport":    "organization.manage",
		"approvalKeys":     "organization.manage",
		"credentialReview": "identity.manage",
		"requirements":     "policy.read",
	}
)

// controlExplanations is securityStatus.ts's CONTROL_EXPLANATIONS.
var controlExplanations = map[string][2]string{
	"requirement-protection": {
		"Counts each edit or revocation of a Tailnet Requirement made without an approval. Creating one is not counted: it only restricts.",
		"Editing or revoking a Tailnet Requirement would need an approval with a trusted passkey, so a stolen admin sign-in cannot remove one from off the tailnet.",
	},
	"admin-step-up": {
		"Counts each administrative change made without an approval: machine identities and credentials, grants, roles, groups and teams, admins and members, integrations, deletion, and .env export.",
		"Those changes would need an approval with a trusted passkey. A machine credential can never give one, so it would be refused.",
	},
	"passkey-verification": {
		"Counts requests by a person's dashboard or CLI sign-in that was not made with a trusted passkey that verified them (PIN, fingerprint or face). Only requests that were allowed and succeeded count, and machine credentials never do. Access counts are best-effort: a busy server can drop some, so a count is a lower bound.",
		"Such sign-ins would be refused in this organization until the person signs in again with a trusted passkey and a PIN, fingerprint or face.",
	},
	"credential-lifetime": {
		"Counts machine credentials issued without a lifetime (they would get the default) and with one above the maximum (they would be refused). OIDC and agent-run credentials are not counted.",
		"Machine credentials would get the default lifetime when none is given, and longer ones would be refused. Existing credentials never change.",
	},
}

// securityChecklist is securityStatus.ts's CHECKLIST: id, title, why, url.
var securityChecklist = [][4]string{
	{"report-mode", "Try each control in report mode", "Report refuses nothing; its counts show what enforce would stop before you decide.", securityDocs + "/reference/security-controls/"},
	{"trusted-passkeys", "Give every admin a trusted passkey", "Only a trusted passkey can approve turning a control down or off.", securityDocs + "/getting-started/#your-passkeys"},
	{"find-files", "Find copies of secrets on disk", "varlatch scan --find-files lists .env and key files that a stolen laptop would give away.", securityDocs + "/reference/secret-scanning/#finding-copies-of-secrets"},
	{"backup-object-lock", "Keep backups where the host cannot erase them", "With Object Lock on the bucket, a compromised host cannot delete or overwrite archives.", securityDocs + "/operations/backup/#scoping-destination-credentials-per-provider"},
	{"threat-model", "Read the threat model", "What Varlatch protects against, and what it leaves to whoever runs the host.", securityDocs + "/threat-model/"},
}

func checklistDoc() []any {
	out := make([]any, len(securityChecklist))
	for i, c := range securityChecklist {
		out[i] = jsjson.Object{{Key: "id", Value: c[0]}, {Key: "title", Value: c[1]}, {Key: "why", Value: c[2]}, {Key: "url", Value: c[3]}}
	}
	return out
}

var controlOrder = []string{"requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"}

// controlRank is CONTROL_ORDER.indexOf(name): -1 for a name it lacks.
func controlRank(name any) int {
	if s, ok := name.(string); ok {
		return slices.Index(controlOrder, s)
	}
	return -1
}

// fetchSecurityStatus is securityStatus.ts's fetchSecurityStatus: the
// document `security status --json` prints, without its version.
func (r *Run) fetchSecurityStatus(lazy *lazyAPI, organization string) (jsjson.Object, error) {
	api, err := lazy.get()
	if err != nil {
		return nil, err
	}
	meta, err := r.readMeta(api)
	if err != nil {
		return nil, err
	}
	hasCap := func(capability string) (bool, error) { return meta.has(capability) }
	if ok, err := hasCap(securityControlsCapability); err != nil {
		return nil, err
	} else if !ok {
		return nil, &securityFailure{"varlatch security status: this server (" + meta.version + ") has no security controls " +
			"(it lacks the security.controls capability); upgrade the server."}
	}
	unavailable := []any{}
	missing := func(section, reason string) {
		unavailable = append(unavailable, jsjson.Object{{Key: "section", Value: section}, {Key: "reason", Value: reason}})
	}
	// The caller's own permissions, where the server can say: parts they do
	// not allow are never asked for.
	var held []any
	knowsHeld := false
	if ok, err := hasCap("organizations.permissions"); err != nil {
		return nil, err
	} else if ok {
		permissions, err := api.MyOrganizationPermissions(bg, organization)
		if err != nil {
			return nil, err
		}
		actions, aok, err := read(permissions, permissions != apiclient.Undefined, "actions")
		if err != nil {
			return nil, err
		}
		knowsHeld = true
		if aok && actions != nil {
			if held, err = iterate(actions, "permissions.actions"); err != nil {
				return nil, err
			}
		}
	}
	holds := func(action string) bool { return slices.Contains(held, any(action)) }
	part := func(section, capability string, load func() (any, error)) (any, bool, error) {
		if capability != "" {
			ok, err := hasCap(capability)
			if err != nil {
				return nil, false, err
			}
			if !ok {
				missing(section, "not-supported")
				return nil, false, nil
			}
		}
		if knowsHeld && !holds(sectionNeeds[section]) {
			missing(section, "not-permitted")
			return nil, false, nil
		}
		v, err := load()
		if err != nil {
			if !notPermitted(err) {
				return nil, false, err
			}
			missing(section, "not-permitted")
			return nil, false, nil
		}
		return v, true, nil
	}

	// Every member reads the freeze (organization.read), as the controls.
	var incidentFreeze any // nil: null
	if ok, err := hasCap("organizations.incident-freeze"); err != nil {
		return nil, err
	} else if ok {
		answer, err := api.IncidentFreeze(bg, organization)
		if err != nil {
			return nil, err
		}
		freeze, fok, err := read(answer, answer != apiclient.Undefined, "freeze")
		if err != nil {
			return nil, err
		}
		incidentFreeze = undef
		if fok {
			incidentFreeze = freeze
		}
	}
	list, err := api.ListSecurityControls(bg, organization)
	if err != nil {
		return nil, err
	}
	report, gotReport, err := part("controlReport", "security.report", func() (any, error) { return api.SecurityControlReport(bg, organization, 30) })
	if err != nil {
		return nil, err
	}
	// The approval keys need what the counts need: no second refusal when the counts were refused.
	var keys any
	countsRefused := false
	for _, u := range unavailable {
		o := u.(jsjson.Object)
		if o.Value("section") == "controlReport" && o.Value("reason") == "not-permitted" {
			countsRefused = true
		}
	}
	if !gotReport && countsRefused {
		missing("approvalKeys", "not-permitted")
	} else if keys, _, err = part("approvalKeys", "security.approval-keys", func() (any, error) { return api.SecurityApprovalKeys(bg, organization) }); err != nil {
		return nil, err
	}
	review, _, err := part("credentialReview", credentialReviewCapability, func() (any, error) { return api.CredentialReview(bg, organization) })
	if err != nil {
		return nil, err
	}
	requirements, _, err := part("requirements", "", func() (any, error) { return api.ListRequirements(bg, organization) })
	if err != nil {
		return nil, err
	}
	// The audit export: asked only where the server has it and the caller may manage the organization.
	mayManage := !knowsHeld || holds("organization.manage")
	var auditExport any
	if ok, err := hasCap("audit.storage-export"); err != nil {
		return nil, err
	} else if ok && mayManage {
		answer, err := api.GetAuditExport(bg, organization)
		if err != nil && !notPermitted(err) {
			return nil, err
		}
		if err == nil {
			auditExport = answer
		}
	}

	var doc jsjson.Object
	if err := catchJS(func() {
		items := slices.Clone(array(at(list, "items"), "list.items", "sort"))
		slices.SortStableFunc(items, func(a, b any) int { return controlRank(at(a, "control")) - controlRank(at(b, "control")) })
		shown := make([]any, len(items))
		for i, c := range items {
			var counts any // null
			if !isNullish(report) {
				for _, x := range array(at(report, "controls"), "report.controls", "find") {
					if strictEq(at(x, "control"), at(c, "control")) {
						counts = x
						break
					}
				}
			}
			o := spreadOnto(jsjson.Object{}, c)
			if name, ok := at(c, "control").(string); ok {
				if e, ok := controlExplanations[name]; ok {
					o = o.Set("explanation", jsjson.Object{{Key: "report", Value: e[0]}, {Key: "enforce", Value: e[1]}})
				} else {
					o = setOrDrop(o, "explanation", nil, false)
				}
			} else {
				o = setOrDrop(o, "explanation", nil, false)
			}
			if truthy(counts) {
				cs := jsjson.Object{}
				for _, k := range []string{"total", "currentHour", "pending", "entries"} {
					cs = member(cs, k, at(counts, k), true)
				}
				o = o.Set("counts", cs)
			} else {
				o = o.Set("counts", nil)
			}
			shown[i] = o
		}
		enforcing := enforceable(list)
		var window any // null
		if truthy(report) {
			w := jsjson.Object{}
			for _, k := range []string{"days", "since", "generatedAt"} {
				w = member(w, k, at(report, k), true)
			}
			window = w
		}
		controls := member(jsjson.Object{}, "availableModes", at(list, "availableModes"), true)
		controls = append(controls, jsjson.Member{Key: "window", Value: window}, jsjson.Member{Key: "items", Value: shown})
		var reqs any // null
		if truthy(requirements) {
			ritems := at(requirements, "items")
			ro := member(jsjson.Object{}, "count", length(ritems), true)
			ro = append(ro, jsjson.Member{Key: "protectedBy", Value: "requirement-protection"})
			reqs = member(ro, "items", ritems, true)
		}
		doc = jsjson.Object{{Key: "organization", Value: organization}, {Key: "enforceAvailable", Value: len(enforcing) > 0}, {Key: "enforceable", Value: enforcing},
			{Key: "controls", Value: controls}}
		doc = member(doc, "approvalKeys", keys, true)
		doc = member(doc, "credentialReview", review, true)
		doc = append(doc, jsjson.Member{Key: "requirements", Value: reqs}, jsjson.Member{Key: "checklist", Value: checklistDoc()}, jsjson.Member{Key: "unavailable", Value: unavailable})
		doc = member(doc, "incidentFreeze", incidentFreeze, true)
		// Last, so every earlier key keeps its place.
		doc = member(doc, "auditExport", auditExport, true)
	}); err != nil {
		return nil, err
	}
	return doc, nil
}

// until is securityStatus.ts's until: "in 3 days", "within a day".
func until(when any, now float64) string {
	parsed, ok := jsval.DateParse(js(when))
	if !ok {
		parsed = math.NaN()
	}
	days := math.Ceil((parsed - now) / 86_400_000)
	if days <= 1 {
		return "within a day"
	}
	return "in " + jsNum(days) + " days"
}

// entryLine is securityStatus.ts's entryLine.
func entryLine(e any) string {
	actor := at(e, "actor")
	who := sval(coalesce(at(actor, "name"), at(actor, "id")))
	kind := ""
	if k := at(actor, "kind"); truthy(k) && !strictEq(k, "human") {
		kind = " (" + sval(k) + ")"
	}
	return "      " + sval(at(e, "operation")) + "  " + sval(at(e, "reason")) + "  by " + who + kind + ": " + sval(at(e, "count"))
}

// securityStatusLines is securityStatus.ts's securityStatusLines.
func (r *Run) securityStatusLines(s jsjson.Object, now float64) []string {
	organization := sval(at(s, "organization"))
	lines := []string{"Security for " + organization}
	if f := at(s, "incidentFreeze"); truthy(f) {
		frozenBy := at(f, "frozenBy")
		reason, ok := at(f, "reason").(string)
		if !ok {
			throwType("text.replace is not a function")
		}
		lines = append(lines,
			"FROZEN for an incident since "+templateTime(at(f, "frozenAt"))+" by "+sval(coalesce(at(frozenBy, "name"), at(frozenBy, "id")))+": "+r.Secrets.ServerMessage(reason),
			"  Every read and write is refused except inspection, audit and recovery. Lift it: varlatch org unfreeze "+organization,
		)
	}
	controls := at(s, "controls")
	items := array(at(controls, "items"), "s.controls.items", "filter")
	var on []string
	for _, c := range items {
		if !strictEq(at(c, "mode"), "off") {
			on = append(on, sval(at(c, "control"))+" ("+sval(at(c, "mode"))+")")
		}
	}
	if len(on) == 0 {
		lines = append(lines, "Every control is off, as it is by default: nothing is counted, refused or changed.")
	} else {
		lines = append(lines, "Every control is off by default. Turned on here: "+strings.Join(on, ", ")+".")
	}

	// Controls.
	lengths := make([]any, len(items))
	for i, c := range items {
		lengths[i] = length(at(c, "control"))
	}
	width := maxLength(lengths)
	heading := "Controls"
	if window := at(controls, "window"); truthy(window) {
		heading = "Controls (counts of the last " + sval(at(window, "days")) + " days)"
	}
	lines = append(lines, "", heading)
	for _, c := range items {
		var facts []string
		if config := at(c, "config"); truthy(config) {
			facts = append(facts, configWords(config))
		}
		counts := at(c, "counts")
		if truthy(counts) {
			total := at(counts, "total")
			if strictEq(total, 0.0) {
				facts = append(facts, "nothing counted")
			} else {
				fact := sval(total) + " counted"
				if hour := at(counts, "currentHour"); gt(hour, 0.0) {
					fact += ", " + sval(hour) + " this hour"
				}
				facts = append(facts, fact)
			}
		}
		line := "  " + shownValue(jsPadEnd(at(c, "control"), width, "c.control")) + "  " + shownValue(jsPadEnd(at(c, "mode"), 6, "c.mode"))
		if len(facts) > 0 {
			line += "  " + strings.Join(facts, "; ")
		}
		lines = append(lines, line)
		if truthy(counts) && strictEq(at(c, "control"), "passkey-verification") && !strictEq(at(c, "mode"), "off") {
			lines = append(lines, "      only allowed, successful requests count; access counts are best-effort, so this is a lower bound")
		}
		var entries []any
		if !isNullish(counts) {
			entries = array(at(counts, "entries"), "c.counts.entries", "slice")
		}
		for i, e := range entries {
			if i == securityStatusEntriesShownAsText {
				break
			}
			lines = append(lines, entryLine(e))
		}
		if more := len(entries) - securityStatusEntriesShownAsText; more > 0 {
			lines = append(lines, "      and "+pl(float64(more), "more entry", "more entries")+" (--json lists all)")
		}
	}
	enforcing := at(s, "enforceable")
	modes := join(at(controls, "availableModes"), ", ", "s.controls.availableModes")
	if gt(length(enforcing), 0.0) {
		line := "  Modes: " + modes + ", and enforce for " + join(enforcing, ", ", "s.enforceable") + "."
		if num(length(enforcing)) < float64(len(items)) {
			line += " Enforce for the others: coming in a later release."
		}
		lines = append(lines, line)
	} else {
		lines = append(lines, "  Modes: "+modes+". Enforce: coming in a later release.")
	}
	lines = append(lines,
		"  Report counts what a control would have done, without refusing or changing anything.",
		"  Turning a control down or off, or a lifetime up, needs your approval with a trusted passkey.",
	)

	// Approval keys.
	if keys := at(s, "approvalKeys"); truthy(keys) {
		lines = append(lines, "", "Approval keys of the admins (only a trusted passkey can approve)")
		for _, a := range must(iterate(at(keys, "items"), "s.approvalKeys.items")) {
			trusted := at(a, "trusted")
			line := "  " + sval(at(at(a, "identity"), "name")) + "  " + sval(trusted) + " trusted, " + sval(at(a, "unconfirmed")) + " unconfirmed"
			if strictEq(trusted, 0.0) {
				line += ": cannot approve anything yet"
			}
			lines = append(lines, line)
		}
		if gt(at(at(keys, "summary"), "withoutTrustedKey"), 0.0) {
			lines = append(lines,
				"  Confirm a passkey with a trusted one under Account, Security in the dashboard. Without any trusted one,",
				"  ask whoever runs the server: varlatch admin reenroll --identity <id>.",
			)
		}
	}

	// Credentials.
	if review := at(s, "credentialReview"); truthy(review) {
		lines = append(lines, "", "Machine credentials", "  "+usagePolicyLine(review))
		expiry := at(review, "expiry")
		expiring := 0.0
		if truthy(expiry) {
			lines = append(lines, "  "+expiryLine(expiry))
			list := must(iterate(at(expiry, "items"), "expiry.items"))
			for _, c := range list {
				when := ""
				if expiresAt := at(c, "expiresAt"); truthy(expiresAt) {
					if strictEq(at(c, "state"), "expired") {
						when = "expired " + ago(expiresAt, now)
					} else {
						when = "expires " + until(expiresAt, now) + " (" + templateTime(expiresAt) + ")"
					}
				}
				lines = append(lines, "  "+sval(at(c, "id"))+"  "+sval(coalesce(at(c, "name"), "unnamed"))+"  for "+sval(at(at(c, "identity"), "name"))+": "+when)
			}
		}
		if !isNullish(expiry) {
			expiring = num(coalesce(length(at(expiry, "items")), 0.0))
		}
		if gt(at(at(review, "summary"), "listed"), 0.0) || expiring > 0 {
			lines = append(lines, "  Details: varlatch security report. Revoke or replace them in the dashboard under Access, Machines.")
		}
	}

	// Requirements.
	if requirements := at(s, "requirements"); truthy(requirements) {
		protection := any("off")
		for _, c := range items {
			if strictEq(at(c, "control"), "requirement-protection") {
				protection = coalesce(at(c, "mode"), "off")
				break
			}
		}
		count := at(requirements, "count")
		counted := "None"
		if !strictEq(count, 0.0) {
			counted = pl(count, "requirement", "requirements")
		}
		lines = append(lines, "", "Tailnet Requirements",
			"  "+counted+". requirement-protection is "+sval(protection)+".",
			"  Edit them in the dashboard under Access, Advanced, or list them: varlatch tailnet requirements.",
		)
	}

	// The audit export.
	if status := at(s, "auditExport"); truthy(status) {
		e := at(status, "export")
		shown := truthy(e) && (strictEq(at(e, "state"), "active") || strictEq(at(e, "state"), "draining"))
		lines = append(lines, "", "Audit export")
		if !shown {
			if !truthy(at(status, "enabled")) {
				lines = append(lines, "  Stopped by the host operator on this installation (VARLATCH_AUDIT_EXPORT=off).")
			}
			last := ""
			if truthy(e) {
				last = "; the last export was " + sval(at(e, "state"))
			}
			lines = append(lines, "  Not set up"+last+". The audit log stays in this installation only.",
				"  Copy it to a bucket you control: varlatch audit-export create (see varlatch audit-export --help).")
		} else {
			// The same lines as varlatch audit-export show, under this heading.
			for _, line := range r.auditExportLines(organization, status) {
				if !strings.HasPrefix(line, "  ") {
					line = "  " + line
				}
				lines = append(lines, line)
			}
			lines = append(lines,
				"  Checklist: compliance retention for at least 400 days; a bucket in an account the host operator does not control;",
				"  someone watching the heartbeat. Details: varlatch audit-export show.",
			)
		}
	}

	// Checklist.
	lines = append(lines, "", "Checklist")
	for _, item := range must(iterate(at(s, "checklist"), "s.checklist")) {
		lines = append(lines, "  - "+sval(at(item, "title"))+": "+sval(at(item, "why")), "    "+sval(at(item, "url")))
	}

	if unavailable := must(iterate(at(s, "unavailable"), "s.unavailable")); len(unavailable) > 0 {
		lines = append(lines, "", "Not shown")
		for _, u := range unavailable {
			section := js(at(u, "section"))
			if strictEq(at(u, "reason"), "not-supported") {
				lines = append(lines, "  "+wordOf(sectionWords, section)+": this server does not offer it; upgrade the server.")
			} else {
				lines = append(lines, "  "+wordOf(sectionWords, section)+": needs "+wordOf(sectionNeeds, section)+". An organization admin manages this.")
			}
		}
	}
	return printableLines(lines)
}

// ---------------------------------------------------------------------------
// The audit export's status lines (auditExport.ts's statusLines), which
// security status shows under its heading. Slice 5.7c's audit-export show
// prints the same.

var auditLockWords = map[string]string{
	"verified": "verified",
	"accepted": "lock headers accepted, not verified for this provider",
	"not-set":  "no retention set",
}

// hostOf is auditExport.ts's hostOf: the URL's host, the endpoint as it is
// when it is not a URL.
func hostOf(endpoint any) string {
	text := js(endpoint)
	if u, ok := whatwg.ParseURL(text); ok {
		return u.Host
	}
	return text
}

// retentionWords is auditExport.ts's retentionWords.
func retentionWords(retention any) string {
	if !truthy(retention) {
		return "none"
	}
	days := at(retention, "days")
	s := Printable(sval(at(retention, "mode"))) + ", " + Printable(sval(days)) + " day"
	if !strictEq(days, 1.0) {
		s += "s"
	}
	return s
}

// auditExportLines is auditExport.ts's statusLines.
func (r *Run) auditExportLines(organization string, status any) []string {
	safe := func(v any) string { return Printable(sval(v)) }
	var lines []string
	if !truthy(at(status, "enabled")) {
		lines = append(lines, "Audit export is stopped by the host operator on this installation (VARLATCH_AUDIT_EXPORT=off): nothing is delivered.")
	}
	e := at(status, "export")
	if !truthy(e) {
		return append(lines, organization+" has no audit export.",
			"Create one with: varlatch audit-export create --endpoint <url> --region <region> --bucket <bucket> --access-key-id <id>")
	}
	d := at(e, "destination")
	state := at(e, "state")
	first := "Audit export of " + Printable(organization) + ": " + safe(state)
	if deadline := at(e, "drainDeadline"); strictEq(state, "draining") && truthy(deadline) {
		first += " (until " + templateTime(deadline) + " at the latest)"
	}
	prefix := at(d, "prefix")
	prefixText := safe(prefix)
	if strictEq(prefix, "") {
		prefixText = "(none)"
	}
	destination := "  destination   " + Printable(shownValue(hostOf(at(d, "endpoint")))) + ", bucket " + safe(at(d, "bucket")) + ", prefix " + prefixText
	if truthy(at(d, "pathStyle")) {
		destination += ", path-style"
	}
	lines = append(lines, first, destination,
		"  retention     "+retentionWords(at(e, "retention"))+"; Object Lock "+wordOf(auditLockWords, at(e, "objectLock")),
		"  stream        "+safe(at(e, "streamId"))+", delivered up to position "+safe(at(e, "cursor")),
	)
	if lag := at(e, "lag"); truthy(lag) {
		pending := at(lag, "pending")
		line := "  pending       " + Printable(sval(pending)) + " event"
		if !strictEq(pending, 1.0) {
			line += "s"
		}
		if oldest := at(lag, "oldestPendingAt"); truthy(oldest) {
			line += ", the oldest from " + templateTime(oldest)
		}
		lines = append(lines, line)
	}
	lastSuccess, lastAttempt := at(e, "lastSuccessAt"), at(e, "lastAttemptAt")
	written := "  last written  " + timeOr(lastSuccess, lastSuccess != undef, "never")
	if truthy(lastAttempt) && !strictEq(lastAttempt, lastSuccess) {
		written += "; last attempt " + templateTime(lastAttempt)
	}
	lines = append(lines, written)
	heartbeat := "none yet"
	if h := at(e, "lastHeartbeatAt"); truthy(h) {
		heartbeat = "last for " + templateTime(h)
	}
	lines = append(lines, "  heartbeat     "+heartbeat+" (one an hour; none in the bucket for two hours means the copy stopped)")
	if lastError := at(e, "lastError"); truthy(lastError) {
		message, ok := lastError.(string)
		if !ok {
			throwType("text.replace is not a function")
		}
		line := "  last error    " + r.Secrets.ServerMessage(message)
		if since := at(e, "failingSince"); truthy(since) {
			line += " (failing since " + templateTime(since) + ")"
		}
		lines = append(lines, line)
	}
	if strictEq(at(e, "stoppedReason"), "object_conflict") {
		lines = append(lines, "  STOPPED       an object with the planned name exists with other content; nothing was overwritten. Change the destination or remove the export.")
	}
	if format := at(e, "unsupportedPlanFormat"); format != nil {
		lines = append(lines,
			"  STOPPED       a pending object was planned in format "+safe(format)+", which this release cannot upload;",
			"                the host operator finishes it with an earlier release or runs varlatchd admin audit-export discard-plan.",
		)
	}
	key := "  key           "
	switch canRead := at(e, "keyCanRead"); {
	case canRead == nil:
		key += "object read not determined"
	case truthy(canRead):
		key += "can read objects"
	default:
		key += "write-only"
	}
	if at(e, "retention") != nil {
		switch readable := at(e, "retentionReadable"); {
		case readable == nil:
			key += ", retention read not determined"
		case truthy(readable):
			key += ", can read retention"
		default:
			key += ", cannot read retention"
		}
	}
	return append(lines, key, "  version       "+safe(at(e, "version")))
}
