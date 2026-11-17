// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Coolify adapter. The base identity is the instance origin (https, no
// redirects followed, the host pinned). Exactly one of applicationUuid (an
// application) or serviceUuid (a service: a Compose stack whose variables
// every container shares) is the destination's identity; the rest are an
// application's per-target options (buildTime, deployAction,
// platformExpands). See packages/sync/src/coolify.ts for the Coolify API
// facts each rule follows.

var (
	coolifyTokenRejected = AccessCheck{Status: StatusCredentialRejected, Where: WhereConnection, HTTPStatus: 401,
		Message: "Coolify rejected the token: it is mistyped, or was deleted."}
	// coolifyVersionText is what /api/v1/version answers.
	coolifyVersionText = regexp.MustCompile(`^"?v?[0-9]+\.[0-9]+[A-Za-z0-9_.+-]*"?$`)
	coolifyUUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{2,63}$`)
	coolifyNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

const (
	// coolifyMaxPlatformExpands is the most names one application may list
	// for Coolify to resolve.
	coolifyMaxPlatformExpands  = 100
	coolifyServiceEnvForbidden = "Coolify lets only team admins and owners manage a service's variables. Create the token as one."
)

type coolify struct{}

// CoolifyAdapter is coolifyAdapter.
var CoolifyAdapter Adapter = coolify{}

func (coolify) Platform() Platform             { return Coolify }
func (coolify) CredentialScopeUnit() ScopeUnit { return ScopeInstance }
func (coolify) SupportsReadBack() bool         { return true }
func (coolify) SupportsRedeploy() bool         { return true }

// flagStyle is the env-flag vocabulary an instance speaks: "current",
// "legacy", or "" when a row does not say.
func flagStyle(row Object) string {
	if _, ok := row.Get("is_buildtime"); ok {
		return "current"
	}
	if _, ok := row.Get("is_runtime"); ok {
		return "current"
	}
	if _, ok := row.Get("is_build_time"); ok {
		return "legacy"
	}
	return ""
}

// buildTimeOption is the destination's buildTime: nil when unset.
func buildTimeOption(destination Fields) *bool {
	switch destination.Get("buildTime") {
	case "true":
		t := true
		return &t
	case "false":
		f := false
		return &f
	}
	return nil
}

// createFlags is a new key's flags.
func createFlags(style string, buildTime *bool, expands bool) Object {
	literal := !expands
	if style == "current" {
		o := Object{{"is_literal", literal}, {"is_multiline", literal}}
		if buildTime != nil {
			o = append(o, Member{"is_buildtime", *buildTime}, Member{"is_runtime", true})
		}
		return o
	}
	o := Object{{"is_literal", literal}}
	if buildTime != nil {
		o = append(o, Member{"is_build_time", *buildTime})
	}
	return o
}

// updateFlags is an existing key's flags: what the row has, mirrored, the
// build-time option on top.
func updateFlags(row Object, buildTime *bool, expands bool) Object {
	literal := !expands
	switch flagStyle(row) {
	case "current":
		build := truthy(row.Value("is_buildtime"))
		if buildTime != nil {
			build = *buildTime
		}
		var runtime any = true
		if buildTime == nil || *buildTime {
			if v := row.Value("is_runtime"); v != nil {
				runtime = v // row.is_runtime ?? true
			}
		}
		return Object{{"is_literal", literal}, {"is_multiline", literal},
			{"is_shown_once", truthy(row.Value("is_shown_once"))}, {"is_buildtime", build}, {"is_runtime", runtime}}
	case "legacy":
		build := truthy(row.Value("is_build_time"))
		if buildTime != nil {
			build = *buildTime
		}
		return Object{{"is_literal", literal}, {"is_build_time", build}}
	}
	return Object{{"is_literal", literal}}
}

// expandedNames is the destination's platformExpands, as a set.
func expandedNames(destination Fields) map[string]bool {
	set := map[string]bool{}
	for _, n := range strings.Split(destination.Get("platformExpands"), ",") {
		if n != "" {
			set[n] = true
		}
	}
	return set
}

func coolifyRequest(ctx context.Context, req *Request, method, path string, body []byte) (*response, error) {
	return send(ctx, req, method, req.BaseIdentity+"/api/v1"+path, [][2]string{
		{"Authorization", "Bearer " + req.Credential},
		{"Content-Type", "application/json"},
		{"Accept", "application/json"},
	}, body)
}

// asciiLower is a regular expression's /i without the u flag on these
// patterns: only ASCII letters fold.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// coolifyForbidden reads a 403's message for the advice; it is matched,
// never repeated.
func coolifyForbidden(res *response, where Where) AccessCheck {
	message := ""
	if body, ok := res.jsonBody(); ok {
		if o, isObject := body.(Object); isObject {
			message, _ = o.Value("message").(string)
		}
	}
	m := asciiLower(message)
	advice := "Coolify refused the token. It needs the read and write permissions, plus deploy to redeploy."
	switch {
	case strings.Contains(m, "api is disabled"):
		advice = "The API is off on this Coolify instance. Turn on API access in its settings."
	case strings.Contains(m, "not allowed to access the api"):
		advice = "Coolify accepts API calls only from listed IP addresses, and this server's is not among them."
	case strings.Contains(m, "exceed your current role"):
		advice = "The token belongs to a team member, and Coolify limits members to read-only tokens. Create it as a team admin or owner."
	}
	return AccessCheck{Status: StatusPermissionMissing, Where: where, HTTPStatus: 403, Message: advice}
}

// resource is the application or service a destination names.
type resource struct {
	kind string // "application" or "service"
	uuid string
	path string
}

func resourceOf(destination Fields) resource {
	if s := destination.Get("serviceUuid"); s != "" {
		return resource{"service", s, "/services/" + s}
	}
	uuid := "undefined" // a template literal of an absent field
	if destination.Has("applicationUuid") {
		uuid = destination.Get("applicationUuid")
	}
	return resource{"application", uuid, "/applications/" + uuid}
}

// listEnvs is the production env rows: the application endpoint merges
// preview-deployment rows in. An array in the list is a row with no
// fields, as JavaScript reads one.
func listEnvs(ctx context.Context, req *Request) ([]Object, error) {
	res, err := coolifyRequest(ctx, req, "GET", resourceOf(req.Destination).path+"/envs", nil)
	if err != nil {
		return nil, err
	}
	if !res.ok() {
		return nil, &AdapterError{
			Message:   "Coolify env list failed (" + strconv.Itoa(res.status) + ")",
			Retryable: res.status != 401 && res.status != 403 && res.status != 404,
		}
	}
	parsed, err := res.json()
	if err != nil {
		return nil, err
	}
	list, _ := parsed.([]any)
	rows := []Object{}
	for _, e := range list {
		switch row := e.(type) {
		case Object:
			if !truthy(row.Value("is_preview")) {
				rows = append(rows, row)
			}
		case []any:
			rows = append(rows, Object{})
		}
	}
	return rows, nil
}

// rowKey is a row's key when it is a string; only a string key can match
// a name.
func rowKey(row Object) (string, bool) {
	k, ok := row.Value("key").(string)
	return k, ok
}

// phpTrimmed is what PHP's trim() removes, which Coolify applies to every
// value it stores and reads.
func phpTrimmed(value string) bool {
	if value == "" {
		return false
	}
	in := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0 || c == 0x0b }
	return in(value[0]) || in(value[len(value)-1])
}

// coolifySharedTypes is Coolify's shared-variable types, replaced inside
// {{type.NAME}} (and vault, for a linked secret manager).
var coolifySharedTypes = map[string]bool{"team": true, "project": true, "environment": true, "server": true, "vault": true}

// braceInners is the inner text of each /\{\{(.*?)\}\}/g match: the
// shortest text up to "}}" without a line terminator.
func braceInners(value string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(value[i:], "{{")
		if j < 0 {
			return out
		}
		start := i + j
		k := strings.Index(value[start+2:], "}}")
		if k >= 0 && !hasLineTerminator(value[start+2:start+2+k]) {
			out = append(out, value[start+2:start+2+k])
			i = start + 2 + k + 2
			continue
		}
		i = start + 1
	}
}

func hasLineTerminator(s string) bool {
	return strings.ContainsAny(s, "\n\r  ")
}

// sharedType is /^([^.]*)\./.exec(inner.trim())?.[1]: the text before the
// first dot, and whether there is one.
func sharedType(inner string) (string, bool) {
	t := whatwg.Trim(inner)
	i := strings.IndexByte(t, '.')
	if i < 0 {
		return "", false
	}
	return t[:i], true
}

// endsInOddBackslashes is /(?:^|[^\\])(?:\\\\)*\\$/.
func endsInOddBackslashes(value string) bool {
	n := 0
	for i := len(value) - 1; i >= 0 && value[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

func isJSON(value string) bool {
	_, err := parseJSON([]byte(value))
	return err == nil
}

// copyRisk is whether a service's compose file may copy the stored value
// into the file Compose reads, where $ is expanded.
type copyRisk int

const (
	copySafe copyRisk = iota
	copyCopied
	copyUnknown
)

func copyRiskOf(destination Fields, name string, usage *UsageReport) copyRisk {
	if destination.Get("serviceUuid") == "" {
		return copySafe
	}
	if usage == nil || !usage.Checked {
		return copyUnknown
	}
	u, ok := usage.Get(name)
	switch {
	case !ok:
		return copyUnknown
	case u.CopiedIntoCompose:
		return copyCopied
	case len(u.UnknownIn) > 0:
		return copyUnknown
	}
	return copySafe
}

// undeliverableValue is why a value would not reach the destination's
// containers exactly as given, "" when it does.
func undeliverableValue(value string, copied copyRisk, expands bool) string {
	if expands {
		return unresolvableValue(value)
	}
	if phpTrimmed(value) {
		return "Coolify removes leading and trailing whitespace from values, so it would store a different value"
	}
	if strings.Contains(value, "'") {
		return "Coolify writes values in single quotes without escaping, so a value with a single quote breaks the .env it deploys"
	}
	if endsInOddBackslashes(value) {
		return "Coolify writes values in single quotes, so a value ending in a backslash breaks the .env it deploys"
	}
	for _, inner := range braceInners(value) {
		if t, ok := sharedType(inner); ok && coolifySharedTypes[t] {
			return "Coolify replaces {{" + t + ".…}} with one of its shared variables, so it would deliver a different value"
		}
	}
	if (strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[")) && isJSON(value) &&
		(strings.ContainsAny(value, "$\n") || strings.Contains(value, " #")) {
		return "Coolify writes JSON values unquoted, where Docker Compose changes $, \" #\" and line breaks"
	}
	if strings.Contains(value, "$") && copied == copyCopied {
		return "The service's compose file copies this value where Docker Compose expands $, so it would arrive changed"
	}
	if strings.Contains(value, "$") && copied == copyUnknown {
		return "Varlatch could not check whether the service's compose file copies this value where Docker Compose expands $ (reading it takes Coolify's read:sensitive permission), so a value with $ is not pushed"
	}
	return ""
}

// unresolvableValue is why a value listed for Coolify to resolve would
// arrive changed by more than Coolify's own substitution, "" when not.
func unresolvableValue(value string) string {
	if phpTrimmed(value) {
		return "Coolify removes leading and trailing whitespace from values, so it would store a different value"
	}
	if strings.Contains(value, "\n") {
		return "A value Coolify resolves is written unquoted, where a line break ends it"
	}
	if strings.ContainsAny(value, "\r\t\x00\\'\"") {
		return "Coolify escapes carriage returns, tabs, NUL, backslashes and quotes in a value it resolves, so it would deliver a different value"
	}
	if strings.Contains(value, " #") {
		return "A value Coolify resolves is written unquoted, where \" #\" starts a comment"
	}
	if (strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[")) && isJSON(value) {
		return "Coolify writes JSON values as they are, so a JSON value cannot be one Coolify resolves"
	}
	for _, inner := range braceInners(value) {
		if t, ok := sharedType(inner); ok && t == "vault" {
			return "Coolify resolves {{vault.…}} through a linked secret manager, which Varlatch does not cover"
		}
	}
	return ""
}

// storedOtherwise is a row stored in another form than Varlatch writes a
// value; a flag the row does not report is not judged.
func storedOtherwise(row Object, service, expands bool) bool {
	multiline := service || flagStyle(row) == "current"
	if expands {
		if row.Value("is_literal") == true {
			return true
		}
		return multiline && row.Value("is_multiline") == true
	}
	if row.Value("is_literal") == false {
		return true
	}
	return multiline && row.Value("is_multiline") == false
}

// compareUnits is JavaScript's default sort order: UTF-16 code units.
func compareUnits(a, b string) int {
	return slices.Compare(codeUnits(a), codeUnits(b))
}

// canonicalExpands is platformExpands in canonical form: deduplicated,
// sorted, comma-separated; "" when none.
func canonicalExpands(raw any, present bool) (string, error) {
	if !present || raw == nil || raw == "" {
		return "", nil
	}
	var list []any
	switch x := raw.(type) {
	case []any:
		list = x
	case string:
		for _, s := range strings.Split(x, ",") {
			list = append(list, s)
		}
	default:
		return "", &AdapterError{Message: "Coolify platformExpands must be a list of env keys"}
	}
	seen := map[string]bool{}
	var names []string
	for _, n := range list {
		s, ok := n.(string)
		if !ok {
			return "", &AdapterError{Message: "Coolify platformExpands must be a list of env keys"}
		}
		if s = whatwg.Trim(s); s != "" && !seen[s] {
			seen[s] = true
			names = append(names, s)
		}
	}
	slices.SortStableFunc(names, compareUnits)
	for _, name := range names {
		if !coolifyNamePattern.MatchString(name) {
			shown := shortText(name, 64)
			if shown == "" {
				shown = "?"
			}
			return "", &AdapterError{Message: `Coolify platformExpands: "` + shown + `" is not an env key (letters, digits and _, not starting with a digit)`}
		}
	}
	if len(names) > coolifyMaxPlatformExpands {
		return "", &AdapterError{Message: "Coolify platformExpands lists at most " + strconv.Itoa(coolifyMaxPlatformExpands) + " names"}
	}
	return strings.Join(names, ","), nil
}

// containerNames is Coolify's labels for a service's containers, bounded.
func containerNames(service Object) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, key := range []string{"applications", "databases"} {
		list, ok := service.Value(key).([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			o, isObject := item.(Object)
			if !isObject {
				continue
			}
			if name := shortText(o.Value("name"), 64); name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	slices.SortStableFunc(names, compareUnits)
	if len(names) > 20 {
		names = names[:20]
	}
	return names
}

func (coolify) CanonicalizeBaseIdentity(raw string) (string, error) {
	return canonicalOrigin(raw, "Coolify instance URL")
}

func (coolify) CanonicalizeDestination(raw Object) (Destination, error) {
	given := func(key string) bool {
		v, ok := raw.Get(key)
		return ok && v != nil && v != ""
	}
	fail := func(message string) (Destination, error) { return Destination{}, &AdapterError{Message: message} }
	if given("serviceUuid") {
		service, _ := raw.Value("serviceUuid").(string)
		service = whatwg.Trim(service)
		if given("applicationUuid") {
			return fail("A Coolify destination is an application or a service, not both")
		}
		if !coolifyUUIDPattern.MatchString(service) {
			return fail("Invalid Coolify service UUID")
		}
		if given("buildTime") {
			return fail("A Coolify service takes no buildTime option: its variables have no build-time flag")
		}
		if given("deployAction") {
			return fail("A Coolify service takes no deployAction option: it always restarts")
		}
		if list, isArray := raw.Value("platformExpands").([]any); given("platformExpands") && !(isArray && len(list) == 0) {
			return fail("A Coolify service takes no platformExpands option: only an application's values can be left for Coolify to resolve")
		}
		return Destination{Fields: Fields{{"serviceUuid", service}}, Key: "service:" + service}, nil
	}
	uuid, _ := raw.Value("applicationUuid").(string)
	uuid = whatwg.Trim(uuid)
	if !coolifyUUIDPattern.MatchString(uuid) {
		return fail("Invalid Coolify application UUID")
	}
	fields := Fields{{"applicationUuid", uuid}}
	switch bt := raw.Value("buildTime"); {
	case bt == true || bt == "true":
		fields = append(fields, Field{"buildTime", "true"})
	case bt == false || bt == "false":
		fields = append(fields, Field{"buildTime", "false"})
	case given("buildTime"):
		return fail(`Coolify buildTime must be "true" or "false"`)
	}
	switch da := raw.Value("deployAction"); {
	case da == "restart":
		fields = append(fields, Field{"deployAction", "restart"})
	case da == "deploy":
		fields = append(fields, Field{"deployAction", "deploy"})
	case given("deployAction"):
		return fail(`Coolify deployAction must be "deploy" or "restart"`)
	}
	expandsRaw, present := raw.Get("platformExpands")
	expands, err := canonicalExpands(expandsRaw, present)
	if err != nil {
		return Destination{}, err
	}
	if expands != "" {
		fields = append(fields, Field{"platformExpands", expands})
	}
	// Options never enter the identity.
	return Destination{Fields: fields, Key: uuid}, nil
}

func (coolify) ValidateName(name string, destination Fields) string {
	if !coolifyNamePattern.MatchString(name) {
		return "Coolify env keys allow only letters, digits, and _, not starting with a digit"
	}
	if destination.Get("serviceUuid") != "" && CoolifyOwnsName(name) {
		return "Coolify sets this name itself on a service (SERVICE_FQDN_*, SERVICE_URL_*, SERVICE_NAME_*, COOLIFY_*)"
	}
	return ""
}

func (coolify) CanonicalizeName(name string) string { return name }

func (coolify) WriteValues(ctx context.Context, req *Request, items []SyncItem) ([]NameOutcome, error) {
	res := resourceOf(req.Destination)
	path := res.path + "/envs"
	rows, err := listEnvs(ctx, req)
	if err != nil {
		return nil, err
	}
	existing := map[string]Object{}
	for _, row := range rows {
		if k, ok := rowKey(row); ok {
			existing[k] = row
		}
	}
	buildTime := buildTimeOption(req.Destination)
	// The instance's flag vocabulary, from any row it returned.
	style := ""
	for _, row := range rows {
		if style = flagStyle(row); style != "" {
			break
		}
	}
	expanded := expandedNames(req.Destination)
	outcomes := []NameOutcome{}
	for _, item := range items {
		stop, err := req.abort(ctx)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		expands := expanded[item.Name]
		if problem := undeliverableValue(item.Value, copyRiskOf(req.Destination, item.Name, req.Usage), expands); problem != "" {
			// Nothing is sent: a value Coolify would change is not delivered.
			outcomes = append(outcomes, NameOutcome{Name: item.Name, Error: problem})
			continue
		}
		row, hasRow := existing[item.Name]
		method := "POST"
		if hasRow {
			method = "PATCH"
		}
		var answer *response
		switch {
		case res.kind == "service":
			answer, err = coolifyRequest(ctx, req, method, path, stringify(Object{
				{"key", item.Name}, {"value", item.Value}, {"is_literal", true}, {"is_multiline", true},
			}))
		case hasRow:
			body := Object{{"key", item.Name}, {"value", item.Value}, {"is_preview", false}}
			answer, err = coolifyRequest(ctx, req, "PATCH", path, stringify(append(body, updateFlags(row, buildTime, expands)...)))
		default:
			create := func(s string) (*response, error) {
				body := Object{{"key", item.Name}, {"value", item.Value}, {"is_preview", false}}
				return coolifyRequest(ctx, req, "POST", path, stringify(append(body, createFlags(s, buildTime, expands)...)))
			}
			first := style
			if first == "" {
				first = "current"
			}
			answer, err = create(first)
			if err == nil && answer.status == 422 && style == "" {
				// Nothing was written: retry once in the legacy vocabulary.
				stop, aerr := req.abort(ctx)
				if aerr != nil {
					return nil, aerr
				}
				if stop {
					return outcomes, nil
				}
				style = "legacy"
				answer, err = create(style)
			} else if err == nil && answer.ok() && style == "" {
				style = "current"
			}
		}
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, outcome(item.Name, answer, false))
	}
	return outcomes, nil
}

func (coolify) DeleteNames(ctx context.Context, req *Request, names []string) ([]NameOutcome, error) {
	res := resourceOf(req.Destination)
	rows, err := listEnvs(ctx, req)
	if err != nil {
		return nil, err
	}
	byKey := map[string]any{}
	for _, row := range rows {
		if k, ok := rowKey(row); ok {
			byKey[k] = row.Value("uuid")
		}
	}
	outcomes := []NameOutcome{}
	for _, name := range names {
		stop, err := req.abort(ctx)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		uuid := byKey[name]
		if !truthy(uuid) {
			// Already absent: converged.
			outcomes = append(outcomes, NameOutcome{Name: name, OK: true})
			continue
		}
		answer, err := coolifyRequest(ctx, req, "DELETE", res.path+"/envs/"+wellFormed(jsString(uuid)), nil)
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, outcome(name, answer, true))
	}
	return outcomes, nil
}

func (c coolify) ReadValues(ctx context.Context, req *Request) (map[string]*string, error) {
	state, err := c.ReadRemote(ctx, req)
	return state.Values, err
}

// ReadRemote is the stored values, and the rows to rewrite whatever their
// value. A row without "value" is one Coolify withholds: unreadable (nil).
// A stored null is "". Another value is not a string: nil, as it never
// equals one.
func (coolify) ReadRemote(ctx context.Context, req *Request) (RemoteState, error) {
	service := resourceOf(req.Destination).kind == "service"
	expanded := expandedNames(req.Destination)
	rows, err := listEnvs(ctx, req)
	if err != nil {
		return RemoteState{}, err
	}
	state := RemoteState{Values: map[string]*string{}, Rewrite: map[string]bool{}}
	for _, row := range rows {
		key, ok := rowKey(row)
		if !ok {
			continue
		}
		var value *string
		if v, has := row.Get("value"); has {
			switch x := v.(type) {
			case nil:
				empty := ""
				value = &empty
			case string:
				value = &x
			}
		}
		state.Values[key] = value
	}
	for _, row := range rows {
		key, ok := rowKey(row)
		if ok && storedOtherwise(row, service, expanded[key]) {
			state.Rewrite[key] = true
		}
	}
	return state, nil
}

func (coolify) ValueProblem(destination Fields, name, value string, usage *UsageReport) string {
	return undeliverableValue(value, copyRiskOf(destination, name, usage), expandedNames(destination)[name])
}

func (coolify) HeldFix(destination Fields, name, value string) string {
	listed := expandedNames(destination)
	if destination.Get("applicationUuid") == "" || listed[name] || len(listed) >= coolifyMaxPlatformExpands {
		return ""
	}
	if unresolvableValue(value) == "" {
		return "platform-expands"
	}
	return ""
}

// TriggerRedeploy deploys an application (a forced rebuild) unless the
// target opted for a restart; a service restarts.
func (coolify) TriggerRedeploy(ctx context.Context, req *Request) (string, error) {
	stop, err := req.abort(ctx)
	if err != nil {
		return "", err
	}
	if stop {
		return "aborted", nil
	}
	res := resourceOf(req.Destination)
	restart := res.kind == "service" || req.Destination.Get("deployAction") == "restart"
	path, what := res.path+"/start?force=true", "deploy"
	if restart {
		path, what = res.path+"/restart", "restart"
	}
	answer, err := coolifyRequest(ctx, req, "POST", path, nil)
	if err != nil {
		return "", err
	}
	if !answer.ok() {
		return "", &AdapterError{Message: "Coolify " + what + " failed (" + strconv.Itoa(answer.status) + ")", Retryable: true}
	}
	return "sent", nil
}

func (coolify) CheckAccess(ctx context.Context, req *Request) AccessCheck {
	host := hostOf(req.BaseIdentity)
	where := WhereConnection
	check, err := coolifyCheck(ctx, req, host, &where)
	if err != nil {
		return unreachable(host, err, where)
	}
	return check
}

func coolifyCheck(ctx context.Context, req *Request, host string, where *Where) (AccessCheck, error) {
	version, err := coolifyRequest(ctx, req, "GET", "/version", nil)
	if err != nil {
		return AccessCheck{}, err
	}
	switch {
	case version.status == 401:
		return coolifyTokenRejected, nil
	case version.status == 403:
		return coolifyForbidden(version, *where), nil
	case version.status == 404:
		return AccessCheck{Status: StatusNotFound, Where: *where, HTTPStatus: 404,
			Message: "No Coolify API answered at " + host + ". Check the instance URL."}, nil
	}
	// A sign-in page in front of the instance answers 200 as well.
	if !version.ok() || !coolifyVersionText.MatchString(whatwg.Trim(version.text())) {
		return foreign("Coolify", "instance", host, version.status), nil
	}
	if req.Destination.Get("applicationUuid") == "" && req.Destination.Get("serviceUuid") == "" {
		return AccessCheck{Status: StatusOK, Where: *where, Message: "Coolify accepted the token."}, nil
	}

	*where = WhereDestination
	r := resourceOf(req.Destination)
	res, err := coolifyRequest(ctx, req, "GET", r.path, nil)
	if err != nil {
		return AccessCheck{}, err
	}
	if res.ok() {
		found, _ := res.jsonBody()
		o, isObject := found.(Object)
		if !isObject || o.Value("uuid") != r.uuid {
			return AccessCheck{Status: StatusFailed, Where: *where, HTTPStatus: res.status,
				Message: host + " did not answer with " + r.kind + " " + r.uuid + ". Check the instance URL and the UUID."}, nil
		}
		if r.kind == "application" {
			return AccessCheck{Status: StatusOK, Where: *where,
				Message: "The token can read application " + r.uuid + ". The first push shows whether it may also write its variables."}, nil
		}
		return checkServiceVariables(ctx, req, r, o, host)
	}
	switch res.status {
	case 401:
		return coolifyTokenRejected, nil
	case 403:
		return coolifyForbidden(res, *where), nil
	case 404:
		return AccessCheck{Status: StatusNotFound, Where: *where, HTTPStatus: 404,
			Message: "The token's team has no " + r.kind + " " + r.uuid + " on " + host + ". Copy the UUID from the " + r.kind + "'s URL in Coolify."}, nil
	}
	return unexpected("Coolify", res.status, *where), nil
}

// checkServiceVariables is a service's variables, the push's first
// request: whether the token may manage them, and read their values.
func checkServiceVariables(ctx context.Context, req *Request, r resource, service Object, host string) (AccessCheck, error) {
	where := WhereDestination
	res, err := coolifyRequest(ctx, req, "GET", r.path+"/envs", nil)
	if err != nil {
		return AccessCheck{}, err
	}
	switch {
	case res.status == 401:
		return coolifyTokenRejected, nil
	case res.status == 403:
		advice := coolifyForbidden(res, where)
		// Coolify's policy refusal carries no reason of its own.
		if strings.HasPrefix(advice.Message, "Coolify refused the token") {
			advice.Message = coolifyServiceEnvForbidden
		}
		return advice, nil
	case res.status == 404:
		return AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
			Message: "The token's team has no service " + r.uuid + " on " + host + "."}, nil
	case !res.ok():
		return unexpected("Coolify", res.status, where), nil
	}
	body, _ := res.jsonBody()
	rows, isArray := body.([]any)
	if !isArray {
		return AccessCheck{Status: StatusFailed, Where: where, HTTPStatus: res.status,
			Message: host + " did not answer with the variables of service " + r.uuid + "."}, nil
	}
	name := shortText(service.Value("name"), 200)
	if name == "" {
		name = r.uuid
	}
	reach := "Every variable reaches all of its containers, and any added later."
	if containers := containerNames(service); len(containers) > 0 {
		reach = "Every variable reaches all of its containers (" + strings.Join(containers, ", ") + "), and any added later."
	}
	withheld := 0
	for _, row := range rows {
		if o, ok := row.(Object); ok {
			if _, has := o.Get("value"); !has {
				withheld++
			}
		}
	}
	unreadable := ""
	switch {
	case withheld == 0:
	case withheld == len(rows):
		unreadable = " Coolify returned none of their values to this token (reading them takes its read:sensitive permission): repairs rewrite every value, and the compose file is likely unreadable too."
	default:
		unreadable = " Coolify withheld " + strconv.Itoa(withheld) + " of " + strconv.Itoa(len(rows)) + " values from this token (shown once, or no read:sensitive): repairs rewrite those."
	}
	return AccessCheck{Status: StatusOK, Where: where,
		Message: "The token can manage the variables of service " + name + ". " + reach + unreadable + " The first push shows whether it may also write them."}, nil
}

var coolifyAddressPrefix = regexp.MustCompile(`^https?://`)

// ListDestinations is the applications and services of the token's team,
// by name, an application with its first address.
func (coolify) ListDestinations(ctx context.Context, req *Request) DestinationListing {
	host := hostOf(req.BaseIdentity)
	listing, err := coolifyList(ctx, req, host)
	if err != nil {
		return listingFailed(unreachable(host, err, WhereConnection))
	}
	return listing
}

func coolifyList(ctx context.Context, req *Request, host string) (DestinationListing, error) {
	where := WhereConnection
	res, err := coolifyRequest(ctx, req, "GET", "/applications", nil)
	if err != nil {
		return DestinationListing{}, err
	}
	switch res.status {
	case 401:
		return listingFailed(coolifyTokenRejected), nil
	case 403:
		return listingFailed(coolifyForbidden(res, where)), nil
	case 404:
		return listingFailed(AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
			Message: "No Coolify API answered at " + host + ". Check the instance URL."}), nil
	}
	var apps []any
	isArray := false
	if res.ok() {
		body, _ := res.jsonBody()
		apps, isArray = body.([]any)
	}
	if !isArray {
		return listingFailed(foreign("Coolify", "instance", host, res.status)), nil
	}
	items := []DestinationOption{}
	for _, app := range apps {
		o, ok := app.(Object)
		if !ok {
			continue
		}
		uuid, ok := o.Value("uuid").(string)
		if !ok || !coolifyUUIDPattern.MatchString(uuid) {
			continue
		}
		address := ""
		if fqdn, ok := o.Value("fqdn").(string); ok {
			first, _, _ := strings.Cut(fqdn, ",")
			address = shortText(coolifyAddressPrefix.ReplaceAllString(first, ""), 200)
		}
		label := shortText(o.Value("name"), 200)
		if label == "" {
			label = uuid
		}
		items = append(items, DestinationOption{Destination: Fields{{"applicationUuid", uuid}}, Label: label, Detail: address})
	}
	appCount := len(items)

	servicesNote := ""
	svcRes, err := coolifyRequest(ctx, req, "GET", "/services", nil)
	if err != nil {
		return DestinationListing{}, err
	}
	var services []any
	servicesListed := false
	if svcRes.ok() {
		body, _ := svcRes.jsonBody()
		services, servicesListed = body.([]any)
	}
	if servicesListed {
		for _, svc := range services {
			o, ok := svc.(Object)
			if !ok {
				continue
			}
			uuid, ok := o.Value("uuid").(string)
			if !ok || !coolifyUUIDPattern.MatchString(uuid) {
				continue
			}
			label := shortText(o.Value("name"), 200)
			if label == "" {
				label = uuid
			}
			items = append(items, DestinationOption{Destination: Fields{{"serviceUuid", uuid}}, Label: label, Detail: "service"})
		}
	} else {
		servicesNote = " Its services could not be listed (HTTP " + strconv.Itoa(svcRes.status) + ")."
	}
	serviceCount := len(items) - appCount
	sortLabels(items)
	message := "The token's team has " + strconv.Itoa(appCount) + " applications"
	if servicesListed {
		message += " and " + strconv.Itoa(serviceCount) + " services"
	}
	message += " on " + host + "." + servicesNote
	listing := DestinationListing{Check: AccessCheck{Status: StatusOK, Where: where, Message: message}, Items: items}
	if len(items) > MaxDestinations {
		listing.Items, listing.Truncated = items[:MaxDestinations], true
	}
	return listing, nil
}

// sortLabels is items.sort((a, b) => a.label.localeCompare(b.label)):
// stable, in the root collation of Unicode's algorithm (ICU's, as
// localeCompare uses it without a locale argument).
func sortLabels(items []DestinationOption) {
	c := collate.New(language.Und)
	slices.SortStableFunc(items, func(a, b DestinationOption) int {
		return c.CompareString(wellFormed(a.Label), wellFormed(b.Label))
	})
}

// InspectUsage reads a service's compose files where the token may
// (Coolify's read:sensitive) and classifies them; only names, container
// names and verdicts leave it. An application has no compose notion (nil).
func (coolify) InspectUsage(ctx context.Context, req *Request, names []string) *UsageReport {
	r := resourceOf(req.Destination)
	if r.kind != "service" {
		return nil
	}
	res, err := coolifyRequest(ctx, req, "GET", r.path, nil)
	if err != nil {
		return uncheckedUsage("Coolify could not be reached", names)
	}
	if !res.ok() {
		return uncheckedUsage("Coolify did not return the service (HTTP "+strconv.Itoa(res.status)+")", names)
	}
	parsed, _ := res.jsonBody()
	body, isObject := parsed.(Object)
	if !isObject || body.Value("uuid") != r.uuid {
		return uncheckedUsage("Coolify did not answer with the service", names)
	}
	if _, has := body.Get("docker_compose_raw"); !has {
		return uncheckedUsage("Coolify did not return the service's compose file to this token (reading it takes its read:sensitive permission)", names)
	}
	var version *float64
	if v := jsToNumber(body.Value("compose_parsing_version"), hasKey(body, "compose_parsing_version")); !isNaNOrInf(v) {
		version = &v
	}
	raw, rawOK := body.Value("docker_compose_raw").(string)
	generated, generatedOK := body.Value("docker_compose").(string)
	return ClassifyComposeUsage(optionalString(raw, rawOK), optionalString(generated, generatedOK), version, names)
}

func optionalString(s string, ok bool) *string {
	if !ok {
		return nil
	}
	return &s
}

func uncheckedUsage(reason string, names []string) *UsageReport {
	report := &UsageReport{Checked: false, Reason: reason}
	for _, n := range names {
		report.set(n, NameUsage{})
	}
	return report
}
