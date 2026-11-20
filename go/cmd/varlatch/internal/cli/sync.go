// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
)

// `varlatch sync check` and `varlatch sync push` (slice 5.8b of internal
// docs/design/go-cli.md): main.ts's `case "sync"`, syncCheck.ts and
// syncPush.ts, on the Platform Adapters (go/lib/sync, step 4's port of
// @varlatch/sync) with a plain client (apiclient.PlatformClient).
//
// The platform credential is read only from the variable --token-env names
// (VARLATCH_SYNC_TOKEN when it is not given). It and every value pushed or
// disclosed are held for the run: no output, diagnostic or error text shows
// them. sync check reports statuses only, never a value or anything derived
// from one. Every check of the command line and the destination comes
// before the first request; the platform is written last.

const (
	syncUsage      = "Usage: varlatch sync <push|check> --platform <github-actions|coolify|convex> [--map NAME[=DEST]]... [--exclude NAME|PREFIX*]... ..."
	syncCheckUsage = "Usage: varlatch sync check --platform <github-actions|coolify|convex> --base <owner|https://origin> " +
		"(--repo <name> [--gh-environment <name>] | --app <uuid> | --service <uuid> | nothing for convex) [-e <env>] [--server <url>] " +
		"[--token-env VAR] [--map NAME[=DEST]]... [--exclude NAME|PREFIX*]... [--json]"
)

var syncCheckOptions = OptionSpec{
	Values:       []string{"--platform", "--base", "--repo", "--gh-environment", "--app", "--service", "--token-env", "--environment", "--server"},
	Lists:        []string{"--map", "--exclude"},
	Booleans:     []string{"--json"},
	OnceBooleans: true,
	Aliases:      []Alias{{From: "-e", To: "--environment"}},
}

// syncTarget is what the command line names: the platform, the base, the
// destination's raw fields (only those given), the credential's variable,
// --map and --exclude.
type syncTarget struct {
	platform, base, tokenEnv     string
	repo, ghEnvironment          string
	hasRepo, hasGHEnv            bool
	app, service, buildTime      string
	hasApp, hasService, hasBuild bool
	platformExpands              []string
	maps, excludes               []string
}

// syncCommand is main.ts's `case "sync"`.
func syncCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	if sub == "check" {
		return r.syncCheck()
	}
	if sub != "push" {
		return UsageOnly(syncUsage)
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	platform, ok := flagArg(r.Args, "--platform")
	if !ok {
		return UsageError("--platform is required (github-actions, coolify, convex)")
	}
	base, ok := flagArg(r.Args, "--base")
	if !ok {
		return UsageError("--base is required (GitHub owner, or a Coolify/Convex https origin)")
	}
	t := syncTarget{platform: platform, base: base, tokenEnv: "VARLATCH_SYNC_TOKEN", maps: flagValues(r.Args, "--map"), excludes: flagValues(r.Args, "--exclude")}
	t.repo, t.hasRepo = flagArg(r.Args, "--repo")
	t.ghEnvironment, t.hasGHEnv = flagArg(r.Args, "--gh-environment")
	t.app, t.hasApp = flagArg(r.Args, "--app")
	t.service, t.hasService = flagArg(r.Args, "--service")
	t.buildTime, t.hasBuild = flagArg(r.Args, "--build-time")
	for _, v := range flagValues(r.Args, "--platform-expands") {
		t.platformExpands = append(t.platformExpands, strings.Split(v, ",")...)
	}
	if v, ok := flagArg(r.Args, "--token-env"); ok {
		t.tokenEnv = v
	}
	code, err := r.syncPush(lazy, ctx.Organization, ctx.Project, environmentName(ctx.Environment), t)
	if err != nil {
		return err
	}
	return ExitWith(code)
}

// environmentName is ctx.environment as a string.
func environmentName(v any) string { return jsTemplate(v, true) }

// syncGet is `x?.key` of an answer: false when x is null or undefined or
// lacks the key; never a throw.
func syncGet(x any, key string) (any, bool) {
	if x == nil || x == apiclient.Undefined {
		return nil, false
	}
	return jsval.Get(x, key)
}

// syncItems is `answer.items` iterated: V8's TypeError when the answer is
// null or the list is not iterable; none for `?? []` when allowNullish and
// it is missing.
func syncItems(answer any, expr string, allowNullish bool) ([]any, error) {
	list, ok, err := read(answer, answer != apiclient.Undefined, "items")
	if err != nil {
		return nil, err
	}
	if allowNullish && (!ok || list == nil) {
		return nil, nil
	}
	return iterate(list, expr)
}

// syncText is `${x.key}` of an element: V8's TypeError when x is null.
func syncText(x any, key string) (string, error) {
	v, ok, err := read(x, true, key)
	if err != nil {
		return "", err
	}
	return jsTemplate(v, ok), nil
}

// printableAll is `lines.map(printable)`.
func printableAll(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = Printable(l)
	}
	return out
}

// syncRequest is the adapters' request for this run: the plain platform
// client, the canonical base and destination, and the credential.
func (r *Run) syncRequest(base string, destination vsync.Fields, credential string, usage *vsync.UsageReport) *vsync.Request {
	return &vsync.Request{BaseIdentity: base, Destination: destination, Credential: credential, Client: apiclient.PlatformClient(r.Env), Usage: usage}
}

// splitMap is `map.split("=", 2)`: the name, and the rename when given.
func splitMap(m string) (string, string, bool) {
	parts := strings.Split(m, "=")
	if len(parts) == 1 {
		return parts[0], "", false
	}
	return parts[0], parts[1], true
}

// excludedBy is `excludes.some((e) => e.endsWith("*") ? name.startsWith(e.slice(0, -1)) : name === e)`.
func excludedBy(excludes []string, name string) bool {
	for _, e := range excludes {
		if strings.HasSuffix(e, "*") {
			if strings.HasPrefix(name, strings.TrimSuffix(e, "*")) {
				return true
			}
		} else if name == e {
			return true
		}
	}
	return false
}

// adapterMessage is `err instanceof AdapterError ? err.message : String(err)`.
func adapterMessage(err error) string {
	var a *vsync.AdapterError
	if errors.As(err, &a) {
		return a.Message
	}
	var s *vsync.ScriptError
	if errors.As(err, &s) {
		return s.Name + ": " + s.Message
	}
	return err.Error()
}

// resolveSyncTarget is syncCheck.ts's resolveTarget (and syncPush.ts's
// equivalent): the adapter, the canonical base and destination; a wrong
// one is the adapter's message.
func resolveSyncTarget(t syncTarget, push bool) (vsync.Adapter, string, vsync.Fields, error) {
	adapter, err := vsync.GetAdapter(t.platform)
	if err != nil {
		return nil, "", nil, &syncUnknownPlatform{t.platform}
	}
	base, err := adapter.CanonicalizeBaseIdentity(t.base)
	if err != nil {
		return adapter, "", nil, errors.New(adapterMessage(err))
	}
	raw := jsjson.Object{}
	add := func(key, value string, given bool) {
		if given {
			raw = append(raw, jsjson.Member{Key: key, Value: value})
		}
	}
	switch adapter.Platform() {
	case vsync.GitHubActions:
		add("repo", t.repo, t.hasRepo)
		add("environment", t.ghEnvironment, t.ghEnvironment != "")
	case vsync.Coolify:
		if push {
			add("serviceUuid", t.service, t.hasService)
			add("applicationUuid", t.app, t.hasApp)
			add("buildTime", t.buildTime, t.buildTime != "")
			if len(t.platformExpands) > 0 {
				add("platformExpands", strings.Join(t.platformExpands, ","), true)
			}
		} else if t.hasService {
			add("serviceUuid", t.service, true)
			add("applicationUuid", t.app, t.hasApp)
		} else {
			add("applicationUuid", t.app, t.hasApp)
		}
	}
	destination, err := adapter.CanonicalizeDestination(raw)
	if err != nil {
		return adapter, "", nil, errors.New(adapterMessage(err))
	}
	return adapter, base, destination.Fields, nil
}

type syncUnknownPlatform struct{ platform string }

func (e *syncUnknownPlatform) Error() string {
	return "unknown platform \"" + e.platform + "\" (github-actions, coolify, convex)"
}

// fieldsObject is a canonical destination as the JSON object TypeScript holds.
func fieldsObject(f vsync.Fields) jsjson.Object {
	out := jsjson.Object{}
	for _, x := range f {
		out = append(out, jsjson.Member{Key: x.Key, Value: x.Value})
	}
	return out
}

// isDisclosureRefusal is `err.code === "PERMISSION_DENIED" || err.code.startsWith("TAILNET_")`.
func isDisclosureRefusal(err error) (*apiclient.APIError, bool) {
	var api *apiclient.APIError
	if !errors.As(err, &api) {
		return nil, false
	}
	code, _ := api.Code.(string)
	return api, code == "PERMISSION_DENIED" || strings.HasPrefix(code, "TAILNET_")
}

// ---------------------------------------------------------------------------
// sync check

// checkedKey is syncCheck.ts's CheckedKey.
type checkedKey struct {
	name, destination, status, reason string
}

type keyPair struct {
	name, destination string
	invalid           bool
}

// usageNote is syncCheck.ts's UsageNote.
type usageNote struct {
	code, name, reason string
	containers         []string
	hasContainers      bool
}

var checkStatuses = []string{"match", "differs", "missing-on-platform", "extra-on-platform", "unreadable", "absent"}

var checkLabels = map[string]string{
	"match":               "match",
	"differs":             "differs",
	"missing-on-platform": "missing on the platform",
	"extra-on-platform":   "extra on the platform",
	"unreadable":          "not compared",
	"absent":              "absent (neither has it)",
}

var checkReasons = map[string]string{
	"platform-write-only": "the platform's values are write-only",
	"withheld":            "this identity may not read its value in Varlatch",
	"platform-withheld":   "the platform withholds its value from this token",
	"invalid-name":        "the platform cannot store this name, or sets it itself",
}

var itemNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// syncCheckResult is syncCheck.ts's SyncCheckResult.
type syncCheckResult struct {
	platform, base, environment, keySet string
	destination                         vsync.Fields
	keys                                []checkedKey
	unchecked                           string
	hasUnchecked                        bool
	usage                               []usageNote
	notices                             []string
	exitCode                            int
}

// compareKeys is syncCheck.ts's compareKeys: values in, statuses out.
// varlatch maps a stored item to its value (nil: withheld); platform is nil
// when it cannot be read back, and maps a name to nil when it withholds the
// value.
// pushReadable is syncPush.ts's readable filter for one item's value: a
// string is pushed as it is; no value (absent or null) is not readable. A
// value of another type is not readable either: TypeScript passes it on and
// the adapters throw on it (a number has no includes), so Go skips it as
// "not readable in this environment" rather than push its text.
func pushReadable(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// notAString stands for a disclosed value that is not a string: TypeScript
// compares it with ===, so it equals no value the platform holds.
var notAString = new(string)

func compareKeys(pairs []keyPair, varlatch map[string]*string, platform map[string]*string) []checkedKey {
	out := make([]checkedKey, 0, len(pairs))
	for _, p := range pairs {
		key := func(status, reason string) checkedKey {
			return checkedKey{name: p.name, destination: p.destination, status: status, reason: reason}
		}
		switch {
		case p.invalid:
			out = append(out, key("unreadable", "invalid-name"))
			continue
		case platform == nil:
			out = append(out, key("unreadable", "platform-write-only"))
			continue
		}
		remote, onPlatform := platform[p.destination]
		value, stored := varlatch[p.name]
		switch {
		case !stored && onPlatform:
			out = append(out, key("extra-on-platform", ""))
		case !stored:
			out = append(out, key("absent", ""))
		case !onPlatform:
			out = append(out, key("missing-on-platform", ""))
		case remote == nil:
			out = append(out, key("unreadable", "platform-withheld"))
		case value == nil:
			out = append(out, key("unreadable", "withheld"))
		case value == notAString:
			out = append(out, key("differs", ""))
		case *remote == *value:
			out = append(out, key("match", ""))
		default:
			out = append(out, key("differs", ""))
		}
	}
	return out
}

// checkExitCode is syncCheck.ts's checkExitCode: drift wins over an
// incomplete check.
func checkExitCode(keys []checkedKey) int {
	unreadable := false
	for _, k := range keys {
		switch k.status {
		case "differs", "missing-on-platform", "extra-on-platform":
			return 1
		case "unreadable":
			unreadable = true
		}
	}
	if unreadable {
		return 2
	}
	return 0
}

// syncCheck is main.ts's `sync check` with syncCheck.ts's runSyncCheck.
func (r *Run) syncCheck() error {
	opts, err := strictOptions("sync check", r.Args[1:], syncCheckOptions, syncCheckUsage)
	if err != nil {
		return err
	}
	value := func(name string) (string, bool) { return opts.Value(name) }
	platform, ok := value("--platform")
	if !ok {
		return UsageErrorWithUsage("varlatch sync check: --platform is required (github-actions, coolify, convex)", "\n"+syncCheckUsage)
	}
	base, ok := value("--base")
	if !ok {
		return UsageErrorWithUsage("varlatch sync check: --base is required (a GitHub owner, or a Coolify/Convex https origin)", "\n"+syncCheckUsage)
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	t := syncTarget{platform: platform, base: base, tokenEnv: "VARLATCH_SYNC_TOKEN", maps: opts.Lists["--map"], excludes: opts.Lists["--exclude"]}
	t.repo, t.hasRepo = value("--repo")
	t.ghEnvironment, t.hasGHEnv = value("--gh-environment")
	t.app, t.hasApp = value("--app")
	t.service, t.hasService = value("--service")
	if v, ok := value("--token-env"); ok {
		t.tokenEnv = v
	}
	result, err := r.runSyncCheck(lazy, ctx.Organization, ctx.Project, environmentName(ctx.Environment), t)
	var wrong *syncCheckUsageError
	if errors.As(err, &wrong) {
		return UsageErrorWithUsage("varlatch sync check: "+wrong.message, "\n"+syncCheckUsage)
	}
	if err != nil {
		return err
	}
	if opts.Has("--json") {
		for _, n := range result.notices {
			if err := r.warn("varlatch: " + Printable(n)); err != nil {
				return err
			}
		}
		if err := r.printDoc(syncCheckDocument(result)); err != nil {
			return err
		}
	} else {
		outLines, errLines := r.formatSyncCheck(result)
		for _, l := range errLines {
			if err := r.warn(l); err != nil {
				return err
			}
		}
		for _, l := range outLines {
			if err := r.println(l); err != nil {
				return err
			}
		}
	}
	return ExitWith(result.exitCode)
}

type syncCheckUsageError struct{ message string }

func (e *syncCheckUsageError) Error() string { return e.message }

// runSyncCheck is syncCheck.ts's runSyncCheck. Varlatch-side failures
// propagate; a platform that cannot be read is a result (unchecked, 2).
func (r *Run) runSyncCheck(lazy *lazyAPI, org, project, environment string, t syncTarget) (*syncCheckResult, error) {
	adapter, base, destination, err := resolveSyncTarget(t, false)
	if err != nil {
		return nil, &syncCheckUsageError{err.Error()}
	}
	res := &syncCheckResult{platform: string(adapter.Platform()), base: base, destination: destination, environment: environment, notices: []string{}, usage: []usageNote{}}
	finish := func(keySet string, keys []checkedKey, unchecked string, hasUnchecked bool) *syncCheckResult {
		res.keySet, res.keys, res.unchecked, res.hasUnchecked = keySet, keys, unchecked, hasUnchecked
		if hasUnchecked {
			res.exitCode = 2
		} else {
			res.exitCode = checkExitCode(keys)
		}
		return res
	}

	api, err := lazy.get()
	if err != nil {
		return nil, err
	}
	// Metadata and non-sensitive values only: no Secret is disclosed yet.
	effective, err := api.EffectiveConfiguration(bg, org, project, environment, true)
	if err != nil {
		return nil, err
	}
	items, err := syncItems(effective, "effective.items", true)
	if err != nil {
		return nil, err
	}
	itemByName := map[string]any{}
	var storedNames []string
	for _, i := range items {
		name, err := syncText(i, "name")
		if err != nil {
			return nil, err
		}
		if _, seen := itemByName[name]; !seen {
			storedNames = append(storedNames, name)
		}
		itemByName[name] = i
	}
	contractList, err := r.contractNames(api, org, project, effective, &res.notices)
	if err != nil {
		return nil, err
	}
	pairs, keySet, err := selectKeys(adapter, t, storedNames, contractList, destination)
	if err != nil {
		return nil, err
	}
	if keySet == "stored" && !slices.ContainsFunc(res.notices, func(n string) bool { return strings.HasPrefix(n, "cannot read the Contract") }) {
		res.notices = append(res.notices, "no active Contract: comparing the stored items, and extra-on-platform is not reported")
	}

	// The platform first: when it cannot be read, nothing is disclosed.
	var platform map[string]*string
	reader, canRead := adapter.(vsync.ValueReader)
	if !adapter.SupportsReadBack() || !canRead {
		res.notices = append(res.notices, string(adapter.Platform())+" values cannot be read back (write-only): no key can be compared")
	} else {
		credential, _ := r.Env.LookupEnv(t.tokenEnv)
		if credential == "" {
			return finish(keySet, []checkedKey{}, "no platform credential in $"+t.tokenEnv+" (choose the variable with --token-env)", true), nil
		}
		r.holdSecret(credential)
		req := r.syncRequest(base, destination, credential, nil)
		platform, err = reader.ReadValues(bg, req)
		if err != nil {
			// An adapter's message holds a status or an error class only;
			// anything else may quote the response, so it is never repeated.
			var a *vsync.AdapterError
			if errors.As(err, &a) {
				return finish(keySet, []checkedKey{}, a.Message, true), nil
			}
			name := "error"
			var s *vsync.ScriptError
			if errors.As(err, &s) {
				name = s.Name
			}
			return finish(keySet, []checkedKey{}, "the platform's response could not be read ("+name+")", true), nil
		}
		if platform == nil {
			platform = map[string]*string{}
		}
		if inspector, ok := adapter.(vsync.UsageInspector); ok {
			var names []string
			for _, p := range pairs {
				if !p.invalid {
					names = append(names, p.destination)
				}
			}
			if report := inspector.InspectUsage(bg, req, names); report != nil {
				res.usage = append(res.usage, usageNotes(report)...)
			}
		}
	}

	// What Varlatch holds for each compared key: a value, nil when withheld.
	varlatch := map[string]*string{}
	var secrets []string
	for _, p := range pairs {
		item, ok := itemByName[p.name]
		if !ok {
			continue
		}
		if sensitive, ok := syncGet(item, "sensitive"); !ok || !jsjson.Truthy(sensitive) {
			// typeof item.value === "string" ? item.value : null
			varlatch[p.name] = nil
			if v, _ := syncGet(item, "value"); v != nil {
				if s, isString := v.(string); isString {
					varlatch[p.name] = &s
				}
			}
			continue
		}
		varlatch[p.name] = nil
		// Only a Secret the platform also holds, and lets this token read, needs its value.
		if v, ok := platform[p.destination]; ok && v != nil && !slices.Contains(secrets, p.name) {
			secrets = append(secrets, p.name)
		}
	}
	if len(secrets) > 0 {
		list := make([]any, len(secrets))
		for i, s := range secrets {
			list[i] = s
		}
		disclosed, err := api.DiscloseSecrets(bg, org, project, environment, jsjson.Object{{Key: "items", Value: list}})
		if err != nil {
			apiErr, refused := isDisclosureRefusal(err)
			if !refused {
				return nil, err
			}
			res.notices = append(res.notices, "secrets not disclosed ("+safeCode(apiErr.Code)+"): Secrets the platform holds cannot be compared")
		} else {
			list, err := syncItems(disclosed, "disclosed.items", false)
			if err != nil {
				return nil, err
			}
			for _, i := range list {
				name, err := syncText(i, "name")
				if err != nil {
					return nil, err
				}
				if _, ok := varlatch[name]; !ok {
					continue
				}
				// varlatch.set(i.name, i.value): no value (absent or null) is
				// withheld; one that is not a string never equals the
				// platform's (===), so it differs, whatever its text.
				v, _ := syncGet(i, "value")
				switch value := v.(type) {
				case string:
					r.holdSecret(value)
					varlatch[name] = &value
				case nil:
					varlatch[name] = nil
				default:
					if v == apiclient.Undefined {
						varlatch[name] = nil
					} else {
						varlatch[name] = notAString
					}
				}
			}
		}
	}
	return finish(keySet, compareKeys(pairs, varlatch, platform), "", false), nil
}

// contractNames is syncCheck.ts's contractNames: the active Contract's item
// names, or nil when there is none this identity can read.
func (r *Run) contractNames(api *apiclient.Client, org, project string, effective any, notices *[]string) ([]string, error) {
	manifest, _ := syncGet(effective, "manifest")
	if c, _ := syncGet(manifest, "contract"); jsjson.Truthy(manifest) && !jsjson.Truthy(c) {
		return nil, nil
	}
	revision, err := api.GetActiveContract(bg, org, project)
	if err != nil {
		var a *apiclient.APIError
		if !errors.As(err, &a) || (a.Status != 404 && a.Status != 403) {
			return nil, err
		}
		if a.Status == 403 {
			*notices = append(*notices, "cannot read the Contract (403): comparing the stored items, and extra-on-platform is not reported")
		}
		return nil, nil
	}
	c, cOK, err := read(revision, revision != apiclient.Undefined, "contract")
	if err != nil {
		return nil, err
	}
	if !cOK || !jsjson.Truthy(c) {
		return nil, nil
	}
	list, err := pageItems(c, "contract", "map")
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, i := range list {
		name, err := syncText(i, "name")
		if err != nil {
			return nil, err
		}
		if !slices.Contains(contract.ReservedItemNames, name) {
			names = append(names, name)
		}
	}
	return names, nil
}

// selectKeys is syncCheck.ts's selectKeys: --map selects (and renames);
// otherwise every Contract item (or stored item), less --exclude.
func selectKeys(adapter vsync.Adapter, t syncTarget, stored []string, contractList []string, target vsync.Fields) ([]keyPair, string, error) {
	var pairs []keyPair
	pair := func(name, dest string) {
		destination := adapter.CanonicalizeName(dest)
		pairs = append(pairs, keyPair{name: name, destination: destination, invalid: adapter.ValidateName(destination, target) != ""})
	}
	var keySet string
	if len(t.maps) > 0 {
		if len(t.excludes) > 0 {
			return nil, "", &syncCheckUsageError{"--exclude only applies without --map (explicit maps already select)"}
		}
		known := map[string]bool{}
		for _, n := range stored {
			known[n] = true
		}
		for _, n := range contractList {
			known[n] = true
		}
		var unknown []string
		for _, m := range t.maps {
			name, rename, renamed := splitMap(m)
			if !itemNamePattern.MatchString(name) || (renamed && rename == "") {
				return nil, "", &syncCheckUsageError{"--map expects NAME or NAME=DEST, got \"" + m + "\""}
			}
			// A misspelled name must not pass as "absent".
			if !known[name] {
				unknown = append(unknown, name)
				continue
			}
			if !renamed {
				rename = name
			}
			pair(name, rename)
		}
		if len(unknown) > 0 {
			slices.SortFunc(unknown, jsval.CompareUTF16)
			unknown = slices.Compact(unknown)
			return nil, "", &syncCheckUsageError{"--map must name items stored in this environment or in its Contract; not found: " + strings.Join(unknown, ", ")}
		}
		keySet = "map"
	} else {
		names := contractList
		if names == nil {
			for _, n := range stored {
				if !slices.Contains(contract.ReservedItemNames, n) {
					names = append(names, n)
				}
			}
		}
		unique := slices.Clone(names)
		slices.SortFunc(unique, jsval.CompareUTF16)
		unique = slices.Compact(unique)
		for _, name := range unique {
			if !excludedBy(t.excludes, name) {
				pair(name, name)
			}
		}
		keySet = "stored"
		if contractList != nil {
			keySet = "contract"
		}
	}
	seen := map[string]string{}
	for _, p := range pairs {
		if other, ok := seen[p.destination]; ok && other != p.name {
			return nil, "", &syncCheckUsageError{other + " and " + p.name + " both map to the platform name " + p.destination}
		}
		seen[p.destination] = p.name
	}
	return pairs, keySet, nil
}

// usageNotes is syncCheck.ts's usageNotes: the report as notes, sorted by
// name (localeCompare, the root collation).
func usageNotes(report *vsync.UsageReport) []usageNote {
	if !report.Checked {
		reason := report.Reason
		if reason == "" {
			reason = "unknown"
		}
		return []usageNote{{code: "usage-unchecked", reason: reason}}
	}
	named := slices.Clone(report.Names)
	c := collate.New(language.Und)
	slices.SortStableFunc(named, func(a, b vsync.NamedUsage) int { return c.CompareString(a.Name, b.Name) })
	var notes []usageNote
	for _, n := range named {
		u := n.Usage
		if u.Owned {
			notes = append(notes, usageNote{code: "owned", name: n.Name})
		}
		if len(u.ShadowedIn) > 0 {
			notes = append(notes, usageNote{code: "shadowed", name: n.Name, containers: u.ShadowedIn, hasContainers: true})
		}
		if len(u.NotDeliveredTo) > 0 {
			notes = append(notes, usageNote{code: "not-delivered", name: n.Name})
		}
		if len(u.UnknownIn) > 0 {
			notes = append(notes, usageNote{code: "unknown-form", name: n.Name, containers: u.UnknownIn, hasContainers: true})
		}
		if u.GeneratedOnce {
			notes = append(notes, usageNote{code: "generated-once", name: n.Name})
		}
	}
	return notes
}

// describeUsage is syncCheck.ts's describeUsage.
func (r *Run) describeUsage(n usageNote) string {
	where := strings.Join(n.containers, ", ")
	switch n.code {
	case "owned":
		return n.name + ": the platform sets this name itself; a Sync Target will not write it"
	case "shadowed":
		return n.name + ": the compose file sets it in " + where + ", which wins over the stored value"
	case "not-delivered":
		return n.name + ": no container uses it"
	case "unknown-form":
		return n.name + ": used in " + where + " in a form Varlatch does not read"
	case "generated-once":
		return n.name + ": generated once by the platform; a database may read it only on first start"
	}
	reason := "unknown"
	if n.reason != "" {
		reason = r.Secrets.ServerMessage(n.reason)
	}
	return "usage not checked: " + reason
}

// formatSyncCheck is syncCheck.ts's formatSyncCheck: names and statuses only.
func (r *Run) formatSyncCheck(res *syncCheckResult) ([]string, []string) {
	whereParts := []string{res.platform, res.base}
	for _, f := range res.destination {
		whereParts = append(whereParts, f.Value)
	}
	where := strings.Join(whereParts, " ")
	var errLines []string
	for _, n := range res.notices {
		errLines = append(errLines, "varlatch: "+n)
	}
	for _, u := range res.usage {
		errLines = append(errLines, "varlatch: usage: "+r.describeUsage(u))
	}
	if res.hasUnchecked {
		errLines = append(errLines, "varlatch: could not check "+where+" against "+res.environment+": "+res.unchecked)
		return nil, printableAll(errLines)
	}
	width := 0
	for _, k := range res.keys {
		width = max(width, utf16Len(checkLabels[k.status]))
	}
	outLines := []string{where + " against " + res.environment + ":"}
	for _, k := range res.keys {
		name := k.name
		if k.destination != k.name {
			name = k.name + " -> " + k.destination
		}
		label := checkLabels[k.status]
		line := "  " + label + strings.Repeat(" ", width-utf16Len(label)) + "  " + name
		if k.reason != "" {
			line += " (" + checkReasons[k.reason] + ")"
		}
		outLines = append(outLines, line)
	}
	count := func(s string) string {
		n := 0
		for _, k := range res.keys {
			if k.status == s {
				n++
			}
		}
		return strconv.Itoa(n)
	}
	tally := count("match") + " match, " + count("differs") + " differ, " + count("missing-on-platform") + " missing on the platform, " +
		count("extra-on-platform") + " extra on the platform, " + count("unreadable") + " not compared"
	switch res.exitCode {
	case 0:
		outLines = append(outLines, "in sync: "+tally)
	case 1:
		outLines = append(outLines, "DRIFT: "+tally)
	default:
		outLines = append(outLines, "INCOMPLETE: "+tally)
	}
	return printableAll(outLines), printableAll(errLines)
}

// syncCheckDocument is syncCheck.ts's syncCheckDocument: names, statuses
// and counts; never a value.
func syncCheckDocument(res *syncCheckResult) jsjson.Object {
	result := "incomplete"
	switch {
	case res.hasUnchecked:
		result = "unchecked"
	case res.exitCode == 0:
		result = "match"
	case res.exitCode == 1:
		result = "drift"
	}
	counts := jsjson.Object{}
	for _, s := range checkStatuses {
		n := 0
		for _, k := range res.keys {
			if k.status == s {
				n++
			}
		}
		counts = append(counts, jsjson.Member{Key: s, Value: float64(n)})
	}
	keys := make([]any, len(res.keys))
	for i, k := range res.keys {
		o := jsjson.Object{{Key: "name", Value: k.name}, {Key: "destination", Value: k.destination}, {Key: "status", Value: k.status}}
		if k.reason != "" {
			o = append(o, jsjson.Member{Key: "reason", Value: k.reason})
		}
		keys[i] = o
	}
	usage := make([]any, len(res.usage))
	for i, u := range res.usage {
		o := jsjson.Object{{Key: "code", Value: u.code}}
		if u.name != "" {
			o = append(o, jsjson.Member{Key: "name", Value: u.name})
		}
		if u.hasContainers {
			list := make([]any, len(u.containers))
			for j, c := range u.containers {
				list[j] = c
			}
			o = append(o, jsjson.Member{Key: "containers", Value: list})
		}
		if u.code == "usage-unchecked" {
			o = append(o, jsjson.Member{Key: "reason", Value: u.reason})
		}
		usage[i] = o
	}
	notices := make([]any, len(res.notices))
	for i, n := range res.notices {
		notices[i] = n
	}
	doc := jsjson.Object{
		{Key: "result", Value: result}, {Key: "platform", Value: res.platform}, {Key: "base", Value: res.base},
		{Key: "destination", Value: fieldsObject(res.destination)}, {Key: "environment", Value: res.environment}, {Key: "keySet", Value: res.keySet},
	}
	if res.hasUnchecked {
		doc = append(doc, jsjson.Member{Key: "unchecked", Value: res.unchecked})
	}
	return append(doc, jsjson.Member{Key: "counts", Value: counts}, jsjson.Member{Key: "keys", Value: keys},
		jsjson.Member{Key: "usage", Value: usage}, jsjson.Member{Key: "notices", Value: notices}, jsjson.Member{Key: "exitCode", Value: float64(res.exitCode)})
}

// ---------------------------------------------------------------------------
// sync push

// syncPush is syncPush.ts's runSyncPush: the server renders and audits the
// disclosure; this carries the result to the platform, write-only. Every
// check, and the platform's usage report, comes before the one write.
func (r *Run) syncPush(lazy *lazyAPI, org, project, environment string, t syncTarget) (int, error) {
	fail := func(line string) (int, error) { return 1, r.warn("varlatch: " + line) }
	adapter, err := vsync.GetAdapter(t.platform)
	if err != nil {
		return fail("unknown platform \"" + t.platform + "\" (github-actions, coolify, convex)")
	}
	credential, _ := r.Env.LookupEnv(t.tokenEnv)
	if credential == "" {
		return fail("no platform credential in $" + t.tokenEnv + " (choose the variable with --token-env)")
	}
	// A platform echoing the credential back in an error gets it masked (issue #119).
	r.holdSecret(credential)
	_, base, destination, err := resolveSyncTarget(t, true)
	if err != nil {
		return fail(err.Error())
	}

	api, err := lazy.get()
	if err != nil {
		return 0, err
	}
	// Server-rendered values: the server audits these disclosures (ADR-0016).
	effective, err := api.EffectiveConfiguration(bg, org, project, environment, true)
	if err != nil {
		return 0, err
	}
	type entry struct {
		name      string
		sensitive bool
		value     any
	}
	var items []entry
	list, err := syncItems(effective, "effective.items", true)
	if err != nil {
		return 0, err
	}
	for _, i := range list {
		name, err := syncText(i, "name")
		if err != nil {
			return 0, err
		}
		sensitive, _ := syncGet(i, "sensitive")
		value, ok := syncGet(i, "value")
		if !ok {
			value = apiclient.Undefined
		}
		items = append(items, entry{name: name, sensitive: jsjson.Truthy(sensitive), value: value})
	}
	disclosed, err := api.DiscloseSecrets(bg, org, project, environment, jsjson.Object{{Key: "scope", Value: "all-authorized-secrets"}})
	if err != nil {
		apiErr, refused := isDisclosureRefusal(err)
		if !refused {
			return 0, err
		}
		if err := r.warn("varlatch: secrets not disclosed (" + safeCode(apiErr.Code) + "); pushing non-sensitive values only"); err != nil {
			return 0, err
		}
	} else {
		list, err := syncItems(disclosed, "disclosed.items", false)
		if err != nil {
			return 0, err
		}
		byName := map[string]any{}
		for _, i := range list {
			name, err := syncText(i, "name")
			if err != nil {
				return 0, err
			}
			v, ok := syncGet(i, "value")
			if !ok {
				v = apiclient.Undefined
			}
			byName[name] = v
		}
		for k := range items {
			if v, ok := byName[items[k].name]; ok && items[k].sensitive && v != apiclient.Undefined {
				items[k].value = v
			}
		}
	}

	// readable: name -> value, in the order of the first occurrence, the last value.
	var readableNames []string
	readable := map[string]string{}
	for _, i := range items {
		value, ok := pushReadable(i.value)
		if !ok {
			continue
		}
		if _, seen := readable[i.name]; !seen {
			readableNames = append(readableNames, i.name)
		}
		readable[i.name] = value
	}

	var selected []vsync.SyncItem
	var problems []string
	addItem := func(name, dest string) {
		value, ok := readable[name]
		if !ok {
			problems = append(problems, name+": not readable in this environment")
			return
		}
		destName := adapter.CanonicalizeName(dest)
		if invalid := adapter.ValidateName(destName, destination); invalid != "" {
			problems = append(problems, name+": "+invalid)
			return
		}
		selected = append(selected, vsync.SyncItem{Name: destName, Value: value})
	}
	if len(t.maps) > 0 {
		if len(t.excludes) > 0 {
			return fail("--exclude only applies without --map (explicit maps already select)")
		}
		for _, m := range t.maps {
			name, rename, renamed := splitMap(m)
			if !renamed {
				rename = name
			}
			addItem(name, rename)
		}
	} else {
		for _, name := range readableNames {
			if !excludedBy(t.excludes, name) {
				addItem(name, name)
			}
		}
	}
	for _, p := range problems {
		if err := r.warn("varlatch: skipped " + Printable(p)); err != nil {
			return 0, err
		}
	}
	if len(selected) == 0 {
		return fail("nothing to push")
	}

	// A Coolify service says how its compose file uses each name.
	var usage *vsync.UsageReport
	if inspector, ok := adapter.(vsync.UsageInspector); ok {
		names := make([]string, len(selected))
		for i, s := range selected {
			names[i] = s.Name
		}
		usage = inspector.InspectUsage(bg, r.syncRequest(base, destination, credential, nil), names)
	}
	if usage != nil && !usage.Checked {
		reason := "unknown"
		if usage.Reason != "" {
			reason = r.Secrets.ServerMessage(usage.Reason)
		}
		if err := r.warn("varlatch: usage not checked: " + reason); err != nil {
			return 0, err
		}
	}
	var writable []vsync.SyncItem
	for _, item := range selected {
		if u, ok := usage.Get(item.Name); ok && u.Owned {
			problems = append(problems, item.Name+": the platform sets this name itself")
			if err := r.warn("varlatch: skipped " + Printable(item.Name) + ": the platform sets this name itself"); err != nil {
				return 0, err
			}
			continue
		}
		writable = append(writable, item)
	}
	if len(writable) == 0 {
		return fail("nothing to push")
	}

	// A platform echoing a value back in an error gets it masked (issue #119).
	for _, item := range writable {
		r.holdSecret(item.Value)
	}
	outcomes, err := adapter.WriteValues(bg, r.syncRequest(base, destination, credential, usage), writable)
	if err != nil {
		return 0, errors.New(adapterMessage(err))
	}
	failed := 0
	for _, o := range outcomes {
		if o.OK {
			if err := r.println("pushed " + Printable(o.Name)); err != nil {
				return 0, err
			}
			continue
		}
		failed++
		reason := "error"
		if o.Error != "" {
			reason = r.Secrets.ServerMessage(o.Error)
		}
		if err := r.warn("varlatch: failed " + Printable(o.Name) + ": " + reason); err != nil {
			return 0, err
		}
	}
	if err := r.println(strconv.Itoa(len(outcomes)-failed) + "/" + strconv.Itoa(len(outcomes)) + " value(s) pushed to " + string(adapter.Platform()) + " (" + base + ")"); err != nil {
		return 0, err
	}
	if failed > 0 || len(problems) > 0 {
		return 1, nil
	}
	return 0, nil
}
