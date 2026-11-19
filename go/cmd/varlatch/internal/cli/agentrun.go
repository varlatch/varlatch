// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/broker"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/targets"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// `varlatch run --agent-safe` (slice 5.5b of internal docs/design/go-cli.md),
// apps/cli/src/agentRun.ts (ADR-0022 §8, ADR-0039, ADR-0043 Decision 5):
// the trusted parent resolves configuration and starts the Agent with
// non-sensitive values, Placeholders for Secrets, and the proxy settings of
// a local Broker (internal/broker), never a Secret's value and no reusable
// Varlatch credential. The Broker credential never enters the Agent's
// environment, and the per-run proxy credential appears only in the
// Agent's proxy URLs, never in what the CLI prints. The Agent gets an empty
// configuration directory of its own and VARLATCH_AGENT_RUN, so a
// `varlatch` command it starts never falls back to the operator's
// credential.

// brokerCredentialEnv is BROKER_CREDENTIAL_ENV.
const brokerCredentialEnv = "VARLATCH_BROKER_CREDENTIAL"

// targetsServer is TARGETS_SERVER: the minimum server for agent-safe runs.
const targetsServer = "0.11.0"

// agentRunOptions is AgentRunOptions.
type agentRunOptions struct {
	agent string
	// brokerCredentialFile is --broker-credential-file, "" when not given.
	brokerCredentialFile string
	allowHosts           []string
	strict               bool
	// ttlSeconds is Number(--ttl ?? 3600): NaN when it is not a number.
	ttlSeconds         float64
	metadataCredential bool
	// targets are `--target NAME=kind:location`, canonical, by item.
	targets map[string][]string
	omit    []string
}

// agentRunFlags reads the options main.ts gives runAgentSafe, in its
// order: --agent first, then the targets (each a usage error when it is
// not one).
func agentRunFlags(pre []string) (agentRunOptions, error) {
	agent, ok := flagArg(pre, "--agent")
	if !ok {
		return agentRunOptions{}, UsageError("Agent-safe runs need --agent <agent-identity name or id>")
	}
	opts := agentRunOptions{agent: agent, allowHosts: flagValues(pre, "--allow-host"), ttlSeconds: 3600, omit: flagValues(pre, "--omit")}
	opts.brokerCredentialFile, _ = flagArg(pre, "--broker-credential-file")
	network, _ := flagArg(pre, "--agent-network")
	opts.strict = network == "strict"
	if ttl, ok := flagArg(pre, "--ttl"); ok {
		n, isNumber := jsval.ToNumber(jsval.UTF16(ttl))
		if !isNumber {
			n = math.NaN()
		}
		opts.ttlSeconds = n
	}
	opts.metadataCredential = hasArg(pre, "--agent-metadata")
	parsed, err := targetFlags(pre)
	if err != nil {
		return agentRunOptions{}, err
	}
	opts.targets = parsed
	return opts, nil
}

// targetFlags is main.ts's targetFlags: `--target NAME=kind:location`, each
// target in its canonical form, by item in the order given.
func targetFlags(pre []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, raw := range flagValues(pre, "--target") {
		name, target, found := strings.Cut(raw, "=")
		if !found || name == "" {
			return nil, UsageError(`--target expects NAME=kind:location (for example API_KEY=header:authorization), got "` + raw + `"`)
		}
		canonical, err := targets.Parse(target)
		if err != nil {
			return nil, UsageError("--target " + raw + ": " + err.Error())
		}
		out[name] = append(out[name], canonical)
	}
	return out, nil
}

// agentSafeFailure is main.ts's catch around runAgentSafe: an API error or
// an unreachable server keeps its own status (77, 69 and the rest), a
// usage error is 64 with "Nothing was started.", and any other error is
// its message alone, status 1.
func agentSafeFailure(err error) error {
	if err == nil {
		return nil
	}
	var exit *exitError
	var api *apiclient.APIError
	var fetch *apiclient.FetchError
	var wrong *agentUsageError
	switch {
	case errors.As(err, &exit), errors.As(err, &api), errors.As(err, &fetch):
		return err
	case errors.As(err, &wrong):
		return UsageError("varlatch: " + wrong.message + ". Nothing was started.")
	}
	return Fail(err.Error(), ExitFailure)
}

// agentUsageError is strictRun.ts's UsageError as runAgentSafe throws it.
type agentUsageError struct{ message string }

func (e *agentUsageError) Error() string { return e.message }

// checkTargetFlags is checkTargetFlags: every stored Secret is either
// targeted or omitted; a flag naming anything else is a typo, never
// ignored. It gives the Secrets the run mediates, sorted.
func checkTargetFlags(storedSecrets []string, opts agentRunOptions) ([]string, error) {
	stored := map[string]bool{}
	for _, n := range storedSecrets {
		stored[n] = true
	}
	omitted := map[string]bool{}
	for _, n := range opts.omit {
		omitted[n] = true
	}
	var unknown []string
	for n := range opts.targets {
		if !stored[n] {
			unknown = append(unknown, n)
		}
	}
	for n := range omitted {
		if !stored[n] && opts.targets[n] == nil {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		slices.SortFunc(unknown, jsval.CompareUTF16)
		return nil, &agentUsageError{"--target and --omit must name Secrets stored in this environment; not stored here: " + strings.Join(unknown, ", ")}
	}
	var both []string
	for n := range opts.targets {
		if omitted[n] {
			both = append(both, n)
		}
	}
	if len(both) > 0 {
		slices.SortFunc(both, jsval.CompareUTF16)
		return nil, &agentUsageError{"an item cannot be both targeted and omitted: " + strings.Join(both, ", ")}
	}
	var untargeted, mediated []string
	for _, n := range uniqueNames(storedSecrets) {
		if omitted[n] {
			continue
		}
		mediated = append(mediated, n)
		if opts.targets[n] == nil {
			untargeted = append(untargeted, n)
		}
	}
	slices.SortFunc(mediated, jsval.CompareUTF16)
	if len(untargeted) > 0 {
		slices.SortFunc(untargeted, jsval.CompareUTF16)
		lines := make([]string, len(untargeted))
		for i, name := range untargeted {
			// Stored names come from the server: each escaped, the message's own lines kept.
			n := Printable(name)
			lines[i] = n + " has no substitution target: add --target " + n + "=header:authorization\n" +
				"          (or query:, json:, form:), or --omit " + n + " to leave it out of this run"
		}
		return nil, &agentUsageError{strings.Join(lines, "\nvarlatch: ")}
	}
	return mediated, nil
}

// uniqueNames is [...new Set(names)].
func uniqueNames(names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		if !seen[n] {
			out = append(out, n)
		}
		seen[n] = true
	}
	return out
}

// includesCapability is meta.capabilities.includes(name): an array's
// element, or a string's substring.
func includesCapability(meta any, name string) (bool, error) {
	caps, ok, err := read(meta, true, "capabilities")
	if err != nil {
		return false, err
	}
	switch list := caps.(type) {
	case []any:
		return slices.Contains(list, any(name)), nil
	case string:
		return strings.Contains(list, name), nil
	case nil:
		return false, typeErrorRead(caps, ok, "includes")
	}
	return false, &clientctx.TypeError{Message: "meta.capabilities.includes is not a function"}
}

// requireTargetsServer is requireTargetsServer: a server that cannot record
// targets is refused; never fall back to substituting anywhere.
func (r *Run) requireTargetsServer(c *apiclient.Client) error {
	meta, err := c.Meta(context.Background())
	if err != nil {
		return err
	}
	targetsOK, err := includesCapability(meta, "capabilities.targets")
	if err != nil {
		return err
	}
	if !targetsOK {
		return errors.New("varlatch: agent-safe runs need Varlatch " + targetsServer + " or later on the server, which records substitution targets; " +
			"this server is " + r.serverVersionText(meta) + ". Nothing was started.")
	}
	return nil
}

// serverVersionText is `${safeVersion(meta.serverVersion) ?? "an older release"}`.
func (r *Run) serverVersionText(meta any) string {
	v, _ := jsval.Get(meta, "serverVersion")
	if s, ok := r.Secrets.SafeVersion(v); ok {
		return s
	}
	return "an older release"
}

// contractSecrets is contractSecrets: the Contract's Secret names, so
// inherited copies can be stripped. With an active Contract the run needs
// contract.read: it never proceeds with stripping it could not complete.
func (r *Run) contractSecrets(c *apiclient.Client, ctx *clientctx.Context, effective any) ([]string, error) {
	manifest := fieldOf(effective, "manifest")
	if !jsjson.Truthy(manifest) {
		return nil, errors.New("varlatch: agent-safe runs need Varlatch " + targetsServer + " or later on the server. Nothing was started.")
	}
	if !jsjson.Truthy(fieldOf(manifest, "contract")) {
		return nil, nil
	}
	revision, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 403 || apiErr.Status == 404) {
		return nil, errors.New("varlatch: this environment has an active Contract, and an agent-safe run needs contract.read to know which " +
			"inherited names are Secrets and remove them from the Agent's environment. Nothing was started.")
	} else if err != nil {
		return nil, err
	}
	var names []string
	for _, item := range listOf(fieldOf(revision, "contract"), "items") {
		if jsjson.Truthy(fieldOf(item, "sensitive")) {
			names = append(names, jsjson.String(fieldOf(item, "name")))
		}
	}
	return names, nil
}

// storedSecretNames are the effective configuration's Secrets, the run
// context left out.
func storedSecretNames(effective any) []string {
	var out []string
	for _, item := range listOf(effective, "items") {
		name := jsjson.String(fieldOf(item, "name"))
		if jsjson.Truthy(fieldOf(item, "sensitive")) && name != runContextName {
			out = append(out, name)
		}
	}
	return out
}

// mintedCredential is Minted: a short-lived agent-run credential and how
// to revoke it.
type mintedCredential struct {
	server, token string
	revoke        func() error
}

// agentEnvironment is buildAgentEnv: the operator's environment without the
// Broker credential, the operator's bearer, a run context, and the stored
// and Contract Secrets it inherited; the run's non-sensitive values, a
// Placeholder for each Secret it carries; with --agent-metadata the
// agent-run credential; and the proxy settings. It gives the inherited
// no-proxy entries it removed.
func agentEnvironment(base *orderedEnv, effective any, placeholders map[string]string, proxyURL string, credential *mintedCredential, strip []string) (*orderedEnv, []string) {
	env := base
	// The Broker credential is the parent's secret, never the child's, and
	// neither is the parent's own bearer (VARLATCH_TOKEN).
	env.Delete(brokerCredentialEnv)
	env.Delete("VARLATCH_TOKEN")
	env.Delete(runContextName)
	// Stored and Contract Secrets inherited from the operator's shell never
	// reach the Agent; the ones the run carries come back as Placeholders.
	for _, name := range strip {
		env.Delete(name)
	}
	if credential != nil {
		env.Set("VARLATCH_SERVER", credential.server)
		env.Set("VARLATCH_TOKEN", credential.token)
	}
	for _, item := range listOf(effective, "items") {
		name := jsjson.String(fieldOf(item, "name"))
		if name == runContextName {
			continue
		}
		if placeholder, ok := placeholders[name]; ok {
			env.Set(name, placeholder)
		} else if jsjson.Truthy(fieldOf(item, "sensitive")) {
			env.Delete(name)
		} else if v := fieldOf(item, "value"); v != nil {
			env.Set(name, jsjson.String(v))
		}
	}
	var removed []string
	if proxyURL != "" {
		removed = setProxy(env, proxyURL)
	}
	return env, removed
}

// setProxy is setProxy: every spelling of the proxy variables names the
// Broker, Node's fetch is told to honour them, and each spelling of the
// no-proxy variable exempts the Broker's own address and nothing it did not
// already (agentNoProxy). It gives the entries it removed.
func setProxy(env *orderedEnv, proxyURL string) []string {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env.Set(name, proxyURL)
	}
	// Node's fetch (and, from Node 24, its http module) honours the proxy
	// variables only with this set (ADR-0039 Decision 11).
	env.Set("NODE_USE_ENV_PROXY", "1")
	var removed []string
	for _, spelling := range []string{"NO_PROXY", "no_proxy"} {
		value, _ := env.Get(spelling)
		for _, entry := range noProxyEntries(value) {
			if exemptsEveryHost(entry) {
				removed = append(removed, spelling+"="+entry)
			}
		}
	}
	host := proxyURL
	if u, ok := whatwg.ParseURL(proxyURL); ok {
		host = u.Host
	}
	upper, _ := env.Get("NO_PROXY")
	lower, _ := env.Get("no_proxy")
	env.Set("NO_PROXY", withBroker(upper, host))
	env.Set("no_proxy", withBroker(lower, host))
	return removed
}

var (
	everyHostOnPort = regexp.MustCompile(`^\*(:[0-9]+)?$`)
	everyAddress    = regexp.MustCompile(`^\[?[0-9a-f.:]+\]?/0$`)
)

// exemptsEveryHost is exemptsEveryHost: `*`, `*:<port>`, or an address
// range with a /0 prefix.
func exemptsEveryHost(entry string) bool {
	e := whatwg.ToLower(whatwg.Trim(entry))
	return everyHostOnPort.MatchString(e) || everyAddress.MatchString(e)
}

func noProxyEntries(value string) []string {
	var out []string
	for _, e := range strings.Split(value, ",") {
		if e = whatwg.Trim(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// withBroker is agentNoProxy for one spelling: the entries it inherited,
// except one that exempts every host, and the Broker's address, each once.
func withBroker(value, brokerHost string) string {
	var kept []string
	for _, e := range noProxyEntries(value) {
		if !exemptsEveryHost(e) {
			kept = append(kept, e)
		}
	}
	return strings.Join(uniqueNames(append(kept, brokerHost)), ",")
}

// reportStripped is reportStripped: the inherited Secrets the run removed
// from the Agent's environment, by name, never their values.
func (r *Run) reportStripped(names []string, carried []string) {
	var stripped []string
	for _, n := range uniqueNames(names) {
		if _, set := r.Env.LookupEnv(n); set && !slices.Contains(carried, n) {
			stripped = append(stripped, n)
		}
	}
	if len(stripped) > 0 {
		slices.SortFunc(stripped, jsval.CompareUTF16)
		r.eprintln("varlatch: removed Secrets inherited from this shell from the Agent's environment: " + Printable(strings.Join(stripped, ", ")))
	}
}

// findAgent is findAgent: the organization's agent identity named or
// numbered `name`.
func findAgent(c *apiclient.Client, ctx *clientctx.Context, name string) (any, error) {
	identities, err := c.Request(context.Background(), "GET", "/v1/organizations/"+apiclient.EncodeURIComponent(ctx.Organization)+"/identities", apiclient.NoBody, nil)
	if err != nil {
		return nil, err
	}
	for _, i := range listOf(identities, "items") {
		if fieldOf(i, "kind") == "agent" && (fieldOf(i, "name") == name || fieldOf(i, "id") == name) {
			return i, nil
		}
	}
	return nil, errors.New(`No agent identity "` + name + `" in ` + ctx.Organization + `. Create one with the dashboard or the identities API (kind "agent").`)
}

// newRunID is `run_${randomBytes(8).toString("hex")}`.
func newRunID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "run_" + hex.EncodeToString(b)
}

// loadBrokerCredential is loadBrokerCredential: --broker-credential-file,
// else VARLATCH_BROKER_CREDENTIAL. A server echoing it back in an error
// gets it masked.
func (r *Run) loadBrokerCredential(opts agentRunOptions) (string, error) {
	if opts.brokerCredentialFile != "" {
		b, err := os.ReadFile(opts.brokerCredentialFile)
		if err != nil {
			return "", errors.New(nodeReadFileError(opts.brokerCredentialFile, err))
		}
		token := whatwg.Trim(string(b))
		r.Secrets.Remember(token)
		return token, nil
	}
	if fromEnv := r.Getenv(brokerCredentialEnv); fromEnv != "" {
		token := whatwg.Trim(fromEnv)
		r.Secrets.Remember(token)
		return token, nil
	}
	return "", errors.New("Agent-safe runs need a Broker credential: pass --broker-credential-file <path> or set " + brokerCredentialEnv)
}

// nodeReadFileError is the message of the error readFileSync(path) throws.
func nodeReadFileError(path string, err error) string {
	code := secretinput.ReadErrorCode(path, err)
	descriptions := map[string]string{
		"ENOENT":       "no such file or directory",
		"EACCES":       "permission denied",
		"EPERM":        "operation not permitted",
		"ENOTDIR":      "not a directory",
		"ELOOP":        "too many symbolic links encountered",
		"ENAMETOOLONG": "name too long",
		"EMFILE":       "too many open files",
		"EIO":          "i/o error",
	}
	if code == "EISDIR" {
		return "EISDIR: illegal operation on a directory, read"
	}
	if d, ok := descriptions[code]; ok {
		return code + ": " + d + ", open '" + path + "'"
	}
	return err.Error()
}

// agentTTL is ttlSeconds as JSON.stringify writes it: NaN is null.
func agentTTL(ttl float64) any {
	if math.IsNaN(ttl) || math.IsInf(ttl, 0) {
		return nil
	}
	return ttl
}

// mintFor is mintFor (ADR-0023): a short-lived, read-only agent-run
// credential the Agent can read configuration metadata with, revoked on
// exit (its TTL the fail-safe).
func mintFor(brokerAPI *apiclient.Client, ctx *clientctx.Context, server string, agentID any, runID string, ttl float64) (*mintedCredential, error) {
	id := jsjson.String(agentID)
	body := jsjson.Object{{Key: "ttlSeconds", Value: agentTTL(math.Min(ttl, 3600))}, {Key: "runId", Value: runID}}
	issued, err := brokerAPI.IssueAgentCredential(context.Background(), ctx.Organization, id, body)
	if err != nil {
		return nil, err
	}
	return &mintedCredential{
		server: server,
		token:  jsjson.String(fieldOf(issued, "token")),
		revoke: func() error {
			_, err := brokerAPI.RevokeAgentCredential(context.Background(), ctx.Organization, id, jsjson.String(fieldOf(issued, "id")))
			return ignoreAPIError(err)
		},
	}, nil
}

// ignoreAPIError is `.catch((err) => { if (!(err instanceof VarlatchApiError)) throw err; })`.
func ignoreAPIError(err error) error {
	var api *apiclient.APIError
	if errors.As(err, &api) {
		return nil
	}
	return err
}

// revokeQuietly is revokeQuietly: best effort, the Capability's TTL is the
// fail-safe.
func revokeQuietly(brokerAPI *apiclient.Client, ctx *clientctx.Context, capabilityID any) error {
	_, err := brokerAPI.RevokeCapability(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), jsjson.String(capabilityID))
	return ignoreAPIError(err)
}

// issuedCapability is the issued Capability as the run uses it.
type issuedCapability struct {
	id           any
	secret       string
	destinations []string
	targets      map[string][]string
	preflight    any
}

// stringList is a JSON list of strings, each String()ed.
func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, jsjson.String(x))
	}
	return out
}

// targetMap is a JSON object of target lists.
func targetMap(v any) map[string][]string {
	o, ok := v.(jsjson.Object)
	if !ok {
		return nil
	}
	out := map[string][]string{}
	for _, m := range o {
		out[m.Key] = stringList(m.Value)
	}
	return out
}

// sameTargetsJSON is broker.ts's sameTargets for the server's answer: the
// same items, each with the same targets in any order. A list that is not
// one never matches.
func sameTargetsJSON(answer any, want []targets.Item) bool {
	o, ok := answer.(jsjson.Object)
	if !ok || len(o) != len(want) {
		return false
	}
	got := map[string][]string{}
	for _, m := range o {
		list, ok := m.Value.([]any)
		if !ok {
			return false
		}
		var ts []string
		for _, x := range list {
			s, ok := x.(string)
			if !ok {
				return false
			}
			ts = append(ts, s)
		}
		slices.SortFunc(ts, targets.Compare)
		got[m.Key] = ts
	}
	for _, it := range want {
		ts, ok := got[it.Name]
		if !ok || !slices.Equal(ts, it.Targets) {
			return false
		}
	}
	return true
}

// issueWithTargets is issueWithTargets: issue, and refuse unless varlatchd
// recorded exactly the targets requested.
func issueWithTargets(brokerAPI *apiclient.Client, ctx *clientctx.Context, items []string, body jsjson.Object, requested map[string][]string) (*issuedCapability, error) {
	answer, err := brokerAPI.IssueCapability(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), body)
	if err != nil {
		return nil, err
	}
	cap := &issuedCapability{
		id:           fieldOf(answer, "id"),
		secret:       jsjson.String(fieldOf(answer, "secret")),
		destinations: stringList(fieldOf(answer, "destinations")),
		targets:      targetMap(fieldOf(answer, "targets")),
		preflight:    fieldOf(answer, "preflight"),
	}
	recorded := fieldOf(answer, "targets")
	if !jsjson.Truthy(recorded) {
		if err := revokeQuietly(brokerAPI, ctx, cap.id); err != nil {
			return nil, err
		}
		return nil, errors.New("varlatch: the server recorded different substitution targets than this run requested. Nothing was started.")
	}
	given := make([]targets.Item, 0, len(items))
	for _, n := range items {
		given = append(given, targets.Item{Name: n, Targets: requested[n]})
	}
	canonical, err := targets.Canonical(items, given)
	if err != nil {
		// Go is stricter than TypeScript, which leaves the Capability to its
		// TTL here: a run that is refused revokes what it was issued.
		if revokeErr := revokeQuietly(brokerAPI, ctx, cap.id); revokeErr != nil {
			return nil, revokeErr
		}
		return nil, err
	}
	if !sameTargetsJSON(recorded, canonical) {
		if err := revokeQuietly(brokerAPI, ctx, cap.id); err != nil {
			return nil, err
		}
		return nil, errors.New("varlatch: the server recorded different substitution targets than this run requested. Nothing was started.")
	}
	return cap, nil
}

// runAgentSafe is runAgentSafe.
func (r *Run) runAgentSafe(ctx *clientctx.Context, api *lazyClient, opts agentRunOptions, command string, commandArgs []string) error {
	c, err := api.get()
	if err != nil {
		return err
	}
	if err := r.requireTargetsServer(c); err != nil {
		return err
	}
	effective, err := c.EffectiveConfiguration(context.Background(), ctx.Organization, ctx.Project, environmentOf(ctx), true)
	if err != nil {
		return err
	}
	storedSecrets := storedSecretNames(effective)
	secretItems, err := checkTargetFlags(storedSecrets, opts)
	if err != nil {
		return err
	}
	contracted, err := r.contractSecrets(c, ctx, effective)
	if err != nil {
		return err
	}
	strip := append(slices.Clone(storedSecrets), contracted...)
	r.reportStripped(strip, secretItems)

	agent, err := findAgent(c, ctx, opts.agent)
	if err != nil {
		return err
	}
	agentID := fieldOf(agent, "id")
	runID := newRunID()
	server, err := serverString(ctx.Server)
	if err != nil {
		return err
	}

	if len(secretItems) == 0 {
		// Nothing to mediate: run with non-sensitive values and no broker.
		r.eprintln("varlatch: no Secrets to mediate in this run; running without a broker")
		var minted *mintedCredential
		if opts.metadataCredential {
			token, err := r.loadBrokerCredential(opts)
			if err != nil {
				return err
			}
			if minted, err = mintFor(r.plainClient(server, token), ctx, server, agentID, runID, opts.ttlSeconds); err != nil {
				return err
			}
		}
		env, _ := agentEnvironment(r.parentEnv(), effective, nil, "", minted, strip)
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env.Delete(name)
		}
		code, runErr := r.startAgent(runID, command, commandArgs, env)
		if minted != nil {
			if err := minted.revoke(); err != nil {
				return err
			}
		}
		if runErr != nil {
			return runErr
		}
		return ExitWith(code)
	}

	if len(opts.allowHosts) == 0 {
		return errors.New("This environment has " + strconv.Itoa(len(secretItems)) + " Secret(s); agent-safe runs need at least one --allow-host <host[:port]> destination")
	}

	token, err := r.loadBrokerCredential(opts)
	if err != nil {
		return err
	}
	brokerAPI := r.plainClient(server, token)
	requested := map[string][]string{}
	targetsBody := jsjson.Object{}
	for _, n := range secretItems {
		requested[n] = opts.targets[n]
		targetsBody = append(targetsBody, jsjson.Member{Key: n, Value: anyStrings(opts.targets[n])})
	}
	body := jsjson.Object{
		{Key: "agentIdentityId", Value: agentID},
		{Key: "items", Value: anyStrings(secretItems)},
		{Key: "destinations", Value: anyStrings(opts.allowHosts)},
		{Key: "targets", Value: targetsBody},
		{Key: "ttlSeconds", Value: agentTTL(opts.ttlSeconds)},
		{Key: "runId", Value: runID},
	}
	cap, err := issueWithTargets(brokerAPI, ctx, secretItems, body, requested)
	if err != nil {
		return err
	}
	if cap.preflight == "agent-lacks-secret-use" {
		r.eprintln("varlatch: warning \u2014 agent \"" + opts.agent + `" currently has no secret.use Grant here; exercises will be denied until one is granted`)
	}
	var mint func() (*mintedCredential, error)
	if opts.metadataCredential {
		mint = func() (*mintedCredential, error) {
			return mintFor(brokerAPI, ctx, server, agentID, runID, opts.ttlSeconds)
		}
	}
	return r.runMediated(mediatedRun{
		ctx: ctx, server: server, token: token, opts: opts, brokerAPI: brokerAPI, cap: cap, secretItems: secretItems,
		runID: runID, command: command, commandArgs: commandArgs, mint: mint,
		childEnv: func(placeholders map[string]string, proxyURL string, credential *mintedCredential) (*orderedEnv, []string) {
			return agentEnvironment(r.parentEnv(), effective, placeholders, proxyURL, credential, strip)
		},
	})
}

// anyStrings is a list of strings as a JSON value.
func anyStrings(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// mediatedRun is runMediated's arguments.
type mediatedRun struct {
	ctx         *clientctx.Context
	server      string
	token       string
	opts        agentRunOptions
	brokerAPI   *apiclient.Client
	cap         *issuedCapability
	secretItems []string
	runID       string
	command     string
	commandArgs []string
	mint        func() (*mintedCredential, error)
	childEnv    func(placeholders map[string]string, proxyURL string, credential *mintedCredential) (*orderedEnv, []string)
}

// startBroker is broker.Start; a test makes it fail.
var startBroker = broker.Start

// exerciseMaintenance is runMediated's maintenanceRetryMs: an Agent's
// request is waiting on each exercise, so during isolating maintenance the
// run gives up quickly and the Broker answers 503 with Retry-After.
const exerciseMaintenance = 15 * time.Second

// runMediated is runMediated: Placeholders for the run's Secrets, a Broker
// exercising the Capability, the Agent with the environment childEnv
// builds, and teardown: the Broker closes, a minted metadata credential and
// the Capability are revoked.
func (r *Run) runMediated(run mediatedRun) error {
	placeholdersByItem := map[string]string{}
	placeholders := map[string]string{}
	for _, name := range run.secretItems {
		token := broker.GeneratePlaceholder()
		placeholdersByItem[name] = token
		placeholders[token] = name
	}
	// One client for every exercise, as runMediated's exerciseApi: the
	// Broker exercises concurrently, and the client's one maintenance
	// budget is shared by the requests in flight together.
	retry := exerciseMaintenance
	exerciseAPI := apiclient.New(apiclient.Options{Server: run.server, Token: run.token, UserAgent: r.UserAgent(), MaintenanceRetry: &retry, Env: r.Env})
	capabilityID := jsjson.String(run.cap.id)
	diagnostics := r.newBrokerDiagnostics()
	exercise := func(_ context.Context, host string, port int, placements []broker.Placement) (broker.Exercised, error) {
		list := make([]any, len(placements))
		for i, p := range placements {
			list[i] = jsjson.Object{{Key: "item", Value: p.Item}, {Key: "target", Value: p.Target}}
		}
		body := jsjson.Object{
			{Key: "capabilitySecret", Value: run.cap.secret},
			{Key: "destination", Value: jsjson.Object{{Key: "host", Value: host}, {Key: "port", Value: float64(port)}}},
			{Key: "placements", Value: list},
		}
		result, err := exerciseAPI.ExerciseCapability(context.Background(), run.ctx.Organization, run.ctx.Project, environmentOf(run.ctx), capabilityID, body)
		if err != nil {
			return broker.Exercised{}, err
		}
		items, present := jsval.Get(result, "items")
		list2, ok := items.([]any)
		if !ok {
			if !present || items == nil {
				return broker.Exercised{}, typeErrorRead(items, present, "map")
			}
			return broker.Exercised{}, &clientctx.TypeError{Message: "result.items.map is not a function"}
		}
		exercised := broker.Exercised{Values: map[string]string{}, Retiring: map[string]string{}}
		for _, i := range list2 {
			name := jsjson.String(fieldOf(i, "name"))
			exercised.Values[name] = jsjson.String(fieldOf(i, "value"))
			if retiring := fieldOf(i, "retiring"); jsjson.Truthy(retiring) {
				exercised.Retiring[name] = jsjson.String(fieldOf(retiring, "value"))
			}
		}
		exercised.Targets = targetMap(fieldOf(result, "targets"))
		exercised.Withheld = stringList(fieldOf(result, "withheld"))
		return exercised, nil
	}
	running, err := startBroker(broker.Options{
		Placeholders: placeholders,
		Destinations: run.cap.destinations,
		Targets:      run.cap.targets,
		Exercise:     exercise,
		Strict:       run.opts.strict,
		Report:       diagnostics.report,
		RootCAs:      apiclient.RootPool(r.Env),
	})
	if err != nil {
		// Stricter than TypeScript (which leaves it to the TTL): nothing
		// starts, so the Capability is revoked.
		_ = revokeQuietly(run.brokerAPI, run.ctx, run.cap.id)
		return err
	}

	var minted *mintedCredential
	if run.mint != nil {
		if minted, err = run.mint(); err != nil {
			_ = running.Close()
			_ = revokeQuietly(run.brokerAPI, run.ctx, run.cap.id)
			return err
		}
	}
	issued := ""
	if minted != nil {
		issued = ", metadata credential issued"
	}
	r.eprintln("varlatch: agent-safe run " + run.runID + " \u2014 " + strconv.Itoa(len(run.secretItems)) + " Secret(s) as placeholders, " +
		"broker on 127.0.0.1:" + strconv.Itoa(running.Port) + ", destinations: " + Printable(strings.Join(run.cap.destinations, ", ")) + issued)

	env, removed := run.childEnv(placeholdersByItem, running.ProxyURL, minted)
	if len(removed) > 0 {
		r.eprintln("varlatch: removed inherited no-proxy entries that would send the Agent's requests around the Broker: " + strings.Join(removed, ", "))
	}
	code, runErr := r.startAgent(run.runID, run.command, run.commandArgs, env)

	_ = running.Close()
	diagnostics.summarize()
	if minted != nil {
		if err := minted.revoke(); err != nil {
			runErr = err
		}
	}
	if err := revokeQuietly(run.brokerAPI, run.ctx, run.cap.id); err != nil {
		runErr = err
	}
	if runErr != nil {
		return runErr
	}
	return ExitWith(code)
}

// startAgent is startAgent and withAgentIsolation: the Agent starts with
// its environment, a fresh, empty configuration directory of its own
// (mode 0700, removed when the Agent has exited, whatever its outcome) and
// the run's identifier.
func (r *Run) startAgent(runID, command string, commandArgs []string, env *orderedEnv) (int, error) {
	dir, err := os.MkdirTemp(r.nodeTmpdir(), "varlatch-agent-run-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	env.Set("VARLATCH_CONFIG_DIR", dir)
	env.Set(clientctx.AgentRunEnv, runID)
	return r.runChild(command, commandArgs, env.Lines(), nil)
}

// nodeTmpdir is os.tmpdir(): TMPDIR, TMP or TEMP without a trailing slash,
// else /tmp; the system's on Windows.
func (r *Run) nodeTmpdir() string {
	if runtime.GOOS == "windows" {
		return os.TempDir()
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		if v := r.Getenv(name); v != "" {
			if len(v) > 1 {
				v = strings.TrimSuffix(v, "/")
			}
			return v
		}
	}
	return "/tmp"
}

// brokerDiagnostics is brokerDiagnostics (ADR-0039 Decisions 14 and 23):
// each blocked or failed request and aborted response as it happens, each
// stray Placeholder and unscrubbable Secret once, and counts by rule and by
// scrubbed item at the end. Names, rules, and locations only, never a
// value. The Broker reports from its connections' goroutines.
type brokerDiagnostics struct {
	r        *Run
	mu       sync.Mutex
	counts   map[string]int
	scrubbed map[string]int
	once     map[string]bool
}

func (r *Run) newBrokerDiagnostics() *brokerDiagnostics {
	return &brokerDiagnostics{r: r, counts: map[string]int{}, scrubbed: map[string]int{}, once: map[string]bool{}}
}

// emit writes one line, escaped: item names and destinations come from the
// server and the run.
func (d *brokerDiagnostics) emit(line string) { d.r.eprintln(Printable(line)) }

func (d *brokerDiagnostics) say(key, line string) {
	if d.once[key] {
		return
	}
	d.once[key] = true
	d.emit(line)
}

func (d *brokerDiagnostics) report(event broker.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch event.Kind {
	case "stray":
		d.say("stray "+event.Item+" "+event.Surface,
			"varlatch-broker: "+event.Item+" placeholder forwarded unchanged in the "+event.Surface+", which is not a target")
	case "scrubbed":
		d.scrubbed[event.Item] += event.Count
	case "unscrubbable":
		d.say("short "+event.Item, "varlatch-broker: "+event.Item+" is shorter than 8 bytes and is not scrubbed from responses")
	case "incomplete-prefix":
		d.emit("varlatch-broker: a response ended in the first " + strconv.Itoa(event.Length) + " bytes of " + event.Item + ", relayed unchanged (only complete values are scrubbed)")
	case "aborted":
		d.emit("varlatch-broker: aborted a response: " + event.Reason)
	case "tunnel":
		d.counts["tunnel"]++
		d.say("tunnel "+event.Destination,
			"varlatch-broker: refused an HTTPS tunnel to "+event.Destination+" (curl, fetch, and most SDKs open one); a request that uses a Secret goes through varlatch request")
	case "blocked":
		d.counts[event.Rule]++
		d.emit("varlatch-broker: blocked a request (" + strconv.Itoa(event.Status) + "): " + event.Message)
	case "failed":
		d.counts[event.Rule]++
		d.emit("varlatch-broker: dropped a request after exercise (502): " + event.Message)
	}
}

func (d *brokerDiagnostics) summarize() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.counts) > 0 {
		total := 0
		var byRule []string
		for _, rule := range sortedLocale(d.counts) {
			total += d.counts[rule]
			byRule = append(byRule, rule+" "+strconv.Itoa(d.counts[rule]))
		}
		d.emit("varlatch: the broker refused " + strconv.Itoa(total) + " request(s): " + strings.Join(byRule, ", "))
	}
	if len(d.scrubbed) > 0 {
		var byItem []string
		for _, item := range sortedLocale(d.scrubbed) {
			byItem = append(byItem, item+" "+strconv.Itoa(d.scrubbed[item]))
		}
		d.emit("varlatch: the broker replaced Secrets reflected in responses: " + strings.Join(byItem, ", "))
	}
}

// sortedLocale is the map's keys sorted with localeCompare.
func sortedLocale(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, localeCompare)
	return keys
}

// localeCompare is String.prototype.localeCompare for rule and item names
// (ICU's root collation on [A-Za-z0-9_-]), as internal/broker sorts them:
// punctuation before digits before letters, letters without case first,
// then lower case before upper.
func localeCompare(a, b string) int {
	weight := func(c rune) int {
		switch {
		case c >= '0' && c <= '9':
			return 100 + int(c-'0')
		case c >= 'a' && c <= 'z':
			return 200 + int(c-'a')
		case c >= 'A' && c <= 'Z':
			return 200 + int(c-'A')
		}
		return int(c)
	}
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if wa, wb := weight(ra[i]), weight(rb[i]); wa != wb {
			return wa - wb
		}
	}
	if len(ra) != len(rb) {
		return len(ra) - len(rb)
	}
	for i := range ra {
		la, lb := ra[i] >= 'a' && ra[i] <= 'z', rb[i] >= 'a' && rb[i] <= 'z'
		if la != lb {
			if la {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}
