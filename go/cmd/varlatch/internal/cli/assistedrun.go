// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch run` in assisted mode (ADR-0043 Decision 4, amending ADR-0038
// Decision 10), apps/cli/src/assistedRun.ts: output redaction is the
// default, the redaction set also holds inherited values under known
// Secret names, and a value the matcher cannot register stops the run
// before the command starts.

// assistedRedactionSet is assistedRedactionSet: the Secrets delivered in
// this run, plus the value of each known Secret name the command inherits
// unchanged from this process's environment. Only what the command holds
// counts; empty values carry nothing to mask.
func assistedRedactionSet(delivered []matcher.SecretEntry, child *orderedEnv, parent parentVars, knownSecretNames []string) []matcher.SecretEntry {
	var set []matcher.SecretEntry
	covered := map[string]bool{}
	for _, e := range delivered {
		if v, ok := child.Get(e.Item); e.Value != "" && ok && v == e.Value {
			set = append(set, e)
			covered[e.Item] = true
		}
	}
	seen := map[string]bool{}
	for _, name := range knownSecretNames {
		if seen[name] || covered[name] {
			continue
		}
		seen[name] = true
		inherited, _ := parent.lookup(name)
		if v, ok := child.Get(name); inherited == "" || !ok || v != inherited {
			continue
		}
		set = append(set, matcher.SecretEntry{Item: name, Value: inherited})
		covered[name] = true
	}
	return set
}

// assistedPlan is AssistedPlan.
type assistedPlan struct {
	entries []matcher.SecretEntry
	// allowed are short values the operator allowed to pass unmasked;
	// refused short values nobody allowed (the run must not start);
	// unusedAllowances --allow-unmasked names that are not short Secrets
	// in this run.
	allowed, refused, unusedAllowances []string
}

func planAssistedRedaction(set []matcher.SecretEntry, allowUnmasked []string) assistedPlan {
	var short []string
	for _, e := range set {
		if len(matcher.FormsOf(e.Value)) == 0 && !slices.Contains(short, e.Item) {
			short = append(short, e.Item)
		}
	}
	slices.SortFunc(short, jsval.CompareUTF16)
	plan := assistedPlan{entries: set}
	for _, n := range short {
		if slices.Contains(allowUnmasked, n) {
			plan.allowed = append(plan.allowed, n)
		} else {
			plan.refused = append(plan.refused, n)
		}
	}
	seen := map[string]bool{}
	for _, n := range allowUnmasked {
		if !seen[n] && !slices.Contains(short, n) {
			plan.unusedAllowances = append(plan.unusedAllowances, n)
		}
		seen[n] = true
	}
	slices.SortFunc(plan.unusedAllowances, jsval.CompareUTF16)
	return plan
}

// remedyContext is RemedyContext: the context options a remedy command
// needs (target), the run's own options to repeat (runOptions), and
// whether the run is assisted (false: the human's override outside it).
type remedyContext struct {
	target     string
	runOptions []string
	assisted   bool
}

var remedyServer = regexp.MustCompile(`(?:^|\s)--server (\S+)`)

// unmaskableRefusal is unmaskableRefusal: why an assisted run did not
// start, names and remedies, never a value.
func unmaskableRefusal(items []string, how remedyContext) []string {
	first := items[0]
	several := len(items) > 1
	server := ""
	if m := remedyServer.FindStringSubmatch(how.target); m != nil {
		server = m[1]
	}
	runAs := "varlatch --assisted run"
	if !how.assisted {
		runAs = "varlatch run"
	}
	omit := []string{runAs, how.target}
	omit = append(omit, how.runOptions...)
	for _, n := range items {
		omit = append(omit, "--omit "+n)
	}
	omit = append(omit, "-- <command>")
	retry := append(append([]string{"varlatch run", how.target}, how.runOptions...), "--allow-unmasked "+first+" -- <command>")
	pick := func(one, many string) string {
		if several {
			return many
		}
		return one
	}
	lines := []string{
		"varlatch: " + pick("this Secret is", "these Secrets are") + " shorter than " + strconv.Itoa(matcher.MinLength) + " bytes, so " +
			pick("its value", "their values") + " cannot be masked in the command's output: " + strings.Join(items, ", "),
		pick("  Leave "+first+" out only if the command's code or documentation shows that the command does not use it (no approval needed):",
			"  Leave an item out only if the command's code or documentation shows that the command does not use it (no approval needed), and only those items:"),
		"      " + strings.Join(omit, " "),
		"    Then name " + pick(first, "each item") + " left out in your answer, and say whether the task itself was done: " +
			"getting past this refusal does not show that the command did what was asked.",
		pick("  If you are not sure, or the command uses "+first+", stop and ask the human what to do about "+first+". Approval for one item or action never covers another.",
			"  For each item you are not sure about, or the command uses, stop and ask the human what to do about it. Approval for one item or action never covers another."),
		"  - Only if they approve replacing " + first + " with a new random value (it overwrites the current one):",
		"      varlatch --assisted values set " + first + " " + how.target + " --replace " + first + " --generate hex:32" + pick("", "   (each item needs its own approval)"),
		"    A credential a provider issued is never generated: the human enters it, in their own terminal: varlatch values set " + first + " " + how.target,
	}
	contract := "  - Only if they approve marking " + first + " as not secret (a Contract change, for the whole project): varlatch --assisted agents guide contract"
	if server != "" {
		contract += " (add --server " + server + " to every contract command)"
	}
	return append(lines, contract,
		"  - Showing it unmasked is the human's alone, in their own terminal (assisted mode refuses it; every other Secret stays masked):",
		"      "+strings.Join(retry, " "),
		"Nothing was started.")
}

// assistedGate is assistedGate: false (after naming the items and the
// remedies) when a short value nobody allowed would pass unmasked.
func (r *Run) assistedGate(plan assistedPlan, how remedyContext) bool {
	if n := len(plan.unusedAllowances); n > 0 {
		verb := "are"
		if n == 1 {
			verb = "is"
		}
		r.eprintln("varlatch: --allow-unmasked names " + Printable(strings.Join(plan.unusedAllowances, ", ")) + ", which " + verb +
			" not a Secret shorter than " + strconv.Itoa(matcher.MinLength) + " bytes in this run; ignored")
	}
	if len(plan.refused) == 0 {
		return true
	}
	runOptions := slices.Clone(how.runOptions)
	for _, n := range plan.allowed {
		runOptions = append(runOptions, "--allow-unmasked "+n)
	}
	how.runOptions = runOptions
	// One line each, naming items from the server: escaped (issue #119).
	for _, line := range unmaskableRefusal(plan.refused, how) {
		r.eprintln(Printable(line))
	}
	return false
}

// knownSecretNames is knownSecretNames: every name a default run knows as
// a Secret, stored as one in the Environment (withheld ones included) or
// sensitive in the active Contract. Without contract.read only the stored
// names are known, and the run says so.
func (r *Run) knownSecretNames(ctx *clientctx.Context, c *apiclient.Client, effective any) ([]string, error) {
	names := map[string]bool{}
	for _, item := range listOf(effective, "items") {
		if name, ok := stringField(item, "name"); ok && jsjson.Truthy(fieldOf(item, "sensitive")) {
			names[name] = true
		}
	}
	manifest := fieldOf(effective, "manifest")
	// A server that reports its manifest says whether a Contract is active.
	if !jsjson.Truthy(manifest) || jsjson.Truthy(fieldOf(manifest, "contract")) {
		revision, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
		var apiErr *apiclient.APIError
		switch {
		case err == nil:
			contractDoc, _ := jsval.Get(revision, "contract")
			for _, item := range listOf(contractDoc, "items") {
				if name, ok := stringField(item, "name"); ok && jsjson.Truthy(fieldOf(item, "sensitive")) {
					names[name] = true
				}
			}
		case errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 403):
			if apiErr.Status == 403 {
				r.eprintln("varlatch: cannot read the Contract (403); inherited values are masked only under names stored as Secrets")
			}
		default:
			return nil, err
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	slices.SortFunc(out, jsval.CompareUTF16)
	return out, nil
}

// assistedRunNotices is main.ts's assistedRunNotices: what an assisted run
// tells a coding agent before the command starts, facts only.
func assistedRunNotices(ctx *clientctx.Context, effective any, cmd, where, cwd string) []string {
	var notices []string
	if len(listOf(effective, "items")) == 0 {
		notices = append(notices, "varlatch: no values are stored in Varlatch for "+environmentOf(ctx)+"; "+cmd+" gets only the variables it inherits.")
	}
	dirs := []string{cwd}
	if ctx.RepoRoot != "" && ctx.RepoRoot != cwd {
		dirs = append(dirs, ctx.RepoRoot)
	}
	for _, dir := range dirs {
		file := filepath.Join(dir, ".env")
		if _, err := os.Stat(file); err != nil {
			continue
		}
		shown, err := filepath.Rel(cwd, file)
		if err != nil || shown == "" {
			shown = ".env"
		}
		notices = append(notices, "varlatch: "+shown+" exists and is not read by Varlatch, which cannot tell whether its values are stored already (or older copies). "+
			"To compare names, without values: varlatch --assisted import "+shown+" "+where+" --dry-run --json")
	}
	return notices
}

// fieldOf is v[key] (nil when absent).
func fieldOf(v any, key string) any {
	f, _ := jsval.Get(v, key)
	return f
}

// stringField is v[key] when it is a string.
func stringField(v any, key string) (string, bool) {
	s, ok := fieldOf(v, key).(string)
	return s, ok
}

// listOf is v[key] when it is an array, else none (`?? []`).
func listOf(v any, key string) []any {
	l, _ := fieldOf(v, key).([]any)
	return l
}
