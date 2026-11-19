// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
)

// The inventory (testdata/cli-inventory.json; internal docs/design/go-cli.md,
// decision 16) lists every command, option and environment variable of the
// TypeScript CLI, held to its source by apps/cli/test/cli-inventory.test.ts.
// Here: the command table agrees with it, and everything of a built slice
// is covered by a recorded case or a vector. Missing coverage fails.

type inventory struct {
	Built    []string `json:"built"`
	Commands map[string]struct {
		Slice string `json:"slice"`
	} `json:"commands"`
	Options map[string]struct {
		Of       string   `json:"of"`
		Commands []string `json:"commands"`
		Slice    string   `json:"slice"`
		// CommandSlices: the commands for which the option belongs to a
		// later slice than the command's (--confirm of org and project is
		// their delete subcommands', 5.7c).
		CommandSlices map[string]string `json:"commandSlices"`
	} `json:"options"`
	Environment map[string]struct {
		Slice     string   `json:"slice"`
		CoveredBy []string `json:"coveredBy"`
	} `json:"environment"`
	Precedence []struct {
		Name  string   `json:"name"`
		Slice string   `json:"slice"`
		Cases []string `json:"cases"`
	} `json:"precedence"`
	Exits []struct {
		Command string `json:"command"`
		Status  any    `json:"status"`
		Slice   string `json:"slice"`
	} `json:"exits"`
}

func loadInventory(t *testing.T) *inventory {
	t.Helper()
	data, err := os.ReadFile("testdata/cli-inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	return &inv
}

// recorded is one transcript case, with the command it runs after the
// global options.
type recorded struct {
	ref     string
	command string
	args    []string
	env     map[string]string
	status  int
}

func loadCases(t *testing.T) []recorded {
	t.Helper()
	files, err := filepath.Glob("testdata/transcripts/*.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []recorded
	for _, path := range files {
		f, err := transcript.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			taken, _ := cli.TakeAssistedOption(c.Args)
			rest, _, _ := cli.TakeApprovalOption(taken)
			command := ""
			if len(rest) > 0 {
				command = rest[0]
			}
			out = append(out, recorded{ref: "transcripts/" + filepath.Base(path) + "#" + c.ID, command: command, args: c.Args, env: c.Env, status: c.Expect.Status})
		}
	}
	return out
}

// refExists is whether a coverage reference names a recorded case or a
// vector section that exists.
func refExists(t *testing.T, cases []recorded, ref string) bool {
	if strings.HasPrefix(ref, "transcripts/") {
		return slices.ContainsFunc(cases, func(c recorded) bool { return c.ref == ref })
	}
	file, section, ok := strings.Cut(ref, "#")
	if !ok || !strings.HasPrefix(file, "vectors/") {
		return false
	}
	data, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	return len(doc[section]) > 2
}

func TestInventoryCoverage(t *testing.T) {
	inv := loadInventory(t)
	cases := loadCases(t)
	built := func(slice string) bool { return slices.Contains(inv.Built, slice) }

	// The command table and the inventory name the same commands and slices,
	// and a command runs exactly when its slice is built.
	names := cli.CommandNames()
	invNames := make([]string, 0, len(inv.Commands))
	for name := range inv.Commands {
		invNames = append(invNames, name)
	}
	sort.Strings(invNames)
	tableNames := slices.Sorted(slices.Values(names))
	if !slices.Equal(tableNames, invNames) {
		t.Fatalf("command table %q, inventory %q", tableNames, invNames)
	}
	for _, name := range names {
		slice := inv.Commands[name].Slice
		if got := cli.CommandSlice(name); got != slice {
			t.Errorf("%s: the table says %q, the inventory %q", name, got, slice)
		}
		if cli.Built(name) != built(slice) {
			t.Errorf("%s: built in Go %v, but slice %s is built %v", name, cli.Built(name), slice, built(slice))
		}
	}

	// A built command has a case; so does each of its options, and each
	// global option of a built slice.
	for _, name := range names {
		if cli.Built(name) && !slices.ContainsFunc(cases, func(c recorded) bool { return c.command == name }) {
			t.Errorf("command %s is built but no recorded case runs it", name)
		}
	}
	for option, o := range inv.Options {
		if o.Of == "varlatch" && o.Slice != "" && !built(o.Slice) {
			continue // an option a later slice builds, of a command built already (status --probe)
		}
		if o.Of != "varlatch" {
			// An option of a program whose command line the guardrail hook
			// reads: a hook vector's command uses it.
			if o.Slice != "" && built(o.Slice) && !(o.Of == "another program" && hookCommandsUse(t, option)) {
				t.Errorf("option %s (%s) of built slice %s: no vector uses it", option, o.Of, o.Slice)
			}
			continue
		}
		for _, command := range o.Commands {
			global := command == "*"
			if !global && !cli.Built(command) || global && !built("5.1a") {
				continue
			}
			if later, ok := o.CommandSlices[command]; ok && !built(later) {
				continue
			}
			used := slices.ContainsFunc(cases, func(c recorded) bool {
				return (global || c.command == command) && slices.Contains(c.args, option)
			})
			if !used {
				t.Errorf("option %s of %s: no recorded case uses it", option, command)
			}
		}
	}
	for name, e := range inv.Environment {
		if !built(e.Slice) {
			continue
		}
		covered := slices.ContainsFunc(cases, func(c recorded) bool { _, ok := c.env[name]; return ok })
		for _, ref := range e.CoveredBy {
			if !refExists(t, cases, ref) {
				t.Errorf("environment %s: %s does not exist", name, ref)
			}
			covered = true
		}
		if !covered {
			t.Errorf("environment %s of built slice %s: no recorded case sets it and no vector covers it", name, e.Slice)
		}
	}
	for _, p := range inv.Precedence {
		if !built(p.Slice) {
			continue
		}
		if len(p.Cases) == 0 {
			t.Errorf("precedence %s of built slice %s: no cases", p.Name, p.Slice)
		}
		for _, ref := range p.Cases {
			if !refExists(t, cases, ref) {
				t.Errorf("precedence %s: %s does not exist", p.Name, ref)
			}
		}
	}
	for _, e := range inv.Exits {
		status, numeric := e.Status.(float64)
		if !built(e.Slice) || !numeric {
			continue
		}
		if !slices.ContainsFunc(cases, func(c recorded) bool {
			return (e.Command == "*" || c.command == e.Command) && c.status == int(status)
		}) {
			t.Errorf("exit %v of %s (slice %s): no recorded case ends with it", e.Status, e.Command, e.Slice)
		}
	}
}

// TestClientLacksNotStale: scripts/conformance/client-go.json lists the CLI
// features the Go CLI does not have yet, so conformance runs report their
// checks client-lacks. An entry whose slice is built is stale: the pull
// request that builds a slice removes its features' entries. (The runner
// also fails a run where a lacking check passes.)
func TestClientLacksNotStale(t *testing.T) {
	inv := loadInventory(t)
	data, err := os.ReadFile("../../../scripts/conformance/client-go.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		LacksFeatures map[string]struct {
			Slice string `json:"slice"`
		} `json:"lacksFeatures"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for feature, entry := range file.LacksFeatures {
		if slices.Contains(inv.Built, entry.Slice) {
			t.Errorf("client-go.json says the Go CLI lacks %s, but slice %s is built: remove the entry", feature, entry.Slice)
		}
	}
}

// hookCommands are the shell commands of the hook vectors
// (testdata/vectors/hook.json), read once.
var hookCommands []string

// hookCommandsUse is whether a hook vector's command has option as one of
// its words.
func hookCommandsUse(t *testing.T, option string) bool {
	t.Helper()
	if hookCommands == nil {
		data, err := os.ReadFile("testdata/vectors/hook.json")
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			Cases []struct {
				Stdin string `json:"stdin"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		for _, c := range file.Cases {
			var event struct {
				ToolInput struct {
					Command any `json:"command"`
				} `json:"tool_input"`
			}
			if json.Unmarshal([]byte(c.Stdin), &event) == nil {
				if s, ok := event.ToolInput.Command.(string); ok {
					hookCommands = append(hookCommands, s)
				}
			}
		}
	}
	return slices.ContainsFunc(hookCommands, func(command string) bool {
		return slices.Contains(strings.Fields(command), option)
	})
}
