// SPDX-License-Identifier: Apache-2.0

package cli

// command is one entry of the command table: every command the TypeScript
// CLI dispatches (apps/cli/src/main.ts), with the slice of internal
// docs/design/go-cli.md that builds it in Go ("5.1e"), "step 6" for a host
// command of a Go installation, or "never" for adopt, which manages a
// Compose installation (decision 9). A command not built yet answers with a
// usage error that says so. The same slices are in
// testdata/cli-inventory.json, and TestInventoryCoverage holds the two
// equal.
type command struct {
	name  string
	slice string
	run   func(*Run) error
	// partial runs the forms of a command not built yet that an earlier
	// slice builds (`scan --find-files`, slice 5.4e, of `scan`, 5.4d): it
	// says whether the command line is one of them.
	partial func(*Run) (handled bool, err error)
}

// commands is the table, in the TypeScript CLI's dispatch order.
var commands = []command{
	{name: "login", slice: "5.1e", run: loginCommand},
	{name: "init", slice: "5.1d", run: initCommand},
	{name: "agents", slice: "5.1d", run: agentsCommand},
	{name: "logout", slice: "5.1e", run: logoutCommand},
	{name: "status", slice: "5.1b", run: statusCommand},
	{name: "whoami", slice: "5.1e", run: whoamiCommand},
	{name: "server", slice: "5.1b", run: serverCommand},
	{name: "context", slice: "5.1b", run: contextCommand},
	{name: "env", slice: "5.1e", run: envCommand},
	{name: "run", slice: "5.4b", run: runCommand},
	{name: "validate", slice: "5.3a", run: validateCommand},
	{name: "scan", slice: "5.4d", run: scanCommand},
	{name: "values", slice: "5.3a", run: valuesCommand},
	{name: "mcp", slice: "5.6b", run: mcpCommand},
	{name: "request", slice: "5.5b", run: requestCommand},
	{name: "import", slice: "5.3a", run: importCommand},
	{name: "sync", slice: "5.8b", run: syncCommand},
	{name: "contract", slice: "5.3b", run: contractCommand},
	{name: "types", slice: "5.3c", run: typesCommand},
	{name: "invite", slice: "5.7a", run: inviteCommand},
	{name: "tailnet", slice: "5.7a", run: tailnetCommand},
	{name: "audit", slice: "5.7a", run: auditCommand},
	{name: "org", slice: "5.7a", run: orgCommand},
	{name: "project", slice: "5.7a", run: projectCommand},
	{name: "env-create", slice: "5.7a", run: envCreateCommand},
	{name: "env-delete", slice: "5.7a", run: envDeleteCommand},
	{name: "identity", slice: "5.7a", run: identityCommand},
	{name: "member", slice: "5.7a", run: memberCommand},
	{name: "credential", slice: "5.7a", run: credentialCommand},
	{name: "audit-export", slice: "5.7c", run: auditExportCommand},
	{name: "security", slice: "5.7b", run: securityCommand},
	{name: "admin", slice: "step 6", partial: adminCommand},
	{name: "setup", slice: "step 6"},
	{name: "move", slice: "step 6", partial: movePartial},
	{name: "adopt", slice: "never"},
	{name: "doctor", slice: "step 6"},
	{name: "version", slice: "5.1a", run: versionCommand},
	{name: "--version", slice: "5.1a", run: versionCommand},
	{name: "self-update", slice: "step 6", partial: selfUpdateCommand},
	{name: "upgrade", slice: "step 6"},
}

func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// notBuilt is the usage error of a command the Go CLI does not run (yet).
func notBuilt(c *command) error {
	switch c.slice {
	case "never":
		return UsageError("varlatch " + c.name + ": the Go CLI does not manage a Compose installation; use the TypeScript CLI there until it is migrated")
	case "step 6":
		return UsageError("varlatch " + c.name + ": not in this build of the Go CLI yet (ADR-0059 step 6); use the TypeScript CLI for it until then")
	}
	return UsageError("varlatch " + c.name + ": not in this build of the Go CLI yet (slice " + c.slice + "); use the TypeScript CLI for it until then")
}

// Built is whether the Go CLI runs the command now.
func Built(name string) bool {
	c := lookup(name)
	return c != nil && c.run != nil
}

// CommandSlice is the slice that builds the command ("5.1e", "step 6",
// "never"), "" for a command the TypeScript CLI does not have.
func CommandSlice(name string) string {
	if c := lookup(name); c != nil {
		return c.slice
	}
	return ""
}

// CommandNames lists the table's commands, in order.
func CommandNames() []string {
	names := make([]string, len(commands))
	for i, c := range commands {
		names[i] = c.name
	}
	return names
}
