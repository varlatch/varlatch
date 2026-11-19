// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"sync"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/mcp"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch mcp` (ADR-0043 Decision 9; packages/mcp-server/src/run.ts):
// a Model Context Protocol server over stdio for MCP hosts without a
// shell (internal/mcp), started as runMcpServer starts it:
//
//   - there is no disclosure tool, and --allow-disclose (or
//     VARLATCH_MCP_ALLOW_DISCLOSE) is refused rather than ignored;
//   - writes need --allow-writes, and a Secret's value is never written;
//   - inside an agent-safe run the credential is the agent-run one or none,
//     never the operator's stored credential (ADR-0043 Decision 5), and
//     writes are refused, since that credential is read-only.

// mcpUsage is run.ts's MCP_USAGE.
const mcpUsage = `Usage: varlatch mcp [--server <url>] [--org <slug>] [--project <slug>] [--environment <name>] [--allow-writes]

Runs a Model Context Protocol server over stdio for MCP hosts without a shell.
Defaults for org/project/environment come from the repository context of the
working directory (varlatch.toml, .varlatch/local.json); flags override.
Authentication uses VARLATCH_TOKEN or the stored credential for the server;
inside an agent-safe run, only the run's agent-run credential.

Read tools only by default. --allow-writes (or VARLATCH_MCP_ALLOW_WRITES=1)
adds varlatch_set_value, which refuses a Secret's value, and
varlatch_delete_value. No tool returns a Secret's value.`

const discloseRefusal = "secret disclosure through MCP has been removed: no MCP host can keep a tool result out of the model's " +
	"context. Remove --allow-disclose (and VARLATCH_MCP_ALLOW_DISCLOSE). An agent uses a Secret through " +
	"varlatch run, or through the Broker with varlatch request inside an agent-safe run."

// mcpArgs is run.ts's McpArgs; a flag not given is absent.
type mcpArgs struct {
	server, organization, project, environment *string
	allowWrites, help                          bool
}

// mcpFail is McpStartError: printed as "varlatch mcp: <message>".
func mcpFail(message string, code int) error {
	return Fail("varlatch mcp: "+message, code)
}

// parseMcpArgs is run.ts's parseMcpArgs: every argument is read before
// --help is acted on, so a wrong one is refused even after it.
func (r *Run) parseMcpArgs(argv []string) (*mcpArgs, error) {
	if v, ok := r.Env.LookupEnv("VARLATCH_MCP_ALLOW_DISCLOSE"); ok && v != "" && v != "0" {
		return nil, mcpFail(discloseRefusal, ExitUsage)
	}
	allowWrites, _ := r.Env.LookupEnv("VARLATCH_MCP_ALLOW_WRITES")
	args := &mcpArgs{allowWrites: allowWrites == "1"}
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		next := func() (*string, error) {
			i++
			if i >= len(argv) {
				return nil, &exitError{message: "varlatch mcp: " + arg + " needs a value", usage: "\n" + mcpUsage, code: ExitUsage}
			}
			v := argv[i]
			return &v, nil
		}
		var err error
		switch arg {
		case "--server":
			args.server, err = next()
		case "--org", "--organization":
			args.organization, err = next()
		case "--project":
			args.project, err = next()
		case "--environment", "--env", "-e":
			args.environment, err = next()
		case "--allow-writes":
			args.allowWrites = true
		case "--allow-disclose":
			return nil, mcpFail(discloseRefusal, ExitUsage)
		case "--help", "-h":
			args.help = true
		default:
			return nil, &exitError{message: "varlatch mcp: unknown option " + arg, usage: "\n" + mcpUsage, code: ExitUsage}
		}
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

func flagValue(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// mcpCommand is `varlatch mcp`: it serves until the host closes standard
// input, then exits 0.
func mcpCommand(r *Run) error {
	args, err := r.parseMcpArgs(r.Args)
	if err != nil {
		return err
	}
	if args.help {
		return r.out(mcpUsage + "\n")
	}
	opts, err := r.prepareMcp(args)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	mcp.New(opts).Serve(context.Background(), r.Stdin, func(line string) {
		mu.Lock()
		defer mu.Unlock()
		_ = r.out(line)
	})
	return nil
}

// prepareMcp is run.ts's prepareMcpServer: the defaults, and the client with
// its credential, identified by the MCP server's own User-Agent.
func (r *Run) prepareMcp(args *mcpArgs) (mcp.Options, error) {
	agentRun := clientctx.AgentRunOf(r.Env)
	if agentRun != "" && args.allowWrites {
		return mcp.Options{}, mcpFail("this runs inside agent-safe run "+agentRun+", whose only credential is read-only; --allow-writes does not apply here", ExitUsage)
	}
	// `args.server ?? env.VARLATCH_SERVER`: an empty variable is a server
	// of "", which is none.
	var server any = absentServer
	if args.server != nil {
		server = *args.server
	} else if v, ok := r.Env.LookupEnv("VARLATCH_SERVER"); ok {
		server = v
	}
	defaults := mcp.Defaults{}
	set := func(name string, v any) {
		if v != absentServer {
			defaults = append(defaults, jsjson.Member{Key: name, Value: v})
		}
	}
	or := func(flag *string, fallback any) any {
		if flag != nil {
			return *flag
		}
		return fallback
	}
	cwd, err := Cwd()
	if err != nil {
		return mcp.Options{}, err
	}
	ctx, err := clientctx.ResolveContext(clientctx.ResolveOptions{Cwd: cwd, Environment: flagValue(args.environment), Server: flagValue(args.server)}, r.Env)
	var contextErr *clientctx.ContextError
	switch {
	case err == nil:
		if server == absentServer || server == nil {
			server = ctx.Server
		}
		set("organization", or(args.organization, ctx.Organization))
		set("project", or(args.project, ctx.Project))
		set("environment", or(args.environment, ctx.Environment))
	case errors.As(err, &contextErr):
		// Not inside a repository: flags and the environment only.
		set("organization", or(args.organization, absentServer))
		set("project", or(args.project, absentServer))
		set("environment", or(args.environment, absentServer))
	default:
		return mcp.Options{}, err
	}
	if server == absentServer || !jsjson.Truthy(server) {
		return mcp.Options{}, mcpFail("no server configured; pass --server, set VARLATCH_SERVER, or run inside a varlatch repository", ExitUsage)
	}
	url, err := serverString(server)
	if err != nil {
		return mcp.Options{}, err
	}
	// Inside an agent-safe run loadToken never reads the operator's default
	// store, whether or not VARLATCH_CONFIG_DIR is set (ADR-0043 Decision 5).
	token, err := r.loadToken(url)
	if err != nil {
		return mcp.Options{}, err
	}
	shown := clientctx.DisplayServer(url)
	if token == "" && agentRun != "" {
		return mcp.Options{}, mcpFail("not authenticated to "+shown+": this runs inside agent-safe run "+agentRun+", which gives the Agent no "+
			"Varlatch credential and never uses the operator's ("+clientctx.AgentRunEnv+" is set). For read access to "+
			"configuration metadata, the operator relaunches the run with --agent-metadata.", ExitDenied)
	}
	if token == "" {
		return mcp.Options{}, mcpFail("not authenticated to "+shown+"; run `varlatch login` or set VARLATCH_TOKEN", ExitDenied)
	}
	// A server echoing the bearer back gets it masked by the fail-safe, in
	// a tool's result on stdout as in a diagnostic, whatever its shape.
	r.holdCredential(token)
	client := apiclient.New(apiclient.Options{
		Server:    url,
		Token:     token,
		UserAgent: FormatMCPUserAgent(buildinfo.Version, NodePlatform(), NodeArch()),
		Env:       r.Env,
	})
	return mcp.Options{Client: client, Defaults: defaults, AllowWrites: args.allowWrites, Version: buildinfo.Version}, nil
}

// absentServer stands for a value not given (JavaScript's undefined).
var absentServer any = struct{ absent bool }{true}
