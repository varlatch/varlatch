// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The CLI's use of the API client (slice 5.1c of internal
// docs/design/go-cli.md): main.ts's client(), connectClient(), the
// maintenance notice (maintenance.ts), the expiry warnings (status.ts's
// expiryWarning and envTokenExpiryWarning, main.ts's warnIfExpiring and
// credentialExpiryNotice), and the top-level mapping of API and network
// errors to messages and exit statuses (main.ts's catch).

// clientState is what main.ts keeps per process for its clients.
type clientState struct {
	maintenanceAnnounced bool
	expiryWarned         bool
}

// maintenanceNotice is maintenance.ts's maintenanceNotice (ADR-0036 D6):
// said once per process, on stderr, so stdout stays what scripts parse.
func (r *Run) maintenanceNotice(wait apiclient.MaintenanceWait) {
	if r.clients.maintenanceAnnounced {
		return
	}
	r.clients.maintenanceAnnounced = true
	budget := math.Ceil(float64((wait.RetryIn + wait.Remaining).Milliseconds()) / 1000)
	fmt.Fprintf(r.Stderr, "varlatch: the installation is in maintenance (restore or upgrade); waiting up to %s s…\n", jsjson.Number(budget))
}

// warnExpiryOnce is main.ts's warnExpiryOnce: at most one expiry warning
// per process, whichever path finds it first.
func (r *Run) warnExpiryOnce(warning string) {
	if warning == "" || r.clients.expiryWarned {
		return
	}
	r.clients.expiryWarned = true
	fmt.Fprintln(r.Stderr, jsval.NodeText(warning))
}

// templateTime is `${safeTime(value)}`: "undefined" for a missing time.
func templateTime(value any) string {
	if t, ok := SafeTime(value); ok {
		return t
	}
	return "undefined"
}

// ExpiryWarning is status.ts's expiryWarning: the proportional warning for
// a stored credential, "" when there is nothing to say.
func ExpiryWarning(server string, credential any, now float64) string {
	state := ExpiryState(credential, now)
	server = clientctx.MaskUserinfo(server) // diagnostics never print credential values
	var expiresAt any
	if credential != nil {
		expiresAt, _ = jsval.Get(credential, "expiresAt")
	}
	switch state {
	case "expired":
		return "varlatch: credential for " + server + " expired " + templateTime(expiresAt) + " — run `varlatch login --server " + server + "`"
	case "expiring":
		return "varlatch: credential for " + server + " expires " + templateTime(expiresAt) + " — run `varlatch login --server " + server + "` to renew"
	}
	return ""
}

// EnvTokenExpiryWarning is status.ts's envTokenExpiryWarning: the warning
// for a VARLATCH_TOKEN credential, from the expiry the server named in
// Varlatch-Credential-Expires; "" for a timestamp that does not parse.
func EnvTokenExpiryWarning(server, expiresAt string, now float64) string {
	at, ok := jsval.DateParse(expiresAt)
	if !ok {
		return ""
	}
	server = clientctx.MaskUserinfo(server) // diagnostics never print credential values
	const remedy = "issue a new one (`varlatch credential issue`) and replace VARLATCH_TOKEN"
	// The header's text is the server's: only a timestamp is shown (issue #119).
	shown := templateTime(expiresAt)
	if at <= now {
		return "varlatch: credential for " + server + " (VARLATCH_TOKEN) expired " + shown + "; " + remedy
	}
	return "varlatch: credential for " + server + " (VARLATCH_TOKEN) expires " + shown + "; " + remedy + " before then"
}

func nowMS() float64 { return float64(time.Now().UnixMilli()) }

// warnIfExpiring is main.ts's warnIfExpiring: the stored credential judged
// by its own metadata; never for VARLATCH_TOKEN, which has none.
func (r *Run) warnIfExpiring(server string) error {
	if r.Getenv("VARLATCH_TOKEN") != "" {
		return nil
	}
	credential, err := clientctx.LoadCredential(server, r.Env)
	if err != nil {
		return err
	}
	r.warnExpiryOnce(ExpiryWarning(server, credential, nowMS()))
	return nil
}

// credentialExpiryNotice is main.ts's credentialExpiryNotice (ADR-0054
// Decision 8): the server's Varlatch-Credential-Expires turned into a
// warning, once per process, when the credential came from VARLATCH_TOKEN
// and outside an agent-safe run (whose credential ends with the run).
func (r *Run) credentialExpiryNotice(server, token string) func(string) {
	return func(expiresAt string) {
		if token != r.Getenv("VARLATCH_TOKEN") || clientctx.AgentRunOf(r.Env) != "" {
			return
		}
		r.warnExpiryOnce(EnvTokenExpiryWarning(server, expiresAt, nowMS()))
	}
}

// plainClient is `new VarlatchClient({ onMaintenance: maintenanceNotice,
// server, token, userAgent: cliUserAgent() })`, the client of login,
// logout and status --probe.
func (r *Run) plainClient(server, token string) *apiclient.Client {
	return apiclient.New(apiclient.Options{
		Server:        server,
		Token:         token,
		UserAgent:     r.UserAgent(),
		OnMaintenance: r.maintenanceNotice,
		Env:           r.Env,
	})
}

// LoadToken is packages/context's loadToken: VARLATCH_TOKEN, else the
// stored credential's token ("" for none).
func (r *Run) loadToken(server string) (string, error) {
	if token := r.Getenv("VARLATCH_TOKEN"); token != "" {
		return token, nil
	}
	credential, err := clientctx.LoadCredential(server, r.Env)
	if err != nil {
		return "", err
	}
	token, _ := jsval.Get(credential, "token")
	if credential == nil || !jsjson.Truthy(token) {
		return "", nil // `if (!token)`: refused as not signed in
	}
	return jsjson.String(token), nil
}

// connectClient is main.ts's connectClient: the client of a command that
// talks to its context's server, made when the command first does, so a
// malformed command line exits 64 whether or not a credential is stored.
// No credential is refused (77); inside an agent-safe run the operator's is
// never used. Step-up approvals (onStepUp and --approval's resuming fetch)
// are slice 5.2's: until then a STEP_UP_REQUIRED answer surfaces as its
// error, with the approval's address.
func (r *Run) connectClient(server string) (*apiclient.Client, error) {
	token, err := r.loadToken(server)
	if err != nil {
		return nil, err
	}
	agentRun := clientctx.AgentRunOf(r.Env)
	// The server as these messages show it: diagnostics never print
	// credential values, a URL's user name and password included.
	shown := clientctx.MaskUserinfo(server)
	if token == "" && agentRun != "" {
		return nil, Fail("Not authenticated to "+shown+": this command runs inside agent-safe run "+agentRun+", which gives the "+
			"Agent no Varlatch credential and never uses the operator's.\nFor read access to configuration metadata, "+
			"the operator relaunches the run with --agent-metadata.", ExitDenied)
	}
	if token == "" {
		return nil, Fail("Not authenticated to "+shown+".\nSign in: varlatch login --server "+shown+" (in a browser on this machine), "+
			"varlatch login --server "+shown+" --start (approve in a browser on any device), "+
			"or pipe a credential to varlatch login --server "+shown+" --token-stdin", ExitDenied)
	}
	if err := r.warnIfExpiring(server); err != nil {
		return nil, err
	}
	// A server echoing the bearer back in an error message gets it masked (issue #119).
	r.Secrets.Remember(token)
	return apiclient.New(apiclient.Options{
		Server:              server,
		Token:               token,
		UserAgent:           r.UserAgent(),
		OnMaintenance:       r.maintenanceNotice,
		OnCredentialExpires: r.credentialExpiryNotice(server, token),
		Approval:            r.Approval,
		Env:                 r.Env,
	}), nil
}

// apiErrorLine is safeText.ts's apiErrorLine: the checked code, the masked
// message, and the request id when well formed.
func (r *Run) apiErrorLine(err *apiclient.APIError) string {
	return "Error " + safeCode(err.Code) + ": " + r.Secrets.ServerMessage(err.Message) + r.requestNote(err)
}

// safeCode is safeApiCode for any value a server sent as the code.
func safeCode(code any) string {
	s, _ := code.(string)
	return SafeAPICode(s)
}

// requestNote is safeText.ts's requestNote.
func (r *Run) requestNote(err *apiclient.APIError) string {
	if id, ok := r.Secrets.SafeRequestID(err.RequestID); ok {
		return " (request " + id + ")"
	}
	return ""
}

// mapClientError is main.ts's catch for what the API client throws: a
// pending step-up approval, a passkey verification, maintenance that
// outlasted the wait, any other API error (exitCodes.ts's apiErrorExit),
// and a server that cannot be reached (69). Anything else is returned as
// it is; the TypeScript CLI lets it escape.
func (r *Run) mapClientError(err error) error {
	var api *apiclient.APIError
	if errors.As(err, &api) {
		if pending := apiclient.StepUpApproval(api); pending != nil {
			lines, lineErr := r.approvalLines(pending)
			if lineErr != nil {
				return lineErr
			}
			lines = append(lines, "Error STEP_UP_REQUIRED: "+r.Secrets.ServerMessage(api.Message))
			return Fail(strings.Join(lines, "\n"), ExitDenied)
		}
		if api.CodeIs("PASSKEY_VERIFICATION_REQUIRED") {
			return Fail(strings.Join(r.passkeyVerificationLines(api), "\n"), ExitDenied)
		}
		if api.CodeIs("MAINTENANCE") {
			return Fail("The installation is still in maintenance (restore or upgrade); try again later."+r.requestNote(api), ExitUnavailable)
		}
		code, _ := api.Code.(string) // a code that is not a string matches none of apiErrorExit's
		return Fail(r.apiErrorLine(api), APIErrorExit(api.Status, code))
	}
	if network := apiclient.NetworkFailure(err); network != "" {
		return Fail("Cannot reach the Varlatch server ("+network+"). Check --server, VARLATCH_SERVER, or varlatch.toml, and that the server is running.", ExitUnavailable)
	}
	return err
}

// passkeyVerificationLines is passkeyVerification.ts's
// passkeyVerificationLines (ADR-0054 Decision 7).
func (r *Run) passkeyVerificationLines(err *apiclient.APIError) []string {
	return []string{
		"Error PASSKEY_VERIFICATION_REQUIRED: " + r.Secrets.ServerMessage(err.Message) + r.requestNote(err),
		"To get a CLI credential this Organization accepts:",
		"  varlatch login --server <url>",
		"and approve the sign-in in the browser with a trusted passkey that asks for your PIN, fingerprint or face.",
		"A credential keeps the evidence of the sign-in that issued it, however it is passed later (--token-stdin, VARLATCH_TOKEN);",
		"one issued without a passkey sign-in (for example by admin bootstrap or admin recover --cli-credential) is always refused here.",
	}
}

// jsTemplate is `${value}` for a JSON value read with jsval.Get: String(),
// "undefined" when absent.
func jsTemplate(v any, present bool) string {
	if !present {
		return "undefined"
	}
	return jsjson.String(v)
}

// typeErrorRead is V8's TypeError for reading a property of null or
// undefined.
func typeErrorRead(v any, present bool, key string) error {
	what := "undefined"
	if present && v == nil {
		what = "null"
	}
	return &clientctx.TypeError{Message: fmt.Sprintf("Cannot read properties of %s (reading '%s')", what, key)}
}

// read is base[key], or V8's TypeError when base is null or undefined.
func read(base any, present bool, key string) (any, bool, error) {
	if !present || base == nil || base == apiclient.Undefined {
		return nil, false, typeErrorRead(base, present && base != apiclient.Undefined, key)
	}
	v, ok := jsval.Get(base, key)
	return v, ok, nil
}

// approvalLines is approvals.ts's approvalLines: what the person approves,
// where, and until when. The title, the values a change sets and the
// address are the server's free text: masked as well as escaped (issue
// #119). An approval of another shape throws there, as it does here.
func (r *Run) approvalLines(approval any) ([]string, error) {
	summary, sOK, err := read(approval, true, "summary")
	if err != nil {
		return nil, err
	}
	title, tOK, err := read(summary, sOK, "title")
	if err != nil {
		return nil, err
	}
	lines := []string{"This needs your approval with a trusted passkey: " + r.Secrets.ServerMessage(jsTemplate(title, tOK))}
	changes, _, err := read(summary, sOK, "changes")
	if err != nil {
		return nil, err
	}
	list, err := iterate(changes, "approval.summary.changes")
	if err != nil {
		return nil, err
	}
	for _, change := range list {
		field, fOK, err := read(change, true, "field")
		if err != nil {
			return nil, err
		}
		show := func(key string) string {
			v, ok, _ := read(change, true, key)
			if !ok || v == nil {
				return "not set"
			}
			return r.Secrets.ServerMessage(jsjson.String(v))
		}
		loosens, lOK, _ := read(change, true, "loosens")
		suffix := ""
		if lOK && jsjson.Truthy(loosens) {
			suffix = " (loosens)"
		}
		lines = append(lines, "  "+jsTemplate(field, fOK)+": "+show("from")+" -> "+show("to")+suffix)
	}
	url, uOK, _ := read(approval, true, "url")
	if uOK && jsjson.Truthy(url) {
		lines = append(lines,
			"Open this address in a browser where you are signed in to Varlatch as yourself, check what it says, and approve with a trusted passkey:",
			"  "+jsjson.String(url))
	} else {
		id, idOK, _ := read(approval, true, "id")
		lines = append(lines, "Open the Varlatch dashboard as yourself and approve request "+jsTemplate(id, idOK)+" with a trusted passkey "+
			"(this server has no public URL, so the CLI cannot print its address).")
	}
	expiresAt, _, _ := read(approval, true, "expiresAt")
	lines = append(lines, "It expires at "+templateTime(expiresAt)+". Only you can approve it.")
	for i, line := range lines {
		lines[i] = Printable(line)
	}
	return lines, nil
}

// iterate is `for (const x of v)` over a JSON value: an array's elements, a
// string's characters (code points); anything else is not iterable.
func iterate(v any, expr string) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case string:
		var out []any
		units := jsval.UTF16(x)
		for i := 0; i < len(units); i++ {
			n := 1
			if units[i] >= 0xd800 && units[i] < 0xdc00 && i+1 < len(units) && units[i+1] >= 0xdc00 && units[i+1] < 0xe000 {
				n = 2
			}
			out = append(out, jsval.FromUTF16(units[i:i+n]))
			i += n - 1
		}
		return out, nil
	}
	return nil, &clientctx.TypeError{Message: expr + " is not iterable"}
}
