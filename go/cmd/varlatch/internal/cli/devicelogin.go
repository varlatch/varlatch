// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Device-authorization sign-in (ADR-0043 Decision 2; the design notes
// "Device-authorization sign-in"), ported from deviceLogin.ts at v0.22.0:
// `login --start` requests a pending sign-in, keeps its device code in
// pending-sign-ins.json (clientctx), prints the verification address and
// the user code, and exits at once; the person approves in a browser on
// any device; `login --wait` polls within a deadline, collects the
// credential once, verifies it, and stores it as every login does. The
// device code is a bearer: it never appears in output, argv or logs
// (holdValue), and travels only over HTTPS (or to loopback).

const (
	waitDefaultSeconds = 60
	waitMaxSeconds     = 600
	// startTimeout bounds --start's single request: an agent's shell must
	// not hang on it.
	startTimeout = 30 * time.Second
)

// deviceIO is deviceLogin.ts's DeviceLoginIO.
type deviceIO struct {
	json     bool   // one JSON document on stdout
	cli      string // "varlatch" or "varlatch --assisted", for suggested commands
	assisted bool
	// resolve is the name resolution for the localhost check.
	resolve func(host string) ([]string, error)
}

func defaultResolve(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.IP.String()
	}
	return out, nil
}

var loopbackV4 = regexp.MustCompile(`^127(?:\.\d{1,3}){3}$`)

func isLoopbackAddress(address string) bool {
	return loopbackV4.MatchString(address) || address == "::1"
}

// hostname is URL.hostname: the host without its port (an IPv6 address
// keeps its brackets).
func hostname(host string) string {
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			return host[:i+1]
		}
		return host
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

// transportRefusal is why device sign-in must not run against server, or
// "": only https://, except http:// to a loopback address (127.0.0.1, ::1,
// or localhost resolving only to loopback) in local development. Checked
// before any request.
func (io deviceIO) transportRefusal(server string) string {
	u, ok := whatwg.ParseURL(server)
	if !ok {
		return shownServer(server) + " is not a URL; give the server's address, such as https://varlatch.example.com"
	}
	if u.Protocol == "https:" {
		return ""
	}
	const rule = "device sign-in sends a code that collects a credential, and receives that credential, so it runs only over " +
		"https:// (or http:// to 127.0.0.1, ::1, or localhost in local development)"
	if u.Protocol != "http:" {
		return shownServer(server) + ": " + rule
	}
	name := hostname(u.Host)
	if name == "127.0.0.1" || name == "[::1]" {
		return ""
	}
	if name == "localhost" {
		resolve := io.resolve
		if resolve == nil {
			resolve = defaultResolve
		}
		addresses, err := resolve("localhost")
		if err == nil && len(addresses) > 0 && allLoopback(addresses) {
			return ""
		}
		return shownServer(server) + ": localhost does not resolve only to loopback addresses here; " + rule
	}
	path, _ := u.RequestTarget()
	return shownServer(server) + ": " + rule + ". Use " + shownServer("https://"+u.Host+strings.TrimRight(path, "/"))
}

func allLoopback(addresses []string) bool {
	for _, a := range addresses {
		if !isLoopbackAddress(a) {
			return false
		}
	}
	return true
}

var userCodeShape = regexp.MustCompile(`^[A-Z]{4}-[A-Z]{4}$`)

// deviceClient is a client for device sign-in: no maintenance retry, since
// a maintenance window is a temporary failure here, not something to wait
// out past the deadline.
func (r *Run) deviceClient(server, token string) *apiclient.Client {
	none := time.Duration(0)
	return apiclient.New(apiclient.Options{Server: server, Token: token, UserAgent: r.UserAgent(), MaintenanceRetry: &none, Env: r.Env})
}

// startDeviceLogin is `varlatch login --server <url> --start [--ttl <s>]`.
func (r *Run) startDeviceLogin(server string, ttl *float64, io deviceIO) error {
	if refusal := io.transportRefusal(server); refusal != "" {
		_ = r.warn("varlatch login: " + refusal + ". Nothing was sent.")
		return ExitWith(ExitUsage)
	}
	input := jsjson.Object{}
	if ttl != nil {
		input = jsjson.Object{{Key: "ttlSeconds", Value: *ttl}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	started, err := r.deviceClient(server, "").StartDeviceSignIn(ctx, input)
	cancel()
	if err != nil {
		return r.startFailure(err, server, io)
	}
	field := func(key string) (any, bool, error) { return read(started, started != apiclient.Undefined, key) }
	verificationURI, verificationOK, err := field("verificationUri")
	if err != nil {
		return err
	}
	deviceCode, _, err := field("deviceCode")
	if err != nil {
		return err
	}
	userCode, userCodeOK, err := field("userCode")
	if err != nil {
		return err
	}
	verification := "not a URL"
	if s, isString := verificationURI.(string); isString {
		verification = io.transportRefusal(s)
	}
	code, codeIsString := deviceCode.(string)
	if !codeIsString || code == "" || !userCodeShape.MatchString(jsTemplate(userCode, userCodeOK)) || verification != "" {
		_ = r.warn("varlatch login: the server's answer is not a device sign-in this CLI can show (the verification address must be HTTPS). Nothing was stored.")
		return ExitWith(ExitFailure)
	}
	// The device code is a bearer: a server echoing it back gets it masked
	// (issue #119), and no output or diagnostic shows it.
	r.holdSecret(code)
	expiresIn, expiresInOK, err := field("expiresIn")
	if err != nil {
		return err
	}
	interval, intervalOK, err := field("interval")
	if err != nil {
		return err
	}
	now := time.Now()
	expiresAtMS := float64(now.UnixMilli()) + apiclient.Number(jsUndefinedOr(expiresIn, expiresInOK))*1000
	if math.IsNaN(expiresAtMS) || math.IsInf(expiresAtMS, 0) {
		return errors.New("Invalid time value") // new Date(NaN).toISOString() throws a RangeError
	}
	expiresAt := isoString(time.UnixMilli(int64(expiresAtMS)).UTC())
	entry := jsjson.Object{
		{Key: "server", Value: server},
		{Key: "deviceCode", Value: code},
		{Key: "userCode", Value: userCode},
		{Key: "verificationUri", Value: verificationURI},
		{Key: "expiresAt", Value: expiresAt},
	}
	if intervalOK && interval != apiclient.Undefined {
		entry = append(entry, jsjson.Member{Key: "interval", Value: interval})
	}
	entry = append(entry, jsjson.Member{Key: "startedAt", Value: isoString(now.UTC())})
	_ = verificationOK
	replaced, err := clientctx.SavePendingSignIn(entry, r.Env)
	if err != nil {
		return contextError(err)
	}
	if replaced != nil {
		if at, ok := jsval.DateParse(jsjson.String(replaced.Value("expiresAt"))); ok && at > float64(time.Now().UnixMilli()) {
			code, codeOK := replaced.Get("userCode")
			_ = r.warn("varlatch login: the sign-in started earlier from this CLI for " + shownServer(server) + " (code " + jsTemplate(code, codeOK) +
				") no longer completes here; it expires unused on the server.")
		}
	}
	wait := io.cli + " login --server " + commandServer(server) + " --wait"
	if io.json {
		return r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "verificationUri", Value: verificationURI}, {Key: "userCode", Value: userCode}, {Key: "expiresAt", Value: expiresAt}})
	}
	lines := []string{"Open this address in a browser, on any device, sign in with your passkey, and enter the code:"}
	if io.assisted {
		lines[0] = "Give the person this address and code. They open the address in a browser, on any device, sign in with their passkey, and enter the code:"
	}
	lines = append(lines, "", "  "+Printable(shownValue(verificationURI.(string))), "", "  "+jsTemplate(userCode, true), "",
		"The code expires at "+shownExpiry(expiresAt, float64(time.Now().UnixMilli()))+".")
	if io.assisted {
		lines = append(lines, "Then stop and wait until they say they approved it; only then run:\n  "+wait)
	} else {
		lines = append(lines, "After approving, run:\n  "+wait)
	}
	for _, line := range lines {
		if err := r.println(line); err != nil {
			return err
		}
	}
	return nil
}

// jsUndefinedOr is v, or Undefined when absent.
func jsUndefinedOr(v any, present bool) any {
	if !present {
		return apiclient.Undefined
	}
	return v
}

// shownExpiry is `<time>, in <n> minute(s)`.
func shownExpiry(expiresAt string, now float64) string {
	at, _ := jsval.DateParse(expiresAt)
	minutes := max(0, math.Floor((at-now)/60_000+0.5))
	unit := "minutes"
	if minutes == 1 {
		unit = "minute"
	}
	return expiresAt + ", in " + strconv.FormatFloat(minutes, 'f', -1, 64) + " " + unit
}

func (r *Run) startFailure(err error, server string, io deviceIO) error {
	var redirect *apiclient.DeviceSignInRedirectError
	if errors.As(err, &redirect) {
		_ = r.warn(r.redirectMessage(redirect, server, "Nothing was stored."))
		return ExitWith(ExitFailure)
	}
	var api *apiclient.APIError
	if errors.As(err, &api) {
		if api.Status == 404 {
			return r.unsupported(server)
		}
		if api.CodeIs("MAINTENANCE") {
			_ = r.warn("varlatch login: " + shownServer(server) + " is in maintenance; try again in a moment.")
			return ExitWith(ExitUnavailable)
		}
		_ = r.warn("varlatch login: the server refused to start a sign-in (" + safeCode(api.Code) + "): " + r.Secrets.ServerMessage(api.Message))
		if api.Status >= 500 {
			return ExitWith(ExitUnavailable)
		}
		return ExitWith(ExitFailure)
	}
	if apiclient.IsAbort(err) {
		_ = r.warn("varlatch login: " + shownServer(server) + " did not answer within " + strconv.Itoa(int(startTimeout/time.Second)) + " seconds. Nothing was stored.")
		return ExitWith(ExitUnavailable)
	}
	if network := apiclient.NetworkFailure(err); network != "" {
		_ = r.warn("varlatch login: cannot reach " + shownServer(server) + " (" + network + "). Nothing was stored.")
		return ExitWith(ExitUnavailable)
	}
	return err
}

func (r *Run) unsupported(server string) error {
	_ = r.warn("varlatch login: " + shownServer(server) + " does not offer device sign-in (capability auth.device: Varlatch 0.14.0 or later, " +
		"with an HTTPS public address). Sign in in a browser on this machine instead: " + loginCommandFor(server, ""))
	return ExitWith(ExitUnavailable)
}

func (r *Run) redirectMessage(err *apiclient.DeviceSignInRedirectError, server, kept string) string {
	to := ""
	if err.HasLocation && err.Location != "" {
		to = " to " + r.Secrets.ServerMessage(shownValue(err.Location))
	}
	return "varlatch login: " + shownServer(server) + " answered " + strconv.Itoa(err.Status) + " with a redirect" + to + ". " +
		"Device sign-in follows no redirect, so its code was not sent there. " + kept + " " +
		"Check --server: give the address the server answers at."
}

// waitDeviceLogin is `varlatch login --server <url> --wait [--timeout <s>]`.
func (r *Run) waitDeviceLogin(server string, timeoutSeconds int, io deviceIO) error {
	if refusal := io.transportRefusal(server); refusal != "" {
		_ = r.warn("varlatch login: " + refusal + ". Nothing was sent.")
		return ExitWith(ExitUsage)
	}
	entry, err := clientctx.LoadPendingSignIn(server, r.Env)
	if err != nil {
		return contextError(err)
	}
	if entry == nil {
		_ = r.warn("varlatch login: no sign-in was started from this CLI for " + shownServer(server) + ". Start one: " + io.cli + " login --server " + commandServer(server) + " --start")
		return ExitWith(ExitUsage)
	}
	deviceCode := jsTemplate(entry.Get("deviceCode"))
	r.holdSecret(deviceCode)
	nowMS := func() float64 { return float64(time.Now().UnixMilli()) }
	timeoutMS := float64(timeoutSeconds) * 1000
	deadline := nowMS() + timeoutMS
	// Polls stop early enough to leave time to verify and store a collected
	// credential: the credential is collected once, so it must not be lost
	// to the deadline after collection. Everything still ends by the deadline.
	pollDeadline := deadline - min(5_000, timeoutMS/4)
	startNext := io.cli + " login --server " + commandServer(server) + " --start"
	interval := apiclient.Number(jsUndefinedOr(entry.Get("interval")))
	seenPending := false
	lastPolledAt := math.NaN() // null
	nextPollAt := nowMS()
	if last, ok := entry.Get("lastPolledAt"); ok && jsjson.Truthy(last) {
		at, _ := jsval.DateParse(jsjson.String(last))
		nextPollAt = at + interval*1000
	}
	userCode := jsTemplate(entry.Get("userCode"))
	if !io.json {
		_ = r.warn("Waiting up to " + strconv.Itoa(timeoutSeconds) + " seconds for approval of code " + userCode + "...")
	}
	keep := func(polledAt float64) {
		kept := append(jsjson.Object(nil), entry...).Set("interval", interval)
		if !math.IsNaN(polledAt) && polledAt != 0 {
			kept = kept.Set("lastPolledAt", isoString(time.UnixMilli(int64(polledAt)).UTC()))
		}
		if _, err := clientctx.SavePendingSignIn(kept, r.Env); err != nil {
			_ = err // savePendingSignIn's failure escapes in TypeScript only where it is not caught; the callers below report
		}
	}
	stillPending := func(polledAt float64) error {
		keep(polledAt)
		if io.json {
			if err := r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "state", Value: "pending"}}); err != nil {
				return err
			}
		}
		_ = r.warn("varlatch login: not approved yet. Code " + userCode + " is still waiting at " + Printable(shownValue(jsTemplate(entry.Get("verificationUri")))) +
			" (it expires at " + jsTemplate(entry.Get("expiresAt")) + "). Run again: " + io.cli + " login --server " + commandServer(server) + " --wait")
		return ExitWith(ExitTempfail)
	}
	for {
		// No poll fits before the deadline (an earlier --wait may have
		// polled just now): still pending.
		wait := max(0, nextPollAt-nowMS())
		if math.IsNaN(wait) {
			wait = 0
		}
		if nowMS()+wait >= pollDeadline {
			return stillPending(lastPolledAt)
		}
		if wait > 0 {
			time.Sleep(time.Duration(wait) * time.Millisecond)
		}
		remaining := pollDeadline - nowMS()
		if remaining <= 0 {
			return stillPending(lastPolledAt)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(max(1, remaining))*time.Millisecond)
		polled, err := r.deviceClient(server, "").PollDeviceSignIn(ctx, deviceCode)
		cancel()
		if err != nil {
			lastPolledAt = nowMS()
			return r.waitFailure(err, server, io, func() { keep(lastPolledAt) }, nowMS() >= pollDeadline, seenPending, func() error { return stillPending(lastPolledAt) })
		}
		// The interval runs from the answer, not the request: the server
		// times polls by when it processed them.
		lastPolledAt = nowMS()
		switch polled.State {
		case "pending":
			seenPending = true
			interval = polled.Interval
			nextPollAt = lastPolledAt + interval*1000
			continue
		case "slow_down":
			seenPending = true
			interval = polled.Interval
			nextPollAt = lastPolledAt + interval*1000
			keep(lastPolledAt)
			continue
		case "denied":
			if err := clientctx.DeletePendingSignIn(server, r.Env); err != nil {
				return contextError(err)
			}
			if io.json {
				if err := r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "state", Value: "denied"}}); err != nil {
					return err
				}
			}
			_ = r.warn("varlatch login: the sign-in was denied in the browser. Nothing was stored. Start again: " + startNext)
			return ExitWith(ExitDenied)
		case "expired":
			if err := clientctx.DeletePendingSignIn(server, r.Env); err != nil {
				return contextError(err)
			}
			if collected, ok := entry.Get("collectedCredentialId"); ok && jsjson.Truthy(collected) {
				return r.collectedButNotStored(collected, io, startNext)
			}
			if io.json {
				if err := r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "state", Value: "expired"}}); err != nil {
					return err
				}
			}
			_ = r.warn("varlatch login: the sign-in expired before it was approved and collected (a code lasts 10 minutes). Nothing was stored. Start again: " + startNext)
			return ExitWith(ExitDenied)
		case "consumed":
			var credentialID any = polled.CredentialID
			if polled.CredentialID == "" {
				credentialID = nil
				if collected, ok := entry.Get("collectedCredentialId"); ok && collected != nil {
					credentialID = collected
				}
			}
			// An earlier --wait stored it and only failed to remove this entry.
			stored, err := clientctx.LoadCredential(server, r.Env)
			if err != nil {
				return err
			}
			if jsjson.Truthy(credentialID) && stored != nil {
				if id, ok := jsval.Get(stored, "credentialId"); ok && jsval.StrictEqual(id, credentialID) {
					if err := clientctx.DeletePendingSignIn(server, r.Env); err != nil {
						return contextError(err)
					}
					if io.json {
						expiresAt, ok := jsval.Get(stored, "expiresAt")
						if !ok {
							expiresAt = nil
						}
						return r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "state", Value: "signed-in"}, {Key: "credentialId", Value: credentialID}, {Key: "expiresAt", Value: expiresAt}})
					}
					return r.println("Already logged in to " + shownServer(server) + " with this sign-in's credential.")
				}
			}
			if err := clientctx.DeletePendingSignIn(server, r.Env); err != nil {
				return contextError(err)
			}
			return r.collectedButNotStored(credentialID, io, startNext)
		case "issued":
			id, idOK, err := read(polled.Credential, polled.Credential != apiclient.Undefined, "id")
			if err != nil {
				return err
			}
			// Before anything else can fail or be interrupted: record which
			// credential was collected. The entry stays until the credential
			// is stored, so a later --wait can still name it for revocation.
			collected := append(jsjson.Object(nil), entry...).Set("interval", interval)
			if idOK && id != apiclient.Undefined {
				collected = collected.Set("collectedCredentialId", id)
			}
			_, _ = clientctx.SavePendingSignIn(collected, r.Env) // the messages below name the credential either way
			return r.storeCollected(server, polled.Credential, deadline, io, startNext)
		}
	}
}

// collectedButNotStored: the sign-in's credential was collected, but never
// stored here, so it is named for revocation.
func (r *Run) collectedButNotStored(credentialID any, io deviceIO, startNext string) error {
	if io.json {
		if err := r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "state", Value: "consumed"}, {Key: "credentialId", Value: credentialID}}); err != nil {
			return err
		}
	}
	id := "(id unknown)"
	if credentialID != nil {
		id = jsjson.String(credentialID)
	}
	_ = r.warn("varlatch login: this sign-in's credential was already collected, but never stored by this CLI (its answer was lost, " +
		"or an earlier --wait was interrupted or failed). The credential this CLI had, if any, is unchanged. " +
		"Revoke credential " + Printable(id) + " in the dashboard (Account, Sessions), then start again: " + startNext)
	return ExitWith(ExitDenied)
}

func (r *Run) waitFailure(err error, server string, io deviceIO, keep func(), deadlinePassed, seenPending bool, stillPending func() error) error {
	network := apiclient.NetworkFailure(err)
	// At the deadline with the sign-in last seen pending: 75, as a plain
	// pending deadline.
	if (apiclient.IsAbort(err) || network != "") && deadlinePassed && seenPending {
		return stillPending()
	}
	keep()
	kept := "The pending sign-in is kept; run again: " + io.cli + " login --server " + commandServer(server) + " --wait"
	var redirect *apiclient.DeviceSignInRedirectError
	if errors.As(err, &redirect) {
		_ = r.warn(r.redirectMessage(redirect, server, "The pending sign-in is kept."))
		return ExitWith(ExitFailure)
	}
	var api *apiclient.APIError
	if errors.As(err, &api) {
		if api.Status == 404 {
			_ = r.warn("varlatch login: " + shownServer(server) + " does not offer device sign-in (capability auth.device). " + kept)
			return ExitWith(ExitUnavailable)
		}
		if api.CodeIs("MAINTENANCE") || api.Status == 502 || api.Status == 503 || api.Status == 504 {
			_ = r.warn("varlatch login: " + shownServer(server) + " is unavailable or in maintenance (" + strconv.Itoa(api.Status) + "). " + kept)
			return ExitWith(ExitUnavailable)
		}
		_ = r.warn("varlatch login: the server refused the poll (" + safeCode(api.Code) + "): " + r.Secrets.ServerMessage(api.Message) + ". " + kept)
		if api.Status >= 500 {
			return ExitWith(ExitUnavailable)
		}
		return ExitWith(ExitFailure)
	}
	if apiclient.IsAbort(err) {
		_ = r.warn("varlatch login: " + shownServer(server) + " did not answer before the deadline. " + kept)
		return ExitWith(ExitUnavailable)
	}
	if network != "" {
		_ = r.warn("varlatch login: cannot reach " + shownServer(server) + " (" + network + "). " + kept)
		return ExitWith(ExitUnavailable)
	}
	return err
}

// jsErrorString is String(err) for an error a request rejects with: its
// name and message.
func jsErrorString(err error) string {
	var abort *apiclient.AbortError
	switch {
	case errors.As(err, &abort):
		if abort.Timeout {
			return "TimeoutError: " + err.Error()
		}
		return "AbortError: " + err.Error()
	case errors.As(err, new(*apiclient.FetchError)), errors.As(err, new(*apiclient.BodyError)), errors.As(err, new(*clientctx.TypeError)):
		return "TypeError: " + err.Error()
	}
	return "Error: " + err.Error()
}

// storeCollected verifies the collected credential, stores it, and only
// then revokes the one it replaces: nothing exits 0 before a credential is
// stored, and a failed sign-in never leaves the person signed out.
func (r *Run) storeCollected(server string, credential any, deadline float64, io deviceIO, startNext string) error {
	field := func(key string) (any, bool, error) { return read(credential, credential != apiclient.Undefined, key) }
	token, tokenOK, err := field("token")
	if err != nil {
		return err
	}
	id, idOK, _ := field("id")
	expiresAt, expiresAtOK, _ := field("expiresAt")
	tokenText := jsTemplate(token, tokenOK)
	r.holdSecret(tokenText)
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(int64(deadline)))
	defer cancel()
	probe := r.deviceClient(server, tokenText)
	meta, err := probe.Meta(ctx)
	if err == nil {
		_, err = probe.ListOrganizations(ctx) // verifies the credential
	}
	if err != nil {
		var api *apiclient.APIError
		why := ""
		switch {
		case errors.As(err, &api):
			why = safeCode(api.Code)
		case apiclient.IsAbort(err):
			why = "no answer before the deadline"
		case apiclient.NetworkFailure(err) != "":
			why = apiclient.NetworkFailure(err)
		default:
			why = jsErrorString(err)
		}
		_ = r.warn("varlatch login: the sign-in was approved, but the new credential could not be verified (" + why + "); it was not stored. " +
			"Revoke credential " + Printable(jsTemplate(id, idOK)) + " in the dashboard (Account, Sessions), then start again: " + startNext)
		// The pending entry stays, naming the credential: a later --wait says it again.
		if api != nil && (api.Status == 401 || api.Status == 403) {
			return ExitWith(ExitDenied)
		}
		return ExitWith(ExitUnavailable)
	}
	previous, err := clientctx.LoadCredential(server, r.Env)
	if err != nil {
		return err
	}
	replaced := replacedCredential(previous, tokenText, nowMS())
	entry := jsjson.Object{{Key: "token", Value: token}, {Key: "issuedAt", Value: isoString(time.Now().UTC())}}
	if expiresAtOK && expiresAt != apiclient.Undefined {
		entry = append(entry, jsjson.Member{Key: "expiresAt", Value: expiresAt})
	}
	if idOK && id != apiclient.Undefined {
		entry = append(entry, jsjson.Member{Key: "credentialId", Value: id})
	}
	if err := clientctx.SaveCredential(server, entry, r.Env); err != nil {
		_ = r.warn("varlatch login: the sign-in was approved and its credential verified, but it could not be stored " +
			"(" + err.Error() + "). The credential this CLI had, if any, is unchanged. " +
			"Revoke credential " + Printable(jsTemplate(id, idOK)) + " in the dashboard (Account, Sessions), fix the problem, then start again: " + startNext)
		return ExitWith(ExitFailure)
	}
	// Only now, with the credential stored, is the pending entry done with.
	if err := clientctx.DeletePendingSignIn(server, r.Env); err != nil {
		_ = r.warn("varlatch: the pending sign-in could not be removed (" + err.Error() + "); the credential is stored.")
	}
	r.noteDefaultServer(server)
	if io.json {
		doc := jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "state", Value: "signed-in"}}
		if idOK && id != apiclient.Undefined {
			doc = append(doc, jsjson.Member{Key: "credentialId", Value: id})
		}
		if expiresAtOK && expiresAt != apiclient.Undefined {
			doc = append(doc, jsjson.Member{Key: "expiresAt", Value: expiresAt})
		}
		if err := r.printJSON(doc); err != nil {
			return err
		}
	} else {
		shownVersion, api, err := r.serverSummary(meta)
		if err != nil {
			return err
		}
		if err := r.println("Logged in to " + shownServer(server) + " (server " + shownVersion + ", " + api + "). The credential expires at " + templateTime(jsUndefinedOr(expiresAt, expiresAtOK)) + "."); err != nil {
			return err
		}
	}
	if replaced == nil {
		return nil
	}
	failure, err := r.revokeStoredWith(ctx, r.deviceClient, server, replaced)
	if err != nil {
		return err
	}
	say := r.println
	if io.json {
		say = r.warn
	}
	if failure == "" {
		return say("Previous credential revoked.")
	}
	_ = r.warn("varlatch: previous credential not revoked (" + clientctx.MaskUserinfoInText(failure) + "); it may remain live" + liveUntil(replaced) + ".")
	return nil
}
