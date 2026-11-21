// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/broker"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// A `varlatch run` the Agent starts inside an agent-safe run (slice 5.5b of
// internal docs/design/go-cli.md; main.ts's "run" case and agentRun.ts,
// ADR-0043 Decision 5): it never discloses and never falls back to the
// operator's credential. The command gets this run's environment,
// Placeholders included, less what --omit names; the run's own credentials
// (an agent-run bearer, the proxy credential) are masked in its output; and
// a tunnel the Broker refused meanwhile is named afterwards, since curl
// reports it as a network failure.

func (r *Run) nestedRun(agentRun string, pre []string, command string, commandArgs, omit []string) error {
	var unavailable []string
	for _, f := range []string{"--agent-safe", "--strict", "--export-context"} {
		if hasArg(pre, f) {
			unavailable = append(unavailable, f)
		}
	}
	if len(unavailable) > 0 {
		return UsageError("varlatch: this command runs inside agent-safe run " + agentRun + ", where Secrets are Placeholders and are never " +
			"disclosed, so " + strings.Join(unavailable, " and ") + " cannot run here. Nothing was started.")
	}
	r.eprintln("varlatch: inside agent-safe run " + agentRun + ", Secrets are Placeholders and are never disclosed; the command " +
		"starts with this run's environment unchanged, and the run's own credentials are masked in its output. " +
		"Send requests to allowed destinations with varlatch request.")
	// The run's credentials never reach a nested command's output (an agent asked to check a variable).
	credentials := agentRunCredentials(r.Env)
	nested := r.parentEnv()
	for _, name := range omit {
		nested.Delete(name)
	}
	// A refused tunnel looks like a network failure from curl: say what it was.
	before := r.refusedTunnels()
	var redaction *matcher.OutputRedaction
	if len(credentials) > 0 {
		redaction = matcher.NewOutputRedaction(credentials, matcher.ModeRedact)
	}
	code, err := r.runChild(command, commandArgs, nested.Lines(), redaction)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range nested.Lines() {
		name, value, _ := strings.Cut(line, "=")
		values[name] = value
	}
	if note := tunnelNote(before, r.refusedTunnels(), placeholderNames(values)); note != "" {
		r.eprintln(note)
	}
	return ExitWith(code)
}

// agentRunCredentials is agentRunCredentials: the run's own credentials in
// an Agent's environment, masked in a nested run's output: the agent-run
// credential (VARLATCH_TOKEN, with --agent-metadata) and the Broker's proxy
// credential in the proxy URLs.
func agentRunCredentials(env Env) []matcher.SecretEntry {
	var out []matcher.SecretEntry
	if token, _ := env.LookupEnv("VARLATCH_TOKEN"); token != "" {
		out = append(out, matcher.SecretEntry{Item: "VARLATCH_TOKEN", Value: token})
	}
	for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		raw, _ := env.LookupEnv(name)
		if raw == "" {
			continue
		}
		u, ok := whatwg.ParseURL(raw)
		if !ok {
			continue // not a URL: nothing of the run's to mask
		}
		password, ok := decodeURIComponent(u.Password)
		if !ok || password == "" {
			continue
		}
		if !slices.ContainsFunc(out, func(e matcher.SecretEntry) bool { return e.Value == password }) {
			out = append(out, matcher.SecretEntry{Item: name, Value: password})
		}
	}
	return out
}

// tunnelsResponseLimit is TUNNELS_RESPONSE_LIMIT: the counts are a few
// hundred bytes; the address comes from the Agent's environment.
const tunnelsResponseLimit = 64 * 1024

// refusedTunnels is refusedTunnels: the tunnels the run's Broker refused so
// far, by destination; nil when the proxy is not the run's Broker or it
// does not answer. The note is a hint, never a reason to fail the command.
func (r *Run) refusedTunnels() map[string]float64 {
	raw, set := r.Env.LookupEnv("HTTPS_PROXY")
	if !set {
		raw, _ = r.Env.LookupEnv("https_proxy")
	}
	proxy, ok := whatwg.ParseURL(raw)
	if !ok {
		return nil
	}
	hostname, port := splitURLHost(proxy.Host)
	if hostname != "127.0.0.1" || proxy.Username != "vlt" || port == "" {
		return nil
	}
	password, ok := decodeURIComponent(proxy.Password)
	if !ok {
		return nil
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte("vlt:" + password))
	request := "GET " + broker.TunnelsPath + " HTTP/1.1\r\nProxy-Authorization: Basic " + auth + "\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil
	}
	br := bufio.NewReader(conn)
	head, err := readResponseHead(br)
	if err != nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(responseBody(br, head, "GET"), tunnelsResponseLimit+1))
	if err != nil || len(body) > tunnelsResponseLimit || head.status != 200 {
		return nil
	}
	doc, err := jsjson.Parse(body)
	if err != nil {
		return nil
	}
	list, ok := fieldOf(doc, "tunnels").([]any)
	if !ok {
		return nil
	}
	out := map[string]float64{}
	for _, t := range list {
		count, _ := fieldOf(t, "count").(float64)
		out[jsjson.String(fieldOf(t, "destination"))] = count
	}
	return out
}

// tunnelNote is tunnelNote: what a nested run adds after its command when
// the Broker refused a tunnel meanwhile. Destinations and a Placeholder
// name only, never a value.
func tunnelNote(before, after map[string]float64, placeholders []string) string {
	if before == nil || after == nil {
		return ""
	}
	var refused []string
	for destination, n := range after {
		if n > before[destination] {
			refused = append(refused, destination)
		}
	}
	if len(refused) == 0 {
		return ""
	}
	slices.SortFunc(refused, jsval.CompareUTF16)
	first := refused[0]
	colon := strings.LastIndex(first, ":")
	host, port := first, ""
	if colon >= 0 {
		host, port = first[:colon], first[colon+1:]
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	url := "https://" + host
	if port != "443" {
		url += ":" + port
	}
	url += "/..."
	name := "API_KEY"
	if len(placeholders) > 0 {
		name = placeholders[0]
	}
	return "varlatch: while this command ran, the Broker refused an HTTPS tunnel to " + strings.Join(refused, ", ") + ". " +
		"curl, fetch, and most SDKs open one, and agent-safe runs refuse it: the request never left this machine, " +
		"so this is not a network failure. Send the request with varlatch request instead, for example:\n" +
		`  varlatch --assisted request -H "Authorization: Bearer $` + name + `" ` + url
}
