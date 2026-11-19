// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// `varlatch request` (slice 5.5b of internal docs/design/go-cli.md),
// apps/cli/src/request.ts and main.ts's "request" case (ADR-0043 Decision
// 6): a curl-like client for the Agent inside an agent-safe run. It sends
// each request to the run's Broker as a plain HTTP request with an absolute
// URI and the per-run proxy credential, so the Broker can inspect it,
// substitute Secrets at their targets, originate TLS itself, and scrub the
// response. It needs no Varlatch credential and holds no Secret: the
// Agent's environment carries Placeholders, and responses arrive already
// scrubbed. Outside an agent-safe run it refuses.
//
// Its statuses: 0 when the destination answered (whatever the HTTP status)
// and all of it was written; 1 for a cut-off response, an output that
// cannot be written, or a Broker refusal; 77 when the Broker did not accept
// the proxy credential; 69 when the Broker cannot be reached or answers 503;
// 64 for a wrong command line or no Broker to send through.

const requestUsage = "Usage: varlatch request [-X <method>] [-H '<name>: <value>']... [-d <data>|@<file>|@-] [--json <data>|@<file>|@-] " +
	"[-o <file>] [-i] <https-url>"

// requestUsageError is RequestUsageError.
type requestUsageError struct{ message string }

func (e *requestUsageError) Error() string { return e.message }

// requestOptions is RequestOptions.
type requestOptions struct {
	method string
	// href is url.href, host url.host.
	href, host string
	// headers are the header lines as given, in order, then the defaults.
	headers [][2]string
	body    []byte
	hasBody bool
	// output is -o, "" for standard output.
	output  string
	include bool
}

// httpToken is TOKEN.
var httpToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

var requestValued = map[string]bool{"-X": true, "--request": true, "-H": true, "--header": true, "-d": true, "--data": true, "--json": true, "-o": true, "--output": true}

// parseRequestArgs is parseRequestArgs: the curl-like subset. readData
// resolves `@file` and `@-`: the bytes are sent as they are.
func parseRequestArgs(args []string, readData func(spec string) ([]byte, error)) (requestOptions, error) {
	var opts requestOptions
	method := ""
	json := false
	var positionals []string
	data := func(flag, value string) ([]byte, error) {
		if opts.hasBody {
			return nil, &requestUsageError{"give the body once: " + flag + " after -d or --json"}
		}
		if strings.HasPrefix(value, "@") {
			return readData(value[1:])
		}
		return []byte(value), nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if requestValued[arg] {
			i++
			if i >= len(args) {
				return opts, &requestUsageError{arg + " needs a value"}
			}
			value := args[i]
			switch arg {
			case "-X", "--request":
				if !httpToken.MatchString(value) {
					return opts, &requestUsageError{arg + ": not an HTTP method: " + value}
				}
				method = value
			case "-H", "--header":
				name := ""
				colon := strings.Index(value, ":")
				if colon >= 0 {
					name = whatwg.Trim(value[:colon])
				}
				if !httpToken.MatchString(name) {
					return opts, &requestUsageError{arg + " expects '<name>: <value>'"}
				}
				headerValue := whatwg.Trim(value[colon+1:])
				// A line break would start another header or end the head.
				if strings.ContainsAny(headerValue, "\r\n\x00") {
					return opts, &requestUsageError{arg + " " + name + ": a header value cannot contain a line break"}
				}
				opts.headers = append(opts.headers, [2]string{name, headerValue})
			case "-d", "--data", "--json":
				body, err := data(arg, value)
				if err != nil {
					return opts, err
				}
				opts.body, opts.hasBody = body, true
				if arg == "--json" {
					json = true
				}
			case "-o", "--output":
				opts.output = value
			}
			continue
		}
		if arg == "-i" || arg == "--include" {
			opts.include = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return opts, &requestUsageError{"unknown option " + arg}
		}
		positionals = append(positionals, arg)
	}

	if len(positionals) != 1 {
		if len(positionals) == 0 {
			return opts, &requestUsageError{"give the URL"}
		}
		return opts, &requestUsageError{"give one URL"}
	}
	u, ok := whatwg.ParseURL(positionals[0])
	if !ok {
		return opts, &requestUsageError{"not an absolute URL: " + positionals[0]}
	}
	if u.Protocol != "https:" && u.Protocol != "http:" {
		return opts, &requestUsageError{"not an HTTP URL: " + u.Protocol}
	}
	if u.Username != "" || u.Password != "" {
		return opts, &requestUsageError{"credentials in the URL are not sent; use a header"}
	}
	opts.href, opts.host = urlHref(positionals[0], u), u.Host

	has := func(name string) bool {
		for _, h := range opts.headers {
			if strings.EqualFold(h[0], name) {
				return true
			}
		}
		return false
	}
	if opts.hasBody && json {
		if !has("content-type") {
			opts.headers = append(opts.headers, [2]string{"Content-Type", "application/json"})
		}
		if !has("accept") {
			opts.headers = append(opts.headers, [2]string{"Accept", "application/json"})
		}
	} else if opts.hasBody && !has("content-type") {
		opts.headers = append(opts.headers, [2]string{"Content-Type", "application/x-www-form-urlencoded"})
	}
	if !has("accept") {
		opts.headers = append(opts.headers, [2]string{"Accept", "*/*"})
	}
	switch {
	case method != "":
		opts.method = method
	case opts.hasBody:
		opts.method = "POST"
	default:
		opts.method = "GET"
	}
	return opts, nil
}

// urlHref is url.href for an http or https URL without credentials: the
// origin, the path and query percent-encoded as `new URL` serializes them,
// and the fragment; an empty query or fragment keeps its "?" or "#".
func urlHref(input string, u whatwg.URL) string {
	path, query := u.RequestTarget()
	href := u.Protocol + "//" + u.Host + path
	trimmed := strings.TrimFunc(input, func(r rune) bool { return r <= 0x20 })
	hash := strings.IndexByte(trimmed, '#')
	beforeHash := trimmed
	if hash >= 0 {
		beforeHash = trimmed[:hash]
	}
	if u.Search != "" {
		href += "?" + query
	} else if strings.Contains(beforeHash, "?") {
		href += "?"
	}
	if hash >= 0 {
		href += "#" + fragmentEncode(trimmed[hash+1:])
	}
	return href
}

// fragmentEncode is the fragment percent-encode set: C0 controls, space,
// ", <, >, `, DEL and non-ASCII; tabs and newlines are removed.
func fragmentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\t' || c == '\n' || c == '\r':
		case c <= 0x20 || c >= 0x7f || strings.IndexByte("\"<>`", c) >= 0:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// readDataSpec is readDataSpec: `-` is standard input, anything else a
// file; a file that cannot be read is a usage error naming it.
func (r *Run) readDataSpec(spec string) ([]byte, error) {
	if spec == "-" {
		return io.ReadAll(r.Stdin)
	}
	b, err := os.ReadFile(spec)
	if err != nil {
		return nil, &requestUsageError{"cannot read " + spec + " (" + nodeErrnoCode(spec, err) + ")"}
	}
	return b, nil
}

// brokerEndpoint is BrokerEndpoint.
type brokerEndpoint struct {
	host string
	port int
	// authorization is the Proxy-Authorization value for the per-run credential.
	authorization string
}

// brokerFromEnv is brokerFromEnv: the run's Broker from the Agent's
// environment, or why there is none. Only a loopback proxy is used: that
// is where an agent-safe run's Broker listens.
func (r *Run) brokerFromEnv() (brokerEndpoint, string) {
	run := clientctx.AgentRunOf(r.Env)
	if run == "" {
		return brokerEndpoint{}, "varlatch request sends requests through the Broker of an agent-safe run, and this is not one " +
			"(" + clientctx.AgentRunEnv + " is not set). Outside an agent-safe run, use any HTTP client."
	}
	raw := ""
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v, set := r.Env.LookupEnv(name); set {
			raw = v
			break
		}
	}
	if raw == "" {
		return brokerEndpoint{}, "agent-safe run " + run + " has no Broker: it carries no Secrets, so there is nothing to substitute. " +
			"Use any HTTP client."
	}
	proxy, ok := whatwg.ParseURL(raw)
	if !ok {
		return brokerEndpoint{}, "the proxy in HTTPS_PROXY is not a URL"
	}
	hostname, port := splitURLHost(proxy.Host)
	loopback := hostname == "127.0.0.1" || hostname == "localhost" || hostname == "[::1]"
	user, userOK := decodeURIComponent(proxy.Username)
	password, passwordOK := decodeURIComponent(proxy.Password)
	if proxy.Protocol != "http:" || !loopback || port == "" || proxy.Username == "" || !userOK || !passwordOK {
		return brokerEndpoint{}, "HTTPS_PROXY does not name this run's Broker (a loopback http:// proxy with the per-run credential)"
	}
	n, _ := strconv.Atoi(port)
	return brokerEndpoint{
		host:          strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]"),
		port:          n,
		authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
	}, ""
}

// splitURLHost is a URL's host as hostname and port ("" when none).
func splitURLHost(host string) (hostname, port string) {
	i := strings.LastIndexByte(host, ':')
	if i < 0 || strings.HasSuffix(host, "]") {
		return host, ""
	}
	return host[:i], host[i+1:]
}

// decodeURIComponent is decodeURIComponent; false where it throws.
func decodeURIComponent(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b = append(b, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		v, err := hex.DecodeString(s[i+1 : i+3])
		if err != nil {
			return "", false
		}
		b = append(b, v[0])
		i += 2
	}
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// requestOutcome is RequestOutcome.
type requestOutcome struct {
	// kind is response (the destination answered, and all of it was
	// written), refused (the Broker answered itself), unreachable or
	// incomplete.
	kind   string
	status int
	code   string
	reason string
}

// brokerReplyHeader is BROKER_REPLY_HEADER: the Broker's marker on the
// replies it generates itself, stripped from every destination response.
const brokerReplyHeader = "varlatch-broker"

// requestHead is the request as Node's http.request writes it with the
// headers in this order and a dedicated agent without keep-alive: the
// request line with the absolute URI, Host, User-Agent unless given, the
// headers given, the proxy credential, Content-Length with a body, then
// Connection: close, and Content-Length: 0 for a method that would
// otherwise be chunked.
func requestHead(opts requestOptions, broker brokerEndpoint) ([]byte, error) {
	headers := [][2]string{{"Host", opts.host}}
	hasHeader := func(name string) bool {
		for _, h := range opts.headers {
			if strings.EqualFold(h[0], name) {
				return true
			}
		}
		return false
	}
	if !hasHeader("user-agent") {
		headers = append(headers, [2]string{"User-Agent", "varlatch-request"})
	}
	headers = append(headers, opts.headers...)
	headers = append(headers, [2]string{"Proxy-Authorization", broker.authorization})
	if opts.hasBody {
		headers = append(headers, [2]string{"Content-Length", strconv.Itoa(len(opts.body))})
	}
	var b strings.Builder
	b.WriteString(opts.method + " " + opts.href + " HTTP/1.1\r\n")
	connection, contentLength := false, false
	for _, h := range headers {
		value, err := latin1Header(h[0], h[1])
		if err != nil {
			return nil, err
		}
		b.WriteString(h[0] + ": " + value + "\r\n")
		switch strings.ToLower(h[0]) {
		case "connection":
			connection = true
		case "content-length", "transfer-encoding":
			contentLength = true
		}
	}
	if !connection {
		b.WriteString("Connection: close\r\n")
	}
	switch opts.method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "TRACE", "CONNECT":
	default:
		if !contentLength {
			b.WriteString("Content-Length: 0\r\n")
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String()), nil
}

// latin1Header is a header value as Node writes it: each UTF-16 unit as
// one byte, refused (ERR_INVALID_CHAR) outside tab, 0x20-0x7e and
// 0x80-0xff.
func latin1Header(name, value string) (string, error) {
	var out []byte
	for _, u := range jsval.UTF16(value) {
		if u != '\t' && (u < 0x20 || u == 0x7f || u > 0xff) {
			return "", errors.New(`Invalid character in header content ["` + name + `"]`)
		}
		out = append(out, byte(u))
	}
	return string(out), nil
}

// dialCode is Node's code for a connection that failed.
func dialCode(err error) string {
	for _, c := range []struct {
		errno syscall.Errno
		code  string
	}{
		{syscall.ECONNREFUSED, "ECONNREFUSED"}, {syscall.ECONNRESET, "ECONNRESET"}, {syscall.ETIMEDOUT, "ETIMEDOUT"},
		{syscall.EHOSTUNREACH, "EHOSTUNREACH"}, {syscall.ENETUNREACH, "ENETUNREACH"}, {syscall.EADDRNOTAVAIL, "EADDRNOTAVAIL"},
		{syscall.EPIPE, "EPIPE"},
	} {
		if errors.Is(err, c.errno) {
			return c.code
		}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "ENOTFOUND"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "ECONNRESET"
	}
	return err.Error()
}

// nodeErrnoCode is Node's code for a failed file operation, err.message
// when it has none.
func nodeErrnoCode(path string, err error) string {
	if errors.Is(err, syscall.EPIPE) {
		return "EPIPE"
	}
	if errors.Is(err, syscall.EEXIST) || errors.Is(err, os.ErrExist) {
		return "EEXIST"
	}
	if code := secretinput.ReadErrorCode(path, err); code != "an error" {
		return code
	}
	return err.Error()
}

// responseHead is a response's status line and headers as Node's parser
// gives them.
type responseHead struct {
	version string
	status  int
	reason  string
	// raw are the header lines as received: names in their own case, values
	// without surrounding whitespace.
	raw [][2]string
}

func (h *responseHead) get(name string) (string, bool) {
	for _, p := range h.raw {
		if strings.EqualFold(p[0], name) {
			return p[1], true
		}
	}
	return "", false
}

var statusLine = regexp.MustCompile(`^HTTP/(\d)\.(\d) (\d{3})(?: (.*))?$`)

// maxResponseHead is Node.js's --max-http-header-size default: a response
// head (its status line and headers) larger than this is refused.
const maxResponseHead = 16 * 1024

// errHeadOverflow is Node's HPE_HEADER_OVERFLOW: the code is all that is
// reported, never the head's bytes.
var errHeadOverflow = errors.New("HPE_HEADER_OVERFLOW")

// headLine reads one line of a response head, counting it against left:
// errHeadOverflow once the head would pass maxResponseHead, without
// reading more than that into memory.
func headLine(br *bufio.Reader, left *int) (string, error) {
	var b []byte
	for {
		frag, err := br.ReadSlice('\n')
		*left -= len(frag)
		if *left < 0 {
			return "", errHeadOverflow
		}
		b = append(b, frag...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return string(b), err
	}
}

// readResponseHead reads one response head; interim (1xx) responses but
// 101 are skipped, as Node's client skips them. Each head is bounded at
// maxResponseHead.
func readResponseHead(br *bufio.Reader) (*responseHead, error) {
	for {
		left := maxResponseHead
		line, err := headLine(br, &left)
		if err != nil {
			return nil, err
		}
		m := statusLine.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if m == nil {
			return nil, errors.New("HPE_INVALID_CONSTANT")
		}
		h := &responseHead{version: m[1] + "." + m[2], reason: m[4]}
		h.status, _ = strconv.Atoi(m[3])
		for {
			line, err := headLine(br, &left)
			if err != nil {
				return nil, err
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			name, value, ok := strings.Cut(line, ":")
			if !ok || !httpToken.MatchString(name) {
				return nil, errors.New("HPE_INVALID_HEADER_TOKEN")
			}
			h.raw = append(h.raw, [2]string{name, strings.Trim(value, " \t")})
		}
		if h.status >= 100 && h.status < 200 && h.status != 101 {
			continue
		}
		return h, nil
	}
}

// head is request.ts's head: the status line and headers before the body (-i).
func (h *responseHead) bytes() []byte {
	first := strings.TrimRight("HTTP/"+h.version+" "+strconv.Itoa(h.status)+" "+h.reason, " \t\n\r")
	lines := []string{first}
	for _, p := range h.raw {
		lines = append(lines, p[0]+": "+p[1])
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
}

// errCutOff is a response that ended before it was complete.
var errCutOff = errors.New("the response was cut off before it was complete")

// responseBody is the response's body as its framing gives it: errCutOff
// when the connection ends before the body is complete.
func responseBody(br *bufio.Reader, h *responseHead, method string) io.Reader {
	if method == "HEAD" || h.status == 204 || h.status == 304 || (h.status >= 100 && h.status < 200) {
		return strings.NewReader("")
	}
	if te, ok := h.get("transfer-encoding"); ok && strings.Contains(strings.ToLower(te), "chunked") {
		return &chunkedBody{br: br}
	}
	if cl, ok := h.get("content-length"); ok {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err == nil && n >= 0 {
			return &lengthBody{r: br, left: n}
		}
	}
	return br
}

type lengthBody struct {
	r    io.Reader
	left int64
}

func (l *lengthBody) Read(p []byte) (int, error) {
	if l.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	if err == io.EOF && l.left > 0 {
		return n, errCutOff
	}
	if err != nil && err != io.EOF {
		return n, errCutOff
	}
	return n, nil
}

type chunkedBody struct {
	br   *bufio.Reader
	left int64
	done bool
}

func (c *chunkedBody) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.left == 0 {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, errCutOff
		}
		size, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), ";")
		n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
		if err != nil || n < 0 {
			return 0, errCutOff
		}
		if n == 0 {
			// Trailers, up to the empty line.
			for {
				line, err := c.br.ReadString('\n')
				if err != nil {
					return 0, errCutOff
				}
				if strings.TrimRight(line, "\r\n") == "" {
					break
				}
			}
			c.done = true
			return 0, io.EOF
		}
		c.left = n
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.br.Read(p)
	c.left -= int64(n)
	if err != nil {
		return n, errCutOff
	}
	if c.left == 0 {
		if _, err := c.br.Discard(2); err != nil {
			return n, errCutOff
		}
	}
	return n, nil
}

// sendThroughBroker is sendThroughBroker: one request to the Broker, its
// response relayed. A reply the Broker generated itself carries its marker
// and goes to stderr ("refused"); every other reply is the destination's,
// relayed whatever its status. The body goes to stdout, or with -o to a
// temporary file beside the named one that replaces it only once the whole
// response was received and written; -i writes the head first. A response
// cut off, or an output that cannot be written, is "incomplete", and a
// partial -o file is removed.
func (r *Run) sendThroughBroker(opts requestOptions, broker brokerEndpoint) requestOutcome {
	head, err := requestHead(opts, broker)
	if err != nil {
		return requestOutcome{kind: "error", reason: err.Error()}
	}
	conn, err := net.Dial("tcp", net.JoinHostPort(broker.host, strconv.Itoa(broker.port)))
	if err != nil {
		return requestOutcome{kind: "unreachable", code: dialCode(err)}
	}
	defer conn.Close()
	if _, err := conn.Write(append(head, opts.body...)); err != nil {
		return requestOutcome{kind: "unreachable", code: dialCode(err)}
	}
	br := bufio.NewReader(conn)
	res, err := readResponseHead(br)
	if err != nil {
		if strings.HasPrefix(err.Error(), "HPE_") {
			return requestOutcome{kind: "unreachable", code: err.Error()}
		}
		return requestOutcome{kind: "unreachable", code: dialCode(err)}
	}
	body := responseBody(br, res, opts.method)
	if _, marked := res.get(brokerReplyHeader); marked {
		// The Broker's own reply: its text to stderr, whole or not.
		text, _ := io.ReadAll(body)
		trimmed := whatwg.Trim(string(text))
		if trimmed != "" {
			for _, line := range strings.Split(trimmed, "\n") {
				r.eprintln(line)
			}
		} else if res.status == 407 {
			r.eprintln("varlatch-broker: the per-run proxy credential in HTTPS_PROXY was not accepted")
		}
		return requestOutcome{kind: "refused", status: res.status}
	}
	return r.relayResponse(opts, res, body)
}

// relayResponse writes the destination's response, as the Broker relayed
// it (already scrubbed): the head with -i, then the body, to stdout or to
// the -o file. These bytes are the destination's, never the CLI's text, so
// the fail-safe does not rewrite them, as for the command `run` starts.
func (r *Run) relayResponse(opts requestOptions, res *responseHead, body io.Reader) requestOutcome {
	var out io.Writer = r.Stdout
	target := "standard output"
	temp := ""
	var file *os.File
	if opts.output != "" {
		target = opts.output
		suffix := make([]byte, 6)
		_, _ = rand.Read(suffix)
		temp = filepath.Join(filepath.Dir(opts.output), "."+filepath.Base(opts.output)+".varlatch-"+hex.EncodeToString(suffix))
		f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		if err != nil {
			return requestOutcome{kind: "incomplete", reason: "cannot write " + opts.output + " (" + nodeErrnoCode(temp, err) + ")"}
		}
		file, out = f, f
	} else {
		stop := ignoreBrokenPipe()
		defer stop()
	}
	fail := func(reason string) requestOutcome {
		if file != nil {
			_ = file.Close()
			_ = os.Remove(temp)
		}
		return requestOutcome{kind: "incomplete", reason: reason}
	}
	writeFailure := func(err error) requestOutcome {
		return fail("cannot write " + target + " (" + nodeErrnoCode(target, err) + ")")
	}
	if opts.include {
		if _, err := out.Write(res.bytes()); err != nil {
			return writeFailure(err)
		}
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return writeFailure(werr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(errCutOff.Error())
		}
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return writeFailure(err)
		}
		if err := os.Rename(temp, opts.output); err != nil {
			_ = os.Remove(temp)
			return requestOutcome{kind: "incomplete", reason: "cannot write " + opts.output + " (" + nodeErrnoCode(opts.output, err) + ")"}
		}
	}
	return requestOutcome{kind: "response", status: res.status}
}

// requestCommand is main.ts's "request" case.
func requestCommand(r *Run) error {
	opts, err := parseRequestArgs(r.Args, r.readDataSpec)
	if err != nil {
		var wrong *requestUsageError
		if errors.As(err, &wrong) {
			return UsageErrorWithUsage("varlatch request: "+wrong.message+"\n", requestUsage)
		}
		return err
	}
	broker, refusal := r.brokerFromEnv()
	if refusal != "" {
		return UsageError("varlatch request: " + refusal)
	}
	outcome := r.sendThroughBroker(opts, broker)
	switch outcome.kind {
	case "error":
		return errors.New(outcome.reason)
	case "unreachable":
		return Fail("varlatch request: cannot reach the Broker at "+broker.host+":"+strconv.Itoa(broker.port)+" ("+outcome.code+")", ExitUnavailable)
	case "refused":
		code := ExitFailure
		switch outcome.status {
		case 407:
			code = ExitDenied
		case 503:
			code = ExitUnavailable
		}
		return Fail("varlatch request: the Broker refused the request ("+strconv.Itoa(outcome.status)+"); nothing reached the destination unless it says so above", code)
	case "incomplete":
		message := "varlatch request: " + outcome.reason + "; the output is incomplete"
		if opts.output != "" {
			message += ", and " + opts.output + " was not written"
		}
		return Fail(message, ExitFailure)
	}
	return nil
}
