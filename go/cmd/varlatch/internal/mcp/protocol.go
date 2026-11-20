// SPDX-License-Identifier: Apache-2.0

// Package mcp is `varlatch mcp`'s server (internal docs/design/go-cli.md,
// decision 5): the Model Context Protocol over stdio, newline-delimited
// JSON-RPC, held to what @modelcontextprotocol/sdk 1.32.2's McpServer over
// StdioServerTransport does for packages/mcp-server (ADR-0043 Decision 9),
// with its tools. It declares the tools capability only.
package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Protocol versions, as the SDK lists them.
const latestProtocolVersion = "2025-11-25"

var supportedProtocolVersions = []string{latestProtocolVersion, "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"}

// maxBuffer is the transport's ReadBuffer limit: more unread input than
// this closes the connection.
const maxBuffer = 10 * 1024 * 1024

// readChunk is how much a read takes at once, as Node.js reads a pipe.
const readChunk = 64 * 1024

// JSON-RPC error codes.
const (
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Options configure a server.
type Options struct {
	Client      Client
	Defaults    Defaults
	AllowWrites bool
	// Version is reported to the host in serverInfo.
	Version string
}

// Server answers one MCP host on one stream.
type Server struct {
	opts  Options
	tools []tool

	writeMu sync.Mutex
	write   func(line string)

	// chunkMu is held while one read's lines are handled, the handlers'
	// starts included: an answer that waited on the server is sent only
	// after it (RLock), as Node.js runs an I/O callback only after the
	// chunk it is handling and its microtasks. Answers that need no request
	// are sent within the chunk, in its order.
	chunkMu sync.RWMutex

	mu       sync.Mutex
	inflight map[any]*handling // by request id, as a JavaScript Map keys it
	wg       sync.WaitGroup
}

// handling is a request being handled; aborted (by notifications/cancelled
// or the connection closing) means it gets no response.
type handling struct {
	mu      sync.Mutex
	aborted bool
	// called: the handler called the server, so its answer is an I/O
	// callback's (chunkMu).
	called bool
}

func (h *handling) markCalled() {
	h.mu.Lock()
	h.called = true
	h.mu.Unlock()
}

func (h *handling) hasCalled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.called
}

func (h *handling) abort() {
	h.mu.Lock()
	h.aborted = true
	h.mu.Unlock()
}

func (h *handling) isAborted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.aborted
}

// New makes a server.
func New(opts Options) *Server {
	return &Server{opts: opts, tools: toolsFor(opts.AllowWrites), inflight: map[any]*handling{}}
}

// Serve reads messages from in and writes each answer, one JSON text and a
// line break, through write (never two at once). It returns once in ends
// and every request still being handled has been answered, as the
// TypeScript process exits then; or, when a line outgrows the transport's
// buffer, once the requests in hand are done, unanswered.
func (s *Server) Serve(ctx context.Context, in io.Reader, write func(line string)) {
	s.write = write
	var buffer []byte
	chunk := make([]byte, readChunk)
	for {
		n, err := in.Read(chunk)
		if n > 0 {
			if len(buffer)+n > maxBuffer {
				s.closeConnection()
				break
			}
			buffer = append(buffer, chunk[:n]...)
			// The lines of one read are handled as Node.js handles one
			// chunk: each request is registered in turn (a method without a
			// handler answered at once), then the chunk's notifications take
			// effect, as their handlers run in the microtasks after it, so a
			// cancellation reaches a request later in the same chunk; only
			// then do the handlers start.
			s.chunkMu.Lock()
			var batch chunkWork
			for {
				i := bytes.IndexByte(buffer, '\n')
				if i < 0 {
					break
				}
				line := buffer[:i]
				buffer = buffer[i+1:]
				s.handleLine(ctx, bytes.TrimSuffix(line, []byte("\r")), &batch)
			}
			for _, m := range batch.notifications {
				s.notification(m)
			}
			// One at a time, each until it is done or waits on the server:
			// answers that need no request go out in the chunk's order, as
			// Node.js's microtasks send them.
			for _, start := range batch.starts {
				<-start()
				if betweenStarts != nil {
					betweenStarts()
				}
			}
			s.chunkMu.Unlock()
			if len(buffer) == 0 {
				buffer = nil // let a large line's memory go
			}
		}
		if err != nil {
			break
		}
	}
	s.wg.Wait()
}

// closeConnection is the transport closing: every request in hand is
// aborted, and nothing more is read.
func (s *Server) closeConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.inflight {
		h.abort()
	}
	s.inflight = map[any]*handling{}
}

func (s *Server) send(v jsjson.Object) {
	line := string(jsjson.Stringify(v)) + "\n"
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.write(line)
}

func result(id any, r any) jsjson.Object {
	return jsjson.Object{{Key: "result", Value: r}, {Key: "jsonrpc", Value: "2.0"}, {Key: "id", Value: id}}
}

func rpcError(id any, code int, message string) jsjson.Object {
	return jsjson.Object{{Key: "jsonrpc", Value: "2.0"}, {Key: "id", Value: id}, {Key: "error", Value: jsjson.Object{
		{Key: "code", Value: float64(code)}, {Key: "message", Value: message},
	}}}
}

// message is one JSON-RPC message the SDK's JSONRPCMessageSchema accepts.
type message struct {
	kind   int // request, notification, or a response (ignored)
	id     any
	method string
	params any // absent when it has none
}

const (
	kindRequest = iota + 1
	kindNotification
	kindResponse
)

// chunkWork is what one chunk's lines leave for after them.
type chunkWork struct {
	notifications []message
	starts        []func() <-chan struct{}
}

// handleLine is the transport's readMessage and the protocol's onmessage:
// a line that is not JSON, or not a JSON-RPC message, is dropped without a
// word, as the SDK drops it (its onerror is not set).
func (s *Server) handleLine(ctx context.Context, line []byte, batch *chunkWork) {
	// JSON.parse refuses a byte order mark, which lib/jsjson skips.
	if bytes.HasPrefix(line, []byte("\xef\xbb\xbf")) {
		return
	}
	// JSON.parse has no nesting limit short of memory; nothing below walks
	// a value recursively.
	v, err := jsjson.ParseDeep(line)
	if err != nil {
		return
	}
	m, ok := classify(v)
	if !ok {
		return
	}
	switch m.kind {
	case kindRequest:
		if start := s.request(ctx, m); start != nil {
			batch.starts = append(batch.starts, start)
		}
	case kindNotification:
		batch.notifications = append(batch.notifications, m)
	}
	// A response answers a request the server sent; it sends none.
}

// classify is JSONRPCMessageSchema: a request, a notification, a result or
// an error response, each a strict object.
func classify(v any) (message, bool) {
	o, ok := v.(jsjson.Object)
	if !ok {
		return message{}, false
	}
	if jsonrpc, _ := o.Get("jsonrpc"); jsonrpc != "2.0" {
		return message{}, false
	}
	only := func(keys ...string) bool {
		for _, m := range o {
			found := false
			for _, k := range keys {
				if m.Key == k {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	method, isString := field(o, "method").(string)
	id := field(o, "id")
	params := field(o, "params")
	switch {
	case only("jsonrpc", "id", "method", "params") && validID(id) && isString && validParams(params):
		return message{kind: kindRequest, id: id, method: method, params: params}, true
	case only("jsonrpc", "method", "params") && isString && validParams(params):
		return message{kind: kindNotification, method: method, params: params}, true
	case only("jsonrpc", "id", "result") && validID(id) && validResult(field(o, "result")):
		return message{kind: kindResponse}, true
	case only("jsonrpc", "id", "error") && (id == absent || validID(id)) && validError(field(o, "error")):
		return message{kind: kindResponse}, true
	}
	return message{}, false
}

// validID is RequestIdSchema: a string or a safe integer.
func validID(v any) bool {
	switch x := v.(type) {
	case string:
		return true
	case float64:
		return safeInteger(x)
	}
	return false
}

func safeInteger(x float64) bool {
	return x == math.Trunc(x) && math.Abs(x) <= 1<<53-1
}

// validParams is params as a request or notification may have them: absent,
// or an object whose _meta, when it has one, is RequestMetaSchema.
func validParams(v any) bool {
	if v == absent {
		return true
	}
	o, ok := v.(jsjson.Object)
	return ok && validMeta(field(o, "_meta"))
}

func validMeta(v any) bool {
	if v == absent {
		return true
	}
	meta, ok := v.(jsjson.Object)
	if !ok {
		return false
	}
	if token := field(meta, "progressToken"); token != absent && !validID(token) {
		return false
	}
	if related := field(meta, "io.modelcontextprotocol/related-task"); related != absent {
		r, ok := related.(jsjson.Object)
		if !ok {
			return false
		}
		if _, ok := field(r, "taskId").(string); !ok {
			return false
		}
	}
	return true
}

func validResult(v any) bool {
	o, ok := v.(jsjson.Object)
	return ok && validMeta(field(o, "_meta"))
}

func validError(v any) bool {
	o, ok := v.(jsjson.Object)
	if !ok {
		return false
	}
	code, ok := field(o, "code").(float64)
	if !ok || !safeInteger(code) {
		return false
	}
	_, ok = field(o, "message").(string)
	return ok
}

// idKey is a request id as a JavaScript Map's key (SameValueZero: 0 and
// -0 alike, 1 and "1" apart).
func idKey(id any) any {
	if f, ok := id.(float64); ok && f == 0 {
		return 0.0
	}
	return id
}

// request is the protocol's _onrequest: a method without a handler is
// answered at once; a handled one is registered now (a later request with
// the same id takes its place), and the returned start runs its handler,
// whose answer is sent unless the request was cancelled meanwhile.
func (s *Server) request(ctx context.Context, m message) (start func() <-chan struct{}) {
	handler := s.handler(m.method)
	if handler == nil {
		s.send(rpcError(m.id, codeMethodNotFound, "Method not found"))
		return nil
	}
	h := &handling{}
	key := idKey(m.id)
	s.mu.Lock()
	s.inflight[key] = h
	s.mu.Unlock()
	s.wg.Add(1)
	return func() <-chan struct{} {
		// Closed when the handler is done or first calls the server.
		settled := make(chan struct{})
		var once sync.Once
		settle := func() { once.Do(func() { close(settled) }) }
		called := func() {
			h.markCalled()
			settle()
		}
		go func() {
			defer settle()
			s.answer(context.WithValue(ctx, callingKey{}, called), m, handler, h, key)
		}()
		return settled
	}
}

// betweenStarts, when set (by a test), runs after each handler of a chunk
// has started and before the next starts.
var betweenStarts func()

// callingKey holds, in a handler's context, what to do when it first calls
// the server.
type callingKey struct{}

// calling tells the chunk's loop that a handler waits on the server.
func calling(ctx context.Context) {
	if settle, ok := ctx.Value(callingKey{}).(func()); ok {
		settle()
	}
}

// answer runs a registered request's handler and sends its answer, unless
// the request was cancelled (or the connection closed) meanwhile; the
// handler itself runs on, as the SDK's does.
func (s *Server) answer(ctx context.Context, m message, handler func(context.Context, any) (any, error), h *handling, key any) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		if s.inflight[key] == h {
			delete(s.inflight, key)
		}
		s.mu.Unlock()
	}()
	r, err := s.run(ctx, m, handler)
	if h.hasCalled() {
		// An answer from the server: after the chunk being handled.
		s.chunkMu.RLock()
		defer s.chunkMu.RUnlock()
	}
	if h.isAborted() {
		return
	}
	if err != nil {
		code := codeInternalError
		if rpc, ok := errors.AsType[*rpcErr](err); ok {
			code = rpc.code
		}
		s.send(rpcError(m.id, code, err.Error()))
		return
	}
	s.send(result(m.id, r))
}

// run checks task creation, as the protocol does before the handler, then
// runs the handler. A handler that panics is answered as the SDK answers
// one that throws: -32603 with what it was, and the server serves on.
func (s *Server) run(ctx context.Context, m message, handler func(context.Context, any) (any, error)) (r any, err error) {
	defer func() {
		if p := recover(); p != nil {
			r, err = nil, fmt.Errorf("%v", p)
		}
	}()
	if taskAugmented(m.params) {
		return nil, errors.New("Server does not support task creation (required for " + m.method + ")")
	}
	return handler(ctx, m.params)
}

// rpcErr is an McpError: its code, and "MCP error <code>: <message>".
type rpcErr struct {
	code    int
	message string
}

func (e *rpcErr) Error() string { return e.message }

func mcpError(code int, message string) *rpcErr {
	return &rpcErr{code: code, message: "MCP error " + jsjson.Number(float64(code)) + ": " + message}
}

// zodError is a request that failed its method's schema: a ZodError,
// which carries no code (-32603) and its issues as its message.
type zodError struct{ issues []issue }

func (e *zodError) Error() string { return zodMessage(e.issues) }

// handler is the request handler the SDK registers for a method, or nil.
func (s *Server) handler(method string) func(context.Context, any) (any, error) {
	switch method {
	case "initialize":
		return s.initialize
	case "ping":
		return func(context.Context, any) (any, error) { return jsjson.Object{}, nil }
	case "tools/list":
		return s.listTools
	case "tools/call":
		return s.callTool
	}
	return nil
}

func (s *Server) initialize(_ context.Context, params any) (any, error) {
	if issues := initializeIssues(params); len(issues) > 0 {
		return nil, &zodError{issues}
	}
	version := latestProtocolVersion
	requested, _ := params.(jsjson.Object).Value("protocolVersion").(string)
	for _, v := range supportedProtocolVersions {
		if v == requested {
			version = v
		}
	}
	return jsjson.Object{
		{Key: "protocolVersion", Value: version},
		{Key: "capabilities", Value: jsjson.Object{{Key: "tools", Value: jsjson.Object{{Key: "listChanged", Value: true}}}}},
		{Key: "serverInfo", Value: jsjson.Object{{Key: "name", Value: "varlatch"}, {Key: "version", Value: s.opts.Version}}},
	}, nil
}

func (s *Server) listTools(_ context.Context, params any) (any, error) {
	if issues := listToolsIssues(params); len(issues) > 0 {
		return nil, &zodError{issues}
	}
	list := make([]any, len(s.tools))
	for i, t := range s.tools {
		list[i] = t.definition()
	}
	return jsjson.Object{{Key: "tools", Value: list}}, nil
}

// notification is the protocol's _onnotification: only a cancellation
// changes anything (notifications/initialized and notifications/progress
// for a request the server never sent do not); any other is ignored.
func (s *Server) notification(m message) {
	if m.method != "notifications/cancelled" {
		return
	}
	// CancelledNotificationSchema: params {requestId?, reason?}.
	p, ok := m.params.(jsjson.Object)
	if !ok {
		return
	}
	id := field(p, "requestId")
	if id != absent && !validID(id) {
		return
	}
	if reason := field(p, "reason"); reason != absent {
		if _, ok := reason.(string); !ok {
			return
		}
	}
	// `if (!notification.params.requestId) return;`
	switch x := id.(type) {
	case absentT:
		return
	case string:
		if x == "" {
			return
		}
	case float64:
		if x == 0 {
			return
		}
	}
	s.mu.Lock()
	h := s.inflight[idKey(id)]
	s.mu.Unlock()
	if h != nil {
		h.abort()
	}
}
