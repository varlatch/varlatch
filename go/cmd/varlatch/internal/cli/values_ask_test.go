// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// `values ask`, `asked` and `ask-cancel` (ADR-0063).

const askToken = "vlt_entry_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

type askServer struct {
	*valuesServer
	mu   sync.Mutex
	sent []string
	// capabilities and answer are what it says.
	capabilities, answer string
}

func newAskServer(t *testing.T) *askServer {
	s := &askServer{valuesServer: newValuesServer(t), capabilities: `"values.entry-links"`,
		answer: `{"link":{"id":"enl_abcdefghijklmnop","expiresAt":"2026-11-25T10:00:00Z"},"url":"https://varlatch.example/entry#` + askToken + `"}`}
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("content-type", "application/json")
		if r.URL.Path == "/v1/meta" {
			_, _ = io.WriteString(w, `{"serverVersion":"0.50.0","capabilities":[`+s.capabilities+`]}`)
			return
		}
		s.mu.Lock()
		s.sent = append(s.sent, r.Method+" "+r.URL.Path+" "+string(raw))
		s.mu.Unlock()
		switch r.Method {
		case "DELETE":
			w.WriteHeader(204)
		case "GET":
			_, _ = io.WriteString(w, `{"items":[{"id":"enl_1aaaaaaaaaa","item":"A_KEY","status":"entered","restrictedTo":"member"},{"id":"enl_2aaaaaaaaaa","item":"B_KEY","status":"cancelled","reason":"value-changed"},{"id":"enl_3\u001b[31m","item":"C_KEY","status":"pending"}]}`)
		default:
			w.WriteHeader(201)
			_, _ = io.WriteString(w, s.answer)
		}
	})
	return s
}

func TestValuesAsk(t *testing.T) {
	for what, c := range map[string]struct {
		args []string
		body string
	}{
		"a member":   {[]string{"A_KEY"}, `{"item":"A_KEY"}`},
		"one person": {[]string{"A_KEY", "--for", "idn_x"}, `{"item":"A_KEY","restrictedTo":"identity","identityId":"idn_x"}`},
		"anyone":     {[]string{"A_KEY", "--anyone"}, `{"item":"A_KEY","restrictedTo":"anyone"}`},
		"all of it": {[]string{"A_KEY", "--replace", "A_KEY", "--totp", "--description", "The key.", "--ttl", "60"},
			`{"item":"A_KEY","replace":true,"accepts":"otpauth","description":"The key.","ttlSeconds":60}`},
	} {
		t.Run(what, func(t *testing.T) {
			s := newAskServer(t)
			code, stdout, stderr := runIn(t, s.valuesServer, "", nil, nil, append([]string{"values", "ask"}, c.args...)...)
			if code != 0 || !strings.Contains(stdout, "https://varlatch.example/entry#"+askToken+"\n") || strings.Count(stdout, askToken) != 1 || strings.Contains(stderr, askToken) {
				t.Errorf("%d %q %q", code, stdout, stderr)
			}
			if want := "POST " + envPath + "/entry-links " + c.body; len(s.sent) != 1 || s.sent[0] != want {
				t.Errorf("%q, want %s", s.sent, want)
			}
		})
	}
}

func TestValuesAskRefuses(t *testing.T) {
	for what, c := range map[string]struct {
		args   []string
		server func(*askServer)
		says   string
		sends  int
	}{
		"nothing":                 {[]string{"values", "ask"}, nil, "Usage: varlatch values ask", 0},
		"both":                    {[]string{"values", "ask", "A_KEY", "--anyone", "--for", "idn_x"}, nil, "give one of them", 0},
		"another to replace":      {[]string{"values", "ask", "A_KEY", "--replace", "B_KEY"}, nil, "never covers another", 0},
		"too long":                {[]string{"values", "ask", "A_KEY", "--ttl", "3601"}, nil, "60 to 3600", 0},
		"no number":               {[]string{"values", "ask", "A_KEY", "--ttl", "1e2"}, nil, "60 to 3600", 0},
		"a value":                 {[]string{"values", "ask", "A_KEY", "made-up-value"}, nil, "", 0},
		"an unknown option":       {[]string{"values", "ask", "A_KEY", "--env", "production"}, nil, "unknown option at argument 2", 0},
		"anyone, in assisted":     {[]string{"--assisted", "values", "ask", "A_KEY", "--anyone"}, nil, "No link was made", 0},
		"an older server":         {[]string{"values", "ask", "A_KEY"}, func(s *askServer) { s.capabilities = `"values.totp"` }, "has no entry links", 0},
		"another token":           {[]string{"values", "ask", "A_KEY"}, func(s *askServer) { s.answer = strings.ReplaceAll(s.answer, "vlt_entry_", "vlt_cli_") }, "no link is printed", 1},
		"no address":              {[]string{"values", "ask", "A_KEY"}, func(s *askServer) { s.answer = strings.ReplaceAll(s.answer, "https:", "javascript:") }, "no link is printed", 1},
		"control characters":      {[]string{"values", "ask", "A_KEY"}, func(s *askServer) { s.answer = strings.ReplaceAll(s.answer, "varlatch.example", "varlatch\\u001b[31m") }, "no link is printed", 1},
		"cancel an address":       {[]string{"values", "ask-cancel", "https://varlatch.example/entry#" + askToken}, nil, "give the link's ID", 0},
		"cancel without":          {[]string{"values", "ask-cancel"}, nil, "Usage: varlatch values ask-cancel", 0},
		"list with a positional":  {[]string{"values", "asked", "A_KEY"}, nil, "", 0},
		"usage, of what is ours":  {[]string{"values"}, nil, "Usage: varlatch values <set|list|delete|rotate|rotate-complete>", 0},
		"a path in the link's ID": {[]string{"values", "ask-cancel", "enl_../../grants/x"}, nil, "give the link's ID", 0},
	} {
		t.Run(what, func(t *testing.T) {
			s := newAskServer(t)
			if c.server != nil {
				c.server(s)
			}
			code, stdout, stderr := runIn(t, s.valuesServer, "", nil, nil, c.args...)
			if code == 0 || !strings.Contains(stderr+stdout, c.says) || len(s.sent) != c.sends {
				t.Errorf("%d %q %q, sent %q", code, stdout, stderr, s.sent)
			}
			for _, secret := range []string{askToken, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", "made-up-value"} {
				if strings.Contains(stdout+stderr, secret) {
					t.Errorf("shown: %q %q", stdout, stderr)
				}
			}
		})
	}
}

// A server that answers with a credential this run holds gets nothing printed.
func TestValuesAskPrintsNoCredential(t *testing.T) {
	s := newAskServer(t)
	code, stdout, stderr := runIn(t, s.valuesServer, "", nil, map[string]string{"VARLATCH_TOKEN": askToken}, "values", "ask", "A_KEY")
	if code == 0 || strings.Contains(stdout+stderr, askToken) || !strings.Contains(stderr, "no link is printed") {
		t.Errorf("%d %q %q", code, stdout, stderr)
	}
}

func TestValuesAskedAndCancel(t *testing.T) {
	s := newAskServer(t)
	code, stdout, _ := runIn(t, s.valuesServer, "", nil, nil, "values", "asked")
	if code != 0 || !strings.Contains(stdout, "A_KEY  entered  enl_1aaaaaaaaaa\nB_KEY  cancelled: the value changed first  enl_2aaaaaaaaaa\nC_KEY  waiting") || strings.Contains(stdout, "\x1b") {
		t.Errorf("%d %q", code, stdout)
	}
	code, stdout, _ = runIn(t, s.valuesServer, "", nil, nil, "values", "asked", "--json")
	if code != 0 || !strings.Contains(stdout, `"status": "entered"`) {
		t.Errorf("%d %q", code, stdout)
	}
	code, stdout, _ = runIn(t, s.valuesServer, "", nil, nil, "values", "ask-cancel", "enl_abcdefghij")
	if code != 0 || s.sent[len(s.sent)-1] != "DELETE "+envPath+"/entry-links/enl_abcdefghij " {
		t.Errorf("%d %q %q", code, stdout, s.sent)
	}
}
