package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

const testToken = "test-token-value-with-at-least-32-characters"

func httpFixture(t *testing.T) (*HTTP, *fixture) {
	f := setup(t, "strict")
	t.Setenv("GATEWAY_TEST_TOKEN", testToken)
	h, e := NewHTTP(f.engine)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(h.Close)
	return h, f
}
func httpRequest(h *HTTP, method, path, body, session string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if auth {
		r.Header.Set("Authorization", "Bearer "+testToken)
	}
	if session != "" {
		r.Header.Set("Mcp-Session-Id", session)
		r.Header.Set("MCP-Protocol-Version", Protocol)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func initializeHTTP(t *testing.T, h *HTTP) string {
	t.Helper()
	w := httpRequest(h, "POST", "/mcp", `{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2025-11-25"}}`, "", true)
	if w.Code != 200 || w.Header().Get("Mcp-Session-Id") == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	return w.Header().Get("Mcp-Session-Id")
}
func TestHTTPAuthenticationAndOrigin(t *testing.T) {
	h, _ := httpFixture(t)
	for _, path := range []string{"/mcp", "/metrics"} {
		w := httpRequest(h, "POST", path, `{}`, "", false)
		if w.Code != 401 {
			t.Fatal("unauthenticated request accepted", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted origin accepted")
	}
	if w := httpRequest(h, "GET", "/healthz", "", "", false); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := httpRequest(h, "GET", "/readyz", "", "", false); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestHTTPSessions(t *testing.T) {
	h, _ := httpFixture(t)
	id := initializeHTTP(t, h)
	w := httpRequest(h, "POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, id, true)
	if w.Code != 202 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httpRequest(h, "POST", "/mcp", `{"jsonrpc":"2.0","id":"2","method":"tools/list"}`, id, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Operator-owned") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = httpRequest(h, "GET", "/mcp", "", id, true); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w = httpRequest(h, "GET", "/metrics", "", "", true); w.Code != 200 || !strings.Contains(w.Body.String(), "tool_gateway_sessions 1") {
		t.Fatal(w.Code)
	}
	if w = httpRequest(h, "DELETE", "/mcp", "", id, true); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w = httpRequest(h, "POST", "/mcp", `{"jsonrpc":"2.0","id":"3","method":"ping"}`, id, true); w.Code != 404 {
		t.Fatal("terminated session accepted")
	}
}
func TestHTTPLimits(t *testing.T) {
	for _, kind := range []string{"duplicateJSON", "oversize", "capacity", "noSession", "expired", "wrongVersion", "contentType", "accept", "shutdown"} {
		t.Run(kind, func(t *testing.T) {
			h, f := httpFixture(t)
			body := `{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2025-11-25"}}`
			session := ""
			want := 400
			switch kind {
			case "duplicateJSON":
				body = `{"x":1,"x":2}`
			case "oversize":
				body = strings.Repeat("x", f.engine.Policy.Limits.MaxMessageBytes+1)
				want = 413
			case "capacity":
				f.engine.Policy.Limits.MaxSessions = 1
				initializeHTTP(t, h)
				want = 503
			case "noSession":
				body = `{"jsonrpc":"2.0","id":"1","method":"ping"}`
			case "expired":
				session = initializeHTTP(t, h)
				h.mu.Lock()
				h.sessions[session].expires = time.Now().Add(-time.Second)
				h.mu.Unlock()
				want = 404
			case "shutdown":
				h.Close()
				want = 503
			}
			r := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(body))
			r.Header.Set("Authorization", "Bearer "+testToken)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			if session != "" {
				r.Header.Set("Mcp-Session-Id", session)
				r.Header.Set("MCP-Protocol-Version", Protocol)
			}
			switch kind {
			case "wrongVersion":
				r.Header.Set("MCP-Protocol-Version", "2026-07-28")
			case "contentType":
				r.Header.Set("Content-Type", "text/plain")
				want = 415
			case "accept":
				r.Header.Set("Accept", "text/html")
				want = 406
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal(kind, w.Code, w.Body.String())
			}
		})
	}
}
func TestHTTPReadinessFailsOnAuditFailure(t *testing.T) {
	h, f := httpFixture(t)
	f.engine.Journal.Close()
	w := httpRequest(h, http.MethodGet, "/readyz", "", "", false)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
func TestTaskRequestValidation(t *testing.T) {
	f := setup(t, "strict")
	for _, s := range []string{`[]`, `{"jsonrpc":"2.0","id":null,"method":"ping"}`, `{"jsonrpc":"2.0","id":true,"method":"ping"}`, `{"jsonrpc":"2.0","id":"x","method":"ping","params":[]}`, `{"jsonrpc":"2.0","id":"x","method":"ping","unknown":true}`, `{"jsonrpc":"1.0","id":"x","method":"ping"}`} {
		rejected(t, f.task.Handle(context.Background(), []byte(s)))
	}
	r := f.task.Handle(context.Background(), wire.Canonical(map[string]any{"jsonrpc": "2.0", "id": "good", "method": "ping"}))
	success(t, r)
}
