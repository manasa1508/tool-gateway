package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

type slot struct {
	task    *Task
	expires time.Time
	active  int
}
type HTTP struct {
	engine           *Engine
	token            string
	mu               sync.Mutex
	sessions         map[string]*slot
	closed           bool
	requests, denied atomic.Uint64
}

func NewHTTP(e *Engine) (*HTTP, error) {
	token := os.Getenv(e.Policy.TokenEnv)
	if len(token) < 32 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("gateway bearer token must contain at least 32 characters")
	}
	return &HTTP{engine: e, token: token, sessions: map[string]*slot{}}, nil
}
func (h *HTTP) authorized(r *http.Request) bool {
	want := "Bearer " + h.token
	got := r.Header.Get("Authorization")
	return len(want) == len(got) && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.requests.Add(1)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if origin := r.Header.Get("Origin"); origin != "" {
		allowed := false
		for _, o := range h.engine.Policy.Origins {
			if origin == o {
				allowed = true
			}
		}
		if !allowed {
			h.denied.Add(1)
			http.Error(w, "origin denied", http.StatusForbidden)
			return
		}
	}
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
		h.mu.Lock()
		ready := !h.closed
		h.mu.Unlock()
		if !ready || !h.engine.Journal.Healthy() {
			http.Error(w, "not ready", 503)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
		return
	}
	if !h.authorized(r) {
		h.denied.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="tool-gateway"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/metrics" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		h.mu.Lock()
		n := len(h.sessions)
		h.mu.Unlock()
		_, _ = io.WriteString(w, "# TYPE tool_gateway_http_requests_total counter\ntool_gateway_http_requests_total "+strconv.FormatUint(h.requests.Load(), 10)+"\n# TYPE tool_gateway_http_denied_total counter\ntool_gateway_http_denied_total "+strconv.FormatUint(h.denied.Load(), 10)+"\n# TYPE tool_gateway_sessions gauge\ntool_gateway_sessions "+strconv.Itoa(n)+"\n")
		return
	}
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", 405)
		return
	}
	h.reap()
	sessionID := r.Header.Get("Mcp-Session-Id")
	if r.Method == http.MethodDelete {
		h.mu.Lock()
		s, ok := h.sessions[sessionID]
		busy := ok && s.active > 0
		if ok && s.active == 0 {
			delete(h.sessions, sessionID)
		}
		h.mu.Unlock()
		if !ok {
			http.Error(w, "unknown session", 404)
			return
		}
		if busy {
			http.Error(w, "session busy", 409)
			return
		}
		s.task.Close()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	typ, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if typ != "application/json" {
		http.Error(w, "application/json required", 415)
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "application/json") || !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "Accept must include application/json and text/event-stream", 406)
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && v != Protocol {
		http.Error(w, "unsupported protocol version", 400)
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(h.engine.Policy.Limits.MaxMessageBytes)))
	if e != nil {
		http.Error(w, "request body limit exceeded", 413)
		return
	}
	m, e := wire.Object(b)
	if e != nil {
		writeJSON(w, 400, wire.Error(nil, -32700, "invalid or ambiguous JSON"))
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "gateway shutting down", 503)
		return
	}
	var s *slot
	if sessionID == "" {
		if m["method"] != "initialize" {
			h.mu.Unlock()
			http.Error(w, "initialize required", 400)
			return
		}
		if len(h.sessions) >= h.engine.Policy.Limits.MaxSessions {
			h.mu.Unlock()
			http.Error(w, "session capacity exhausted", 503)
			return
		}
		t := h.engine.NewTask(h.engine.Policy.Principal)
		s = &slot{task: t}
		sessionID = t.ID
		h.sessions[sessionID] = s
	} else {
		var ok bool
		s, ok = h.sessions[sessionID]
		if !ok {
			h.mu.Unlock()
			http.Error(w, "unknown or expired session", 404)
			return
		}
		if r.Header.Get("MCP-Protocol-Version") != Protocol {
			h.mu.Unlock()
			http.Error(w, "MCP-Protocol-Version header required", 400)
			return
		}
	}
	s.active++
	s.expires = time.Now().Add(time.Duration(h.engine.Policy.Limits.SessionTTLSeconds) * time.Second)
	h.mu.Unlock()
	result := s.task.Handle(r.Context(), b)
	h.mu.Lock()
	s.active--
	failedInit := m["method"] == "initialize" && (result == nil || result["error"] != nil)
	if failedInit {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
	if failedInit {
		s.task.Close()
	} else {
		w.Header().Set("Mcp-Session-Id", sessionID)
	}
	if result == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, 200, result)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(wire.Canonical(v))
}
func (h *HTTP) reap() {
	now := time.Now()
	expired := []*Task{}
	h.mu.Lock()
	for id, s := range h.sessions {
		if s.active == 0 && s.expires.Before(now) {
			delete(h.sessions, id)
			expired = append(expired, s.task)
		}
	}
	h.mu.Unlock()
	for _, t := range expired {
		t.Close()
	}
}
func (h *HTTP) Close() {
	h.mu.Lock()
	h.closed = true
	tasks := []*Task{}
	for _, s := range h.sessions {
		tasks = append(tasks, s.task)
	}
	h.sessions = map[string]*slot{}
	h.mu.Unlock()
	for _, t := range tasks {
		t.Close()
	}
}
func (h *HTTP) Sweep(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.reap()
		}
	}
}
func Serve(ctx context.Context, h *HTTP) error {
	// TLS terminates at a trusted ingress. Keep HTTP loopback-bound by default.
	ln, e := net.Listen("tcp", h.engine.Policy.Listen)
	if e != nil {
		return e
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: time.Duration(h.engine.Policy.Limits.RequestTimeoutMS)*time.Millisecond + 5*time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	go h.Sweep(ctx)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			h.Close()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-stopped:
		}
	}()
	e = server.Serve(ln)
	close(stopped)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
