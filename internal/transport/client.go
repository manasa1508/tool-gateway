// Package transport contains bounded upstream clients. It never retries actions.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manasa1508/tool-gateway/internal/policy"
	"github.com/manasa1508/tool-gateway/internal/wire"
)

type Client interface {
	Call(context.Context, string, map[string]any) (map[string]any, error)
	Notify(context.Context, string, map[string]any) error
	Close() error
}
type Factory func(policy.Server, int) (Client, error)

func New(s policy.Server, max int) (Client, error) {
	if s.URL != "" {
		return newHTTP(s, max)
	}
	return newProcess(s, max)
}
func response(b []byte, id string) (map[string]any, error) {
	m, e := wire.Object(b)
	if e != nil {
		return nil, e
	}
	if m["jsonrpc"] != "2.0" || m["id"] != id || m["method"] != nil {
		return nil, errors.New("unexpected upstream envelope")
	}
	_, hasResult := m["result"]
	_, hasError := m["error"]
	if hasResult == hasError {
		return nil, errors.New("invalid upstream response")
	}
	if hasError {
		return nil, errors.New("upstream returned a protocol error")
	}
	r, ok := m["result"].(map[string]any)
	if !ok {
		return nil, errors.New("upstream result must be an object")
	}
	return r, nil
}

type process struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	in       io.WriteCloser
	messages chan []byte
	done     chan struct{}
	once     sync.Once
	dir      string
	seq      uint64
	max      int
}

func newProcess(s policy.Server, max int) (Client, error) {
	dir, e := os.MkdirTemp("", "tool-gateway-upstream-")
	if e != nil {
		return nil, e
	}
	cmd := exec.Command(s.Command[0], s.Command[1:]...)
	cmd.Dir = dir
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=/usr/bin:/bin"}
	for _, k := range s.Env {
		v, ok := os.LookupEnv(k)
		if !ok {
			os.RemoveAll(dir)
			return nil, errors.New("required upstream environment variable missing")
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = io.Discard
	in, e := cmd.StdinPipe()
	if e != nil {
		os.RemoveAll(dir)
		return nil, e
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		in.Close()
		os.RemoveAll(dir)
		return nil, e
	}
	if e = cmd.Start(); e != nil {
		in.Close()
		out.Close()
		os.RemoveAll(dir)
		return nil, e
	}
	p := &process{cmd: cmd, in: in, messages: make(chan []byte, 4), done: make(chan struct{}), dir: dir, max: max}
	go func() {
		defer close(p.messages)
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 4096), max)
		for s.Scan() {
			b := append([]byte{}, s.Bytes()...)
			select {
			case p.messages <- b:
			case <-p.done:
				return
			}
		}
	}()
	return p, nil
}
func (p *process) Close() error {
	p.once.Do(func() {
		close(p.done)
		p.in.Close()
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		_ = os.RemoveAll(p.dir)
	})
	return nil
}
func (p *process) write(ctx context.Context, v any) error {
	b := append(wire.Canonical(v), '\n')
	if len(b) > p.max {
		return errors.New("upstream request too large")
	}
	ch := make(chan error, 1)
	go func() { _, e := p.in.Write(b); ch <- e }()
	select {
	case e := <-ch:
		if e != nil {
			p.Close()
		}
		return e
	case <-ctx.Done():
		p.Close()
		return ctx.Err()
	case <-p.done:
		return errors.New("upstream unavailable")
	}
}
func (p *process) Call(ctx context.Context, method string, params map[string]any) (map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seq++
	id := strconv.FormatUint(p.seq, 10)
	if e := p.write(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
		return nil, e
	}
	for i := 0; i < 32; i++ {
		select {
		case b, ok := <-p.messages:
			if !ok {
				p.Close()
				return nil, errors.New("upstream closed or frame limit exceeded")
			}
			m, e := wire.Object(b)
			if e != nil {
				p.Close()
				return nil, errors.New("malformed upstream message")
			}
			if m["method"] != nil {
				if reverseID, exists := m["id"]; exists {
					if !wire.ValidID(reverseID) {
						p.Close()
						return nil, errors.New("invalid reverse request")
					}
					if e = p.write(ctx, wire.Error(reverseID, -32601, "server-initiated methods disabled by gateway policy")); e != nil {
						return nil, e
					}
				}
				continue
			}
			r, e := response(b, id)
			if e != nil {
				p.Close()
			}
			return r, e
		case <-ctx.Done():
			p.Close()
			return nil, ctx.Err()
		case <-p.done:
			return nil, errors.New("upstream unavailable")
		}
	}
	p.Close()
	return nil, errors.New("upstream message flood")
}
func (p *process) Notify(ctx context.Context, method string, params map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.write(ctx, map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

type remote struct {
	mu                  sync.Mutex
	client              *http.Client
	url, token, session string
	seq                 uint64
	max                 int
	closed              bool
}

func newHTTP(s policy.Server, max int) (Client, error) {
	token := ""
	if s.TokenEnv != "" {
		token = os.Getenv(s.TokenEnv)
		if token == "" {
			return nil, errors.New("upstream token environment variable missing")
		}
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, MaxIdleConns: 8, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second, DisableCompression: true}
	return &remote{client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("upstream redirect denied") }}, url: s.URL, token: token, max: max}, nil
}
func (r *remote) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.client.CloseIdleConnections()
	return nil
}
func (r *remote) send(ctx context.Context, m map[string]any) (*http.Response, error) {
	if r.closed {
		return nil, errors.New("upstream circuit is closed")
	}
	b := wire.Canonical(m)
	if len(b) > r.max {
		return nil, errors.New("request exceeds frame limit")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	if r.session != "" {
		req.Header.Set("Mcp-Session-Id", r.session)
	}
	resp, e := r.client.Do(req)
	if e != nil {
		r.closed = true
		return nil, e
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		r.closed = true
		return nil, fmt.Errorf("upstream HTTP status %d", resp.StatusCode)
	}
	if session := resp.Header.Get("Mcp-Session-Id"); session != "" {
		if len(session) > 128 || strings.ContainsAny(session, "\r\n") {
			resp.Body.Close()
			return nil, errors.New("invalid upstream session")
		}
		if r.session != "" && r.session != session {
			resp.Body.Close()
			r.closed = true
			return nil, errors.New("upstream changed session")
		}
		r.session = session
	}
	return resp, nil
}
func (r *remote) Call(ctx context.Context, method string, params map[string]any) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	id := strconv.FormatUint(r.seq, 10)
	resp, e := r.send(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	typ, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var b []byte
	if typ == "application/json" {
		b, e = io.ReadAll(io.LimitReader(resp.Body, int64(r.max)+1))
		if len(b) > r.max {
			e = errors.New("upstream response limit")
		}
	} else if typ == "text/event-stream" {
		b, e = readSSE(resp.Body, id, r.max)
	} else {
		e = errors.New("unsupported upstream content type")
	}
	if e != nil {
		r.closed = true
		return nil, e
	}
	v, e := response(b, id)
	if e != nil {
		r.closed = true
	}
	return v, e
}
func (r *remote) Notify(ctx context.Context, method string, params map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	resp, e := r.send(ctx, map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		r.closed = true
		return errors.New("notification must receive HTTP 202")
	}
	return nil
}
func readSSE(body io.Reader, id string, max int) ([]byte, error) {
	s := bufio.NewScanner(io.LimitReader(body, int64(max)*4))
	s.Buffer(make([]byte, 4096), max)
	data := []byte{}
	events := 0
	for s.Scan() {
		line := s.Text()
		if line == "" {
			if len(data) > 0 {
				events++
				if events > 32 {
					return nil, errors.New("SSE event limit")
				}
				m, e := wire.Object(data)
				if e != nil {
					return nil, e
				}
				if m["id"] == id && m["method"] == nil {
					return data, nil
				}
				if m["method"] != nil && m["id"] != nil {
					return nil, errors.New("reverse requests are unsupported")
				}
				data = nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")...)
			if len(data) > max {
				return nil, errors.New("SSE frame limit")
			}
		}
	}
	return nil, errors.New("SSE response ended without matching result")
}
