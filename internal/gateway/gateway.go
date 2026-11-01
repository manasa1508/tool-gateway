// Package gateway is the common enforcement path used by stdio and HTTP.
package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/manasa1508/tool-gateway/internal/approval"
	"github.com/manasa1508/tool-gateway/internal/audit"
	"github.com/manasa1508/tool-gateway/internal/policy"
	"github.com/manasa1508/tool-gateway/internal/scan"
	"github.com/manasa1508/tool-gateway/internal/schema"
	"github.com/manasa1508/tool-gateway/internal/transport"
	"github.com/manasa1508/tool-gateway/internal/wire"
)

const Protocol = "2025-11-25"
const Version = "0.1.0"

type Engine struct {
	Policy  *policy.Config
	Journal *audit.Journal
	Factory transport.Factory
}
type registered struct {
	server, name, hash string
	schema             map[string]any
	contract           policy.Tool
}
type contextEntry struct {
	server, name, hash string
	contract           policy.Context
}
type Task struct {
	engine                     *Engine
	ID                         string
	Principal                  string
	gate                       chan struct{}
	cancel                     context.CancelFunc
	lifetime                   context.Context
	clients                    map[string]transport.Client
	initialized, ready, closed bool
	registry                   map[string]registered
	toolsLoaded                bool
	contextLoaded              map[string]bool
	resources, prompts         map[string]contextEntry
	labels                     map[string]bool
	calls                      int
	counts                     map[string]int
	output                     int
	ids                        map[string]bool
}

func (e *Engine) NewTask(principal string) *Task {
	ctx, cancel := context.WithCancel(context.Background())
	return &Task{engine: e, ID: approval.ID(), Principal: principal, gate: make(chan struct{}, 1), lifetime: ctx, cancel: cancel, clients: map[string]transport.Client{}, registry: map[string]registered{}, contextLoaded: map[string]bool{}, resources: map[string]contextEntry{}, prompts: map[string]contextEntry{}, labels: map[string]bool{}, counts: map[string]int{}, ids: map[string]bool{}}
}

// Close cancels an in-flight call before acquiring the task gate.
func (t *Task) Close() {
	t.cancel()
	t.gate <- struct{}{}
	defer func() { <-t.gate }()
	t.closed = true
	for _, c := range t.clients {
		_ = c.Close()
	}
}
func Alias(server, name string) string {
	alias := "tg_" + wire.Hash([]string{server, name})[:32]
	if policy.Name.MatchString(name) {
		return alias + "_" + name
	}
	return alias
}
func (t *Task) event(server, tool, decision string, r scan.Report) audit.Event {
	return audit.Event{Principal: t.Principal, Task: t.ID, Server: server, Tool: tool, Decision: decision, Policy: t.engine.Policy.Hash, Findings: r.IDs(), Score: r.Score}
}
func (t *Task) deny(id any, reason string, r scan.Report) map[string]any {
	if e := t.engine.Journal.Append(t.event("", "", reason, r)); e != nil {
		return wire.Error(id, -32603, "audit unavailable; gateway failed closed")
	}
	return wire.Error(id, -32001, reason)
}
func (t *Task) Handle(ctx context.Context, b []byte) map[string]any {
	if len(b) > t.engine.Policy.Limits.MaxMessageBytes {
		return wire.Error(nil, -32600, "message limit exceeded")
	}
	m, e := wire.Object(b)
	if e != nil {
		return wire.Error(nil, -32700, "invalid or ambiguous JSON")
	}
	id, hasID := m["id"]
	method := wire.String(m["method"])
	if m["jsonrpc"] != "2.0" || method == "" || hasID && !wire.ValidID(id) {
		return wire.Error(nil, -32600, "invalid JSON-RPC request")
	}
	for k := range m {
		if k != "jsonrpc" && k != "id" && k != "method" && k != "params" {
			return wire.Error(id, -32600, "unsupported envelope field")
		}
	}
	p := map[string]any{}
	if x, ok := m["params"]; ok {
		p, ok = x.(map[string]any)
		if !ok {
			return wire.Error(id, -32602, "params must be an object")
		}
	}
	select {
	case t.gate <- struct{}{}:
		defer func() { <-t.gate }()
	default:
		return wire.Error(id, -32005, "task busy; request was not executed")
	}
	if t.closed || t.lifetime.Err() != nil {
		return wire.Error(id, -32004, "task closed")
	}
	if !t.engine.Journal.Healthy() {
		return wire.Error(id, -32603, "audit unavailable; gateway failed closed")
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(t.engine.Policy.Limits.RequestTimeoutMS)*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(t.lifetime, cancel)
	defer stop()
	if !hasID {
		if method == "notifications/initialized" && t.initialized && !t.ready {
			for _, c := range t.clients {
				if e = c.Notify(callCtx, method, map[string]any{}); e != nil {
					t.closed = true
					return nil
				}
			}
			t.ready = true
		}
		return nil
	}
	// Reusing request IDs is disallowed to avoid accidental action replay.
	key := string(wire.Canonical(id))
	if t.ids[key] {
		return t.deny(id, "duplicate request id", scan.Report{})
	}
	if len(t.ids) >= 4096 {
		return t.deny(id, "request budget exceeded", scan.Report{})
	}
	t.ids[key] = true
	switch method {
	case "initialize":
		return t.initialize(callCtx, id, p)
	case "ping":
		return wire.RPC(id, map[string]any{})
	case "server/discover":
		r := wire.Error(id, -32022, "supported protocol profile is 2025-11-25; initialize required")
		wire.Map(r["error"])["data"] = map[string]any{"supported": []string{Protocol}}
		return r
	}
	if !t.ready {
		return t.deny(id, "initialize and notifications/initialized required", scan.Report{})
	}
	switch method {
	case "tools/list":
		if !only(p, "_meta") {
			return wire.Error(id, -32602, "pagination is handled by gateway")
		}
		return t.listTools(callCtx, id)
	case "tools/call":
		return t.callTool(callCtx, id, p)
	case "resources/list":
		return t.listContext(callCtx, id, "resources")
	case "prompts/list":
		return t.listContext(callCtx, id, "prompts")
	case "resources/read":
		return t.readContext(callCtx, id, p, "resources")
	case "prompts/get":
		return t.readContext(callCtx, id, p, "prompts")
	default:
		return wire.Error(id, -32601, "method disabled by gateway policy")
	}
}
func only(m map[string]any, keys ...string) bool {
	for k := range m {
		found := false
		for _, a := range keys {
			if k == a {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (t *Task) initialize(ctx context.Context, id any, p map[string]any) map[string]any {
	if t.initialized {
		return t.deny(id, "task already initialized", scan.Report{})
	}
	if wire.String(p["protocolVersion"]) != Protocol {
		r := wire.Error(id, -32022, "unsupported protocol version")
		wire.Map(r["error"])["data"] = map[string]any{"supported": []string{Protocol}, "requested": wire.String(p["protocolVersion"])}
		return r
	}
	names := sortedServers(t.engine.Policy.Servers)
	for _, name := range names {
		s := t.engine.Policy.Servers[name]
		c, e := t.engine.Factory(s, t.engine.Policy.Limits.MaxMessageBytes)
		if e != nil {
			return t.initFailure(id)
		}
		t.clients[name] = c
		r, e := c.Call(ctx, "initialize", map[string]any{"protocolVersion": Protocol, "clientInfo": map[string]any{"name": "tool-gateway", "version": Version}, "capabilities": map[string]any{}})
		if e != nil || r["protocolVersion"] != Protocol {
			return t.initFailure(id)
		}
	}
	if e := t.engine.Journal.Append(t.event("", "", "initialized", scan.Report{})); e != nil {
		return t.initFailure(id)
	}
	t.initialized = true
	return wire.RPC(id, map[string]any{"protocolVersion": Protocol, "serverInfo": map[string]any{"name": "tool-gateway", "version": Version}, "capabilities": map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}}, "_meta": map[string]any{"io.toolgateway/task": t.ID, "io.toolgateway/policy": t.engine.Policy.Hash}})
}
func (t *Task) initFailure(id any) map[string]any {
	for _, c := range t.clients {
		_ = c.Close()
	}
	t.closed = true
	return wire.Error(id, -32603, "upstream initialization failed; task closed")
}
func sortedServers(m map[string]policy.Server) []string {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func fetchList(ctx context.Context, c transport.Client, kind string) ([]map[string]any, error) {
	all := []map[string]any{}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 16; page++ {
		p := map[string]any{}
		if cursor != "" {
			p["cursor"] = cursor
		}
		r, e := c.Call(ctx, kind+"/list", p)
		if e != nil {
			return nil, e
		}
		a, ok := r[kind].([]any)
		if !ok {
			return nil, errors.New("invalid list result")
		}
		for _, v := range a {
			m, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("invalid list entry")
			}
			all = append(all, m)
			if len(all) > 256 {
				return nil, errors.New("registry limit exceeded")
			}
		}
		v, exists := r["nextCursor"]
		if !exists {
			return all, nil
		}
		cursor = wire.String(v)
		if cursor == "" || len(cursor) > 1024 || seen[cursor] {
			return nil, errors.New("invalid pagination cursor")
		}
		seen[cursor] = true
	}
	return nil, errors.New("pagination limit exceeded")
}
func (t *Task) listTools(ctx context.Context, id any) map[string]any {
	next := map[string]registered{}
	views := []any{}
	for _, server := range sortedServers(t.engine.Policy.Servers) {
		raw, e := fetchList(ctx, t.clients[server], "tools")
		if e != nil {
			return t.deny(id, "tool discovery failed", scan.Report{})
		}
		seen := map[string]bool{}
		for _, v := range raw {
			name := wire.String(v["name"])
			if !policy.Name.MatchString(name) || seen[name] {
				return t.deny(id, "invalid or duplicate upstream tool name", scan.Report{})
			}
			seen[name] = true
			c, approved := t.engine.Policy.Servers[server].Tools[name]
			if !approved {
				continue
			}
			hash := wire.Hash(v)
			if c.SHA256 != "" && hash != c.SHA256 {
				return t.deny(id, "tool definition pin mismatch", scan.Report{})
			}
			report := scan.Analyze(v)
			if report.Reject(t.engine.Policy.Mode) {
				return t.deny(id, "tool metadata rejected", report)
			}
			s, e := schema.Rebuild(v["inputSchema"])
			if e != nil {
				return t.deny(id, "unsupported or unsafe tool schema", report)
			}
			alias := Alias(server, name)
			next[alias] = registered{server, name, hash, s, c}
			views = append(views, map[string]any{"name": alias, "description": c.Description, "inputSchema": s})
			if len(report.Findings) > 0 {
				if e = t.engine.Journal.Append(t.event(server, name, "metadata-profiled", report)); e != nil {
					return wire.Error(id, -32603, "audit unavailable")
				}
			}
		}
	}
	if t.engine.Policy.Mode == "strict" && t.toolsLoaded && !sameTools(t.registry, next) {
		return t.deny(id, "strict registry changed", scan.Report{})
	}
	t.registry = next
	t.toolsLoaded = true
	sort.Slice(views, func(i, j int) bool {
		return wire.String(wire.Map(views[i])["name"]) < wire.String(wire.Map(views[j])["name"])
	})
	return wire.RPC(id, map[string]any{"tools": views})
}
func sameTools(a, b map[string]registered) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k].hash != v.hash {
			return false
		}
	}
	return true
}
func (t *Task) reserve(id any, server, name string, args any, r scan.Report, nonce string, expires int64) map[string]any {
	if t.calls >= t.engine.Policy.Limits.MaxCalls {
		return t.deny(id, "task call budget exhausted", scan.Report{})
	}
	e := t.event(server, name, "call-intent", r)
	e.ArgsHash = wire.Hash(args)
	e.Nonce = nonce
	e.Expires = expires
	if err := t.engine.Journal.Consume(e); err != nil {
		if errors.Is(err, audit.ErrReplay) {
			return wire.Error(id, -32001, "approval already consumed")
		}
		return wire.Error(id, -32603, "audit unavailable or approval expired")
	}
	t.calls++
	return nil
}
func (t *Task) callTool(ctx context.Context, id any, p map[string]any) map[string]any {
	if !only(p, "name", "arguments", "_meta") {
		return wire.Error(id, -32602, "unsupported tool call fields")
	}
	alias := wire.String(p["name"])
	entry, ok := t.registry[alias]
	if !ok {
		return t.deny(id, "tool is not in the approved registry; list tools first", scan.Report{})
	}
	args := map[string]any{}
	if v, exists := p["arguments"]; exists {
		args, ok = v.(map[string]any)
		if !ok {
			return wire.Error(id, -32602, "arguments must be an object")
		}
	}
	if e := schema.Validate(entry.schema, args); e != nil {
		return t.deny(id, "arguments violate sanitized schema", scan.Report{})
	}
	report := scan.Analyze(args)
	if report.Secret {
		return t.deny(id, "credential-bearing arguments blocked", report)
	}
	if report.Reject(t.engine.Policy.Mode) {
		return t.deny(id, "outbound injection rejected", report)
	}
	c := entry.contract
	if e := policy.CheckURLs(c, args); e != nil {
		return t.deny(id, "destination blocked by contract", scan.Report{})
	}
	// Labels accumulate across all responses in a task. Contracts must explicitly
	// accept every label before data may flow into another tool invocation.
	for label := range t.labels {
		found := false
		for _, a := range c.Accepts {
			if label == a {
				found = true
			}
		}
		if !found {
			return t.deny(id, "task data-flow boundary blocked call", scan.Report{})
		}
	}
	if c.MaxCalls > 0 && t.counts[alias] >= c.MaxCalls {
		return t.deny(id, "per-tool call budget exhausted", scan.Report{})
	}
	var claims approval.Claims
	if c.RequireApproval || c.Effect == "write" {
		pub, _ := base64.StdEncoding.DecodeString(t.engine.Policy.ApprovalPublicKey)
		token := wire.String(wire.Map(p["_meta"])["io.toolgateway/approval"])
		want := approval.Claims{Principal: t.Principal, Task: t.ID, Server: entry.server, Tool: entry.name, ArgsHash: wire.Hash(args), Policy: t.engine.Policy.Hash}
		var e error
		claims, e = approval.Verify(ed25519.PublicKey(pub), token, want, time.Now())
		if e != nil {
			r := t.deny(id, "exact-action approval required", scan.Report{})
			wire.Map(r["error"])["data"] = map[string]any{"task": t.ID, "server": entry.server, "tool": entry.name, "args_hash": want.ArgsHash, "policy": want.Policy}
			return r
		}
	}
	if r := t.reserve(id, entry.server, entry.name, args, report, claims.Nonce, claims.Expires); r != nil {
		return r
	}
	t.counts[alias]++
	// Revalidate the full raw definition immediately before execution. This detects
	// advertised rug pulls; it cannot prove that server implementation code is stable.
	raw, e := fetchList(ctx, t.clients[entry.server], "tools")
	if e != nil {
		return t.deny(id, "pre-execution tool discovery failed", scan.Report{})
	}
	valid := definitionMatches(raw, "name", entry.name, entry.hash)
	if !valid {
		return t.deny(id, "tool changed before execution", scan.Report{})
	}
	result, e := t.clients[entry.server].Call(ctx, "tools/call", map[string]any{"name": entry.name, "arguments": args})
	if e != nil {
		return t.deny(id, "upstream action failed; outcome may be unknown; no retry performed", scan.Report{})
	}
	return t.deliver(id, entry.server, entry.name, result, "tool", c.Produces)
}
func (t *Task) deliver(id any, server, name string, result map[string]any, kind string, labels []string) map[string]any {
	report := scan.Analyze(result)
	if report.Secret {
		return t.deny(id, "credential-bearing response quarantined", report)
	}
	if report.Reject(t.engine.Policy.Mode) {
		return t.deny(id, "response injection quarantined", report)
	}
	clean, e := sanitizeResult(result, kind)
	if e != nil {
		return t.deny(id, "unsupported upstream result", report)
	}
	size := len(wire.Canonical(clean))
	if size+t.output > t.engine.Policy.Limits.MaxOutputBytes {
		return t.deny(id, "task output budget exhausted", report)
	}
	if e = t.engine.Journal.Append(t.event(server, name, "result-delivered", report)); e != nil {
		return wire.Error(id, -32603, "audit unavailable; response withheld")
	}
	t.output += size
	for _, l := range labels {
		t.labels[l] = true
	}
	return wire.RPC(id, clean)
}
func sanitizeContent(v any) ([]any, error) {
	a, ok := v.([]any)
	if !ok || len(a) > 128 {
		return nil, errors.New("invalid content")
	}
	out := []any{}
	for _, v := range a {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("invalid content block")
		}
		switch m["type"] {
		case "text":
			s, ok := m["text"].(string)
			if !ok {
				return nil, errors.New("text required")
			}
			out = append(out, map[string]any{"type": "text", "text": s})
		case "resource":
			r := wire.Map(m["resource"])
			s, ok := r["text"].(string)
			if !ok {
				continue
			}
			out = append(out, map[string]any{"type": "text", "text": s})
		default:
			continue
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no supported text content")
	}
	return out, nil
}
func sanitizeResult(r map[string]any, kind string) (map[string]any, error) {
	switch kind {
	case "tool":
		c, e := sanitizeContent(r["content"])
		if e != nil {
			return nil, e
		}
		out := map[string]any{"content": c}
		if v, ok := r["isError"].(bool); ok {
			out["isError"] = v
		}
		if s, ok := r["structuredContent"]; ok {
			out["structuredContent"] = s
		}
		return out, nil
	case "resources":
		a, ok := r["contents"].([]any)
		if !ok || len(a) > 128 {
			return nil, errors.New("invalid resources")
		}
		out := []any{}
		for _, v := range a {
			m := wire.Map(v)
			if s, ok := m["text"].(string); ok {
				out = append(out, map[string]any{"uri": wire.String(m["uri"]), "text": s, "mimeType": "text/plain"})
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no text resources")
		}
		return map[string]any{"contents": out}, nil
	case "prompts":
		a, ok := r["messages"].([]any)
		if !ok || len(a) > 128 {
			return nil, errors.New("invalid prompt messages")
		}
		out := []any{}
		for _, v := range a {
			m := wire.Map(v)
			role := wire.String(m["role"])
			if role != "user" && role != "assistant" {
				return nil, errors.New("invalid prompt role")
			}
			c, e := sanitizeContent([]any{m["content"]})
			if e != nil {
				return nil, e
			}
			for _, block := range c {
				out = append(out, map[string]any{"role": role, "content": block})
			}
		}
		return map[string]any{"messages": out}, nil
	}
	return nil, errors.New("unknown content kind")
}
func (t *Task) listContext(ctx context.Context, id any, kind string) map[string]any {
	next := map[string]contextEntry{}
	views := []any{}
	for _, server := range sortedServers(t.engine.Policy.Servers) {
		s := t.engine.Policy.Servers[server]
		contracts := s.Resources
		if kind == "prompts" {
			contracts = s.Prompts
		}
		if len(contracts) == 0 {
			continue
		}
		raw, e := fetchList(ctx, t.clients[server], kind)
		if e != nil {
			return t.deny(id, "context discovery failed", scan.Report{})
		}
		seen := map[string]bool{}
		for _, v := range raw {
			name := wire.String(v["uri"])
			if kind == "prompts" {
				name = wire.String(v["name"])
			}
			if name == "" || seen[name] {
				return t.deny(id, "invalid context registry", scan.Report{})
			}
			seen[name] = true
			c, approved := contracts[name]
			if !approved {
				continue
			}
			hash := wire.Hash(v)
			if c.SHA256 != "" && c.SHA256 != hash {
				return t.deny(id, "context definition pin mismatch", scan.Report{})
			}
			report := scan.Analyze(v)
			if report.Reject(t.engine.Policy.Mode) {
				return t.deny(id, "context metadata rejected", report)
			}
			alias := Alias(server, name)
			next[alias] = contextEntry{server, name, hash, c}
			view := map[string]any{"name": alias, "description": c.Description}
			if kind == "resources" {
				view["uri"] = "tool-gateway://" + alias
				view["mimeType"] = "text/plain"
			} else {
				args := []any{}
				keys := []string{}
				for k := range c.Arguments {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					args = append(args, map[string]any{"name": k, "required": c.Arguments[k]})
				}
				view["arguments"] = args
			}
			views = append(views, view)
		}
	}
	old := t.resources
	if kind == "prompts" {
		old = t.prompts
	}
	if t.engine.Policy.Mode == "strict" && t.contextLoaded[kind] {
		if len(old) != len(next) {
			return t.deny(id, "strict context registry changed", scan.Report{})
		}
		for k, v := range old {
			if next[k].hash != v.hash {
				return t.deny(id, "strict context registry changed", scan.Report{})
			}
		}
	}
	if kind == "prompts" {
		t.prompts = next
	} else {
		t.resources = next
	}
	t.contextLoaded[kind] = true
	sort.Slice(views, func(i, j int) bool {
		return wire.String(wire.Map(views[i])["name"]) < wire.String(wire.Map(views[j])["name"])
	})
	return wire.RPC(id, map[string]any{kind: views})
}
func (t *Task) readContext(ctx context.Context, id any, p map[string]any, kind string) map[string]any {
	alias := strings.TrimPrefix(wire.String(p["uri"]), "tool-gateway://")
	registry := t.resources
	params := map[string]any{}
	method := "resources/read"
	if kind == "prompts" {
		if !only(p, "name", "arguments", "_meta") {
			return wire.Error(id, -32602, "unsupported prompt fields")
		}
		alias = wire.String(p["name"])
		registry = t.prompts
		method = "prompts/get"
	} else if !only(p, "uri", "_meta") {
		return wire.Error(id, -32602, "unsupported resource fields")
	}
	c, ok := registry[alias]
	if !ok {
		return t.deny(id, "context not in approved registry", scan.Report{})
	}
	if kind == "resources" {
		params["uri"] = c.name
	} else {
		params["name"] = c.name
		a := map[string]any{}
		if v, exists := p["arguments"]; exists {
			a, ok = v.(map[string]any)
			if !ok {
				return wire.Error(id, -32602, "prompt arguments must be object")
			}
		}
		for k, v := range a {
			if _, ok := c.contract.Arguments[k]; !ok {
				return t.deny(id, "unapproved prompt argument", scan.Report{})
			}
			if _, ok := v.(string); !ok {
				return wire.Error(id, -32602, "prompt values must be strings")
			}
		}
		for k, required := range c.contract.Arguments {
			if _, ok := a[k]; required && !ok {
				return wire.Error(id, -32602, "missing prompt argument")
			}
		}
		params["arguments"] = a
	}
	report := scan.Analyze(params)
	if report.Secret || report.Reject(t.engine.Policy.Mode) {
		return t.deny(id, "outbound context arguments rejected", report)
	}
	if len(t.labels) > 0 {
		return t.deny(id, "context request blocked after labeled data exposure", scan.Report{})
	}
	if r := t.reserve(id, c.server, c.name, params, report, "", 0); r != nil {
		return r
	}
	raw, e := fetchList(ctx, t.clients[c.server], kind)
	if e != nil {
		return t.deny(id, "context revalidation failed", scan.Report{})
	}
	field := "uri"
	if kind == "prompts" {
		field = "name"
	}
	valid := definitionMatches(raw, field, c.name, c.hash)
	if !valid {
		return t.deny(id, "context changed before access", scan.Report{})
	}
	r, e := t.clients[c.server].Call(ctx, method, params)
	if e != nil {
		return t.deny(id, "upstream context request failed", scan.Report{})
	}
	if kind == "resources" {
		for _, v := range asArray(r["contents"]) {
			if m := wire.Map(v); m != nil {
				m["uri"] = "tool-gateway://" + alias
			}
		}
	}
	return t.deliver(id, c.server, c.name, r, kind, c.contract.Produces)
}
func asArray(v any) []any { a, _ := v.([]any); return a }

func definitionMatches(raw []map[string]any, field, name, hash string) bool {
	seen := map[string]bool{}
	found := false
	for _, v := range raw {
		key := wire.String(v[field])
		if key == "" || seen[key] {
			return false
		}
		seen[key] = true
		if key == name {
			found = wire.Hash(v) == hash
		}
	}
	return found
}
