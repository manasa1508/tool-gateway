// Command tool-gateway mediates MCP and inspects integration source bundles.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/manasa1508/tool-gateway/internal/approval"
	"github.com/manasa1508/tool-gateway/internal/artifact"
	"github.com/manasa1508/tool-gateway/internal/audit"
	"github.com/manasa1508/tool-gateway/internal/gateway"
	"github.com/manasa1508/tool-gateway/internal/policy"
	"github.com/manasa1508/tool-gateway/internal/scan"
	"github.com/manasa1508/tool-gateway/internal/schema"
	"github.com/manasa1508/tool-gateway/internal/transport"
	"github.com/manasa1508/tool-gateway/internal/wire"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "tool-gateway:", e)
		os.Exit(1)
	}
}
func output(v any) { fmt.Println(string(wire.Canonical(v))) }
func flags(name string, args []string, setup func(*flag.FlagSet)) error {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	setup(f)
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tool-gateway {serve|stdio|check|inspect|scan|simulate|artifact|keygen|approve|verify-audit|demo-policy|demo-server|version} [flags]")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "version":
		output(map[string]any{"version": gateway.Version, "protocol": gateway.Protocol})
		return nil
	case "serve", "stdio", "check":
		var path string
		if e := flags(args[0], args[1:], func(f *flag.FlagSet) { f.StringVar(&path, "policy", "policy.json", "policy JSON path") }); e != nil {
			return e
		}
		c, e := policy.Load(path)
		if e != nil {
			return e
		}
		if args[0] == "check" {
			output(map[string]any{"valid": true, "policy": c.Hash, "mode": c.Mode})
			return nil
		}
		j, e := audit.Open(c.AuditPath)
		if e != nil {
			return e
		}
		defer j.Close()
		engine := &gateway.Engine{Policy: c, Journal: j, Factory: transport.New}
		if args[0] == "serve" {
			h, e := gateway.NewHTTP(engine)
			if e != nil {
				return e
			}
			defer h.Close()
			fmt.Fprintln(os.Stderr, "tool-gateway listening on", c.Listen)
			return gateway.Serve(ctx, h)
		}
		task := engine.NewTask(c.Principal)
		defer task.Close()
		go func() { <-ctx.Done(); task.Close(); _ = os.Stdin.Close() }()
		s := bufio.NewScanner(os.Stdin)
		s.Buffer(make([]byte, 4096), c.Limits.MaxMessageBytes)
		for s.Scan() {
			r := task.Handle(ctx, s.Bytes())
			if r != nil {
				output(r)
			}
		}
		if e = s.Err(); e != nil {
			return errors.New("input closed or frame limit exceeded")
		}
		return nil
	case "scan", "simulate":
		var path string
		if e := flags(args[0], args[1:], func(f *flag.FlagSet) { f.StringVar(&path, "file", "", "JSON/JSONL file (stdin if omitted)") }); e != nil {
			return e
		}
		r, close, e := input(path)
		if e != nil {
			return e
		}
		defer close()
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 4096), 8388608)
		line := 0
		for s.Scan() {
			line++
			v, e := wire.Decode(s.Bytes())
			if e != nil {
				return fmt.Errorf("invalid JSON on line %d", line)
			}
			report := scan.Analyze(v)
			if args[0] == "scan" {
				output(report)
			} else {
				decisions := map[string]string{}
				for _, mode := range []string{"strict", "lenient", "audit"} {
					d := "allow"
					if report.Reject(mode) {
						d = "reject"
					}
					if report.Secret {
						d = "block-credential"
					}
					decisions[mode] = d
				}
				output(map[string]any{"line": line, "report": report, "decisions": decisions})
			}
		}
		return s.Err()
	case "inspect":
		var path string
		if e := flags("inspect", args[1:], func(f *flag.FlagSet) { f.StringVar(&path, "file", "", "saved tools/list JSON response") }); e != nil {
			return e
		}
		b, e := read(path, 8388608)
		if e != nil {
			return e
		}
		m, e := wire.Object(b)
		if e != nil {
			return e
		}
		if r := wire.Map(m["result"]); r != nil {
			m = r
		}
		a, ok := m["tools"].([]any)
		if !ok {
			return errors.New("tools array required")
		}
		out := []any{}
		for _, v := range a {
			m := wire.Map(v)
			name := wire.String(m["name"])
			if !policy.Name.MatchString(name) {
				return errors.New("unsafe tool name")
			}
			s, e := schema.Rebuild(m["inputSchema"])
			view := map[string]any{"name": name, "sha256": wire.Hash(m), "findings": scan.Analyze(m), "inputSchema": s}
			if e != nil {
				view["schema_error"] = e.Error()
			}
			out = append(out, view)
		}
		output(map[string]any{"tools": out, "note": "Review the complete original definitions before pinning. Pins do not certify server code."})
		return nil
	case "artifact":
		return artifactCommand(args[1:])
	case "keygen":
		var path string
		if e := flags("keygen", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&path, "private-key", "", "new private-key file, outside the repository")
		}); e != nil {
			return e
		}
		if path == "" {
			return errors.New("--private-key required")
		}
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		if _, e = f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
		output(map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)})
		return nil
	case "approve":
		return approve(args[1:])
	case "verify-audit":
		var path, head string
		if e := flags("verify-audit", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&path, "file", "", "audit JSONL path")
			f.StringVar(&head, "head", "", "independently retained expected final hash")
		}); e != nil {
			return e
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		h, n, e := audit.Verify(f, head, nil)
		if e != nil {
			return e
		}
		output(map[string]any{"valid": true, "entries": n, "head": h, "externally_anchored": head != ""})
		return nil
	case "demo-policy":
		var out string
		if e := flags("demo-policy", args[1:], func(f *flag.FlagSet) { f.StringVar(&out, "out", "policy.local.json", "new policy path") }); e != nil {
			return e
		}
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		auditPath, e := filepath.Abs("audit.local.jsonl")
		if e != nil {
			return e
		}
		c := policy.Config{Version: 1, Mode: "strict", Listen: "127.0.0.1:8844", TokenEnv: "TOOL_GATEWAY_TOKEN", Principal: "local-user", AuditPath: auditPath, Servers: map[string]policy.Server{"demo": {Command: []string{exe, "demo-server"}, Tools: map[string]policy.Tool{"read_note": {Description: "Read a demonstration internal note.", SHA256: wire.Hash(demoTools()[0]), Effect: "read", Produces: []string{"internal"}, Accepts: []string{"internal"}}, "send_message": {Description: "Send a demonstration message; never actually contacts a network.", SHA256: wire.Hash(demoTools()[1]), Effect: "egress", MaxCalls: 2}}}}}
		b := wire.Canonical(c)
		if _, e = policy.Parse(b); e != nil {
			return e
		}
		f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = f.Write(append(b, '\n'))
		if e == nil {
			output(map[string]any{"policy": out})
		}
		return e
	case "demo-server":
		return demoServer()
	default:
		return errors.New("unknown command")
	}
}
func input(path string) (io.Reader, func(), error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, func() {}, e
	}
	return f, func() { _ = f.Close() }, nil
}
func read(path string, max int) ([]byte, error) {
	r, close, e := input(path)
	if e != nil {
		return nil, e
	}
	defer close()
	b, e := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if len(b) > max {
		return nil, errors.New("input limit exceeded")
	}
	return b, e
}
func approve(args []string) error {
	var policyPath, keyPath, task, server, tool, argsPath string
	var ttl time.Duration
	if e := flags("approve", args, func(f *flag.FlagSet) {
		f.StringVar(&policyPath, "policy", "policy.json", "policy JSON")
		f.StringVar(&keyPath, "private-key", "", "offline signing key")
		f.StringVar(&task, "task", "", "task ID from gateway initialization")
		f.StringVar(&server, "server", "", "server ID")
		f.StringVar(&tool, "tool", "", "original tool name")
		f.StringVar(&argsPath, "args", "", "reviewed argument JSON file")
		f.DurationVar(&ttl, "ttl", 2*time.Minute, "approval lifetime (max 10m)")
	}); e != nil {
		return e
	}
	if keyPath == "" || task == "" || server == "" || tool == "" || argsPath == "" {
		return errors.New("policy, private-key, task, server, tool and args required")
	}
	c, e := policy.Load(policyPath)
	if e != nil {
		return e
	}
	contract, ok := c.Servers[server].Tools[tool]
	if !ok || !(contract.RequireApproval || contract.Effect == "write") {
		return errors.New("tool must be an approved sensitive action")
	}
	b, e := read(argsPath, c.Limits.MaxMessageBytes)
	if e != nil {
		return e
	}
	v, e := wire.Object(b)
	if e != nil {
		return e
	}
	if scan.Analyze(v).Secret {
		return errors.New("cannot approve credential-bearing arguments")
	}
	keyBytes, e := os.ReadFile(keyPath)
	if e != nil {
		return e
	}
	priv, e := base64.StdEncoding.DecodeString(string(bytesTrim(keyBytes)))
	if e != nil || len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid private key")
	}
	pub := base64.StdEncoding.EncodeToString(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))
	if pub != c.ApprovalPublicKey {
		return errors.New("private key does not match policy")
	}
	token, e := approval.Issue(ed25519.PrivateKey(priv), approval.Claims{Principal: c.Principal, Task: task, Server: server, Tool: tool, ArgsHash: wire.Hash(v), Policy: c.Hash}, ttl)
	if e != nil {
		return e
	}
	output(map[string]any{"approval": token, "args_hash": wire.Hash(v), "task": task})
	return nil
}
func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
func artifactCommand(args []string) error {
	var root, path, id, kind string
	if e := flags("artifact", args, func(f *flag.FlagSet) {
		f.StringVar(&root, "root", "", "source bundle directory")
		f.StringVar(&path, "policy", "", "policy path; omit for inspection only")
		f.StringVar(&id, "id", "", "artifact contract ID")
		f.StringVar(&kind, "kind", "skill", "skill, plugin or connector")
	}); e != nil {
		return e
	}
	if root == "" {
		return errors.New("--root required")
	}
	r, e := artifact.Inspect(root)
	if e != nil {
		return e
	}
	if path == "" {
		output(r)
		return nil
	}
	c, e := policy.Load(path)
	if e != nil {
		return e
	}
	a, ok := c.Artifacts[id]
	allowed := ok && a.Kind == kind && a.SHA256 == r.Root && !r.Findings.Secret && !r.Findings.Reject(c.Mode)
	output(map[string]any{"allowed": allowed, "report": r})
	if !allowed {
		return errors.New("artifact not approved or content rejected")
	}
	return nil
}
func demoTools() []any {
	return []any{map[string]any{"name": "read_note", "description": "Read a demonstration note.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}}, map[string]any{"name": "send_message", "description": "A no-op message sink for local testing.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string", "maxLength": 4096}}, "required": []any{"message"}, "additionalProperties": false}}}
}
func demoServer() error {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 1048576)
	for s.Scan() {
		m, e := wire.Object(s.Bytes())
		if e != nil {
			return e
		}
		id, ok := m["id"]
		if !ok {
			continue
		}
		p := wire.Map(m["params"])
		var r any
		switch m["method"] {
		case "initialize":
			r = map[string]any{"protocolVersion": gateway.Protocol, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "demo", "version": "1"}}
		case "tools/list":
			r = map[string]any{"tools": demoTools()}
		case "tools/call":
			text := "message accepted by no-op demo sink"
			if p["name"] == "read_note" {
				text = "Internal demonstration note: the release review is on Monday."
			}
			r = map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
		default:
			output(wire.Error(id, -32601, "unsupported demo method"))
			continue
		}
		output(wire.RPC(id, r))
	}
	return s.Err()
}
