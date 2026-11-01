package policy

import (
	"strings"
	"testing"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

func valid() map[string]any {
	return map[string]any{"version": 1, "mode": "audit", "listen": "127.0.0.1:8844", "token_env": "TOKEN", "principal": "alice", "audit_path": "audit.local.jsonl", "limits": map[string]any{}, "servers": map[string]any{"test": map[string]any{"command": []any{"/bin/test"}, "tools": map[string]any{"search": map[string]any{"description": "Search", "effect": "read"}}}}}
}
func TestPolicyValidation(t *testing.T) {
	if _, e := Parse(wire.Canonical(valid())); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(map[string]any){"version": func(m map[string]any) { m["version"] = 2 }, "mode": func(m map[string]any) { m["mode"] = "unknown" }, "unknown": func(m map[string]any) { m["ignored"] = true }, "principal": func(m map[string]any) { m["principal"] = "" }, "audit": func(m map[string]any) { m["audit_path"] = "" }, "token": func(m map[string]any) { m["token_env"] = "" }, "strictNoPins": func(m map[string]any) { m["mode"] = "strict" }, "limit": func(m map[string]any) { m["limits"] = map[string]any{"max_sessions": -1} }, "listen": func(m map[string]any) { m["listen"] = ":8844" }, "servers": func(m map[string]any) { m["servers"] = map[string]any{} }, "relativeCommand": func(m map[string]any) { wire.Map(wire.Map(m["servers"])["test"])["command"] = []any{"npx"} }, "dualTransport": func(m map[string]any) { wire.Map(wire.Map(m["servers"])["test"])["url"] = "https://example.com/mcp" }, "httpUpstream": func(m map[string]any) {
		s := wire.Map(wire.Map(m["servers"])["test"])
		delete(s, "command")
		s["url"] = "http://example.com"
	}, "writeWithoutKey": func(m map[string]any) {
		wire.Map(wire.Map(wire.Map(wire.Map(m["servers"])["test"])["tools"])["search"])["effect"] = "write"
	}} {
		t.Run(name, func(t *testing.T) {
			m := valid()
			mutate(m)
			if _, e := Parse(wire.Canonical(m)); e == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}
func TestPolicyCanonicalHash(t *testing.T) {
	a, e := Parse(wire.Canonical(valid()))
	if e != nil {
		t.Fatal(e)
	}
	b, e := Parse(wire.Canonical(a))
	if e != nil {
		t.Fatal(e)
	}
	if a.Hash != b.Hash {
		t.Fatal("policy hash not stable")
	}
	if _, e := Parse([]byte(strings.Replace(string(wire.Canonical(valid())), `"version":1`, `"version":1,"version":1`, 1))); e == nil {
		t.Fatal("accepted duplicate key")
	}
}

func TestTokenAudienceSeparation(t *testing.T) {
	m := valid()
	wire.Map(wire.Map(m["servers"])["test"])["env"] = []any{"TOKEN"}
	if _, e := Parse(wire.Canonical(m)); e == nil {
		t.Fatal("gateway token shared with subprocess")
	}
}
func TestDestinationContracts(t *testing.T) {
	c := Tool{URLFields: map[string][]string{"url": {"https://api.example.com"}}}
	for _, u := range []string{"https://api.example.com/v1", "https://api.example.com?q=test"} {
		if e := CheckURLs(c, map[string]any{"url": u}); e != nil {
			t.Fatal(e)
		}
	}
	for _, u := range []any{"http://api.example.com", "https://api.example.com.evil.test", "https://api.example.com@evil.test", "https://api.example.com:444/v1", "https://API.example.com/#secret", "https://api.example.com\\@evil.test", true, nil} {
		t.Run("reject", func(t *testing.T) {
			if e := CheckURLs(c, map[string]any{"url": u}); e == nil {
				t.Fatal("accepted destination", u)
			}
		})
	}
}
