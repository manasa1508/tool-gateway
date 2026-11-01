package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestExactAction(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	want := Claims{Principal: "alice", Task: "task", Server: "db", Tool: "write", ArgsHash: "arguments", Policy: "policy"}
	token, e := Issue(priv, want, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	c, e := Verify(pub, token, want, time.Now())
	if e != nil || c.Nonce == "" {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*Claims){"principal": func(c *Claims) { c.Principal = "bob" }, "task": func(c *Claims) { c.Task = "other" }, "server": func(c *Claims) { c.Server = "other" }, "tool": func(c *Claims) { c.Tool = "other" }, "args": func(c *Claims) { c.ArgsHash = "other" }, "policy": func(c *Claims) { c.Policy = "other" }} {
		t.Run(name, func(t *testing.T) {
			different := want
			change(&different)
			if _, e := Verify(pub, token, different, time.Now()); e == nil {
				t.Fatal("accepted action substitution")
			}
		})
	}
	if _, e := Verify(pub, token, want, time.Now().Add(2*time.Minute)); e == nil {
		t.Fatal("accepted expired approval")
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := Verify(wrong, token, want, time.Now()); e == nil {
		t.Fatal("accepted wrong key")
	}
	for _, bad := range []string{"", token + "x", "x.y", strings.Repeat("x", 5000), "a.b.c"} {
		if _, e := Verify(pub, bad, want, time.Now()); e == nil {
			t.Fatal("accepted malformed approval")
		}
	}
}
func TestTTL(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, ttl := range []time.Duration{0, -time.Second, time.Hour} {
		if _, e := Issue(key, Claims{}, ttl); e == nil {
			t.Fatal("accepted invalid ttl")
		}
	}
}
