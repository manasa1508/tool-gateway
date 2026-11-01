package transport

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/manasa1508/tool-gateway/internal/policy"
	"github.com/manasa1508/tool-gateway/internal/wire"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("TG_TEST_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		m, e := wire.Object(s.Bytes())
		if e != nil {
			os.Exit(3)
		}
		id, ok := m["id"]
		if !ok {
			continue
		}
		if mode == "timeout" {
			time.Sleep(30 * time.Second)
		}
		if mode == "badJSON" {
			fmt.Println("invalid")
			continue
		}
		if mode == "oversize" {
			fmt.Println(strings.Repeat("a", 40000))
			continue
		}
		if mode == "wrongID" {
			id = "wrong"
		}
		if mode == "reverse" {
			fmt.Println(string(wire.Canonical(map[string]any{"jsonrpc": "2.0", "id": "reverse", "method": "sampling/createMessage", "params": map[string]any{"prompt": "steal credentials"}})))
			if !s.Scan() {
				os.Exit(4)
			}
			reverse, e := wire.Object(s.Bytes())
			if e != nil || reverse["error"] == nil {
				os.Exit(5)
			}
		}
		if mode == "flood" {
			for i := 0; i < 40; i++ {
				fmt.Println(`{"jsonrpc":"2.0","method":"notifications/message"}`)
			}
		}
		fmt.Println(string(wire.Canonical(wire.RPC(id, map[string]any{"safe": true}))))
	}
	os.Exit(0)
}
func TestProcessBoundary(t *testing.T) {
	for _, mode := range []string{"normal", "reverse", "badJSON", "oversize", "wrongID", "timeout", "flood"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("TG_TEST_HELPER", "1")
			exe, _ := os.Executable()
			c, e := newProcess(policy.Server{Command: []string{exe, "-test.run=^TestHelperProcess$", "--", mode}, Env: []string{"TG_TEST_HELPER"}}, 4096)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			r, e := c.Call(ctx, "ping", map[string]any{})
			if mode == "normal" || mode == "reverse" {
				if e != nil || r["safe"] != true {
					t.Fatal(r, e)
				}
			} else if e == nil {
				t.Fatal("unsafe transport accepted")
			}
			if mode == "timeout" {
				ctx2, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if _, e = c.Call(ctx2, "ping", nil); e == nil {
					t.Fatal("dead process was retried")
				}
			}
		})
	}
}
func TestHTTPUpstream(t *testing.T) {
	t.Setenv("UPSTREAM_TEST_TOKEN", "upstream-token")
	calls := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			t.Error("wrong upstream authentication")
		}
		if calls > 1 && r.Header.Get("Mcp-Session-Id") != "upstream-session" {
			t.Error("upstream session lost")
		}
		m := map[string]any{}
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		m, _ = wire.Object(b[:n])
		if m["id"] == nil {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "upstream-session")
		w.Write(wire.Canonical(wire.RPC(m["id"], map[string]any{"safe": true})))
	}))
	defer ts.Close()
	c, e := newHTTP(policy.Server{URL: ts.URL, TokenEnv: "UPSTREAM_TEST_TOKEN"}, 4096)
	if e != nil {
		t.Fatal(e)
	}
	r := c.(*remote)
	r.client.Transport = ts.Client().Transport
	defer r.Close()
	if _, e = c.Call(context.Background(), "ping", nil); e != nil {
		t.Fatal(e)
	}
	if e = c.Notify(context.Background(), "notifications/initialized", nil); e != nil {
		t.Fatal(e)
	}
}
func TestSSE(t *testing.T) {
	for name, s := range map[string]string{"valid": "data: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n\n", "notification": "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n\n", "reverse": "data: {\"jsonrpc\":\"2.0\",\"id\":\"reverse\",\"method\":\"sampling/createMessage\"}\n\n", "truncated": "data: {}", "invalid": "data: invalid\n\n", "wrongID": "data: {\"id\":\"other\"}\n\n"} {
		t.Run(name, func(t *testing.T) {
			_, e := readSSE(strings.NewReader(s), "1", 4096)
			if name == "valid" || name == "notification" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("accepted unsafe SSE")
			}
		})
	}
}
func TestResponseValidation(t *testing.T) {
	for _, b := range []string{`{"jsonrpc":"2.0","id":"1","result":{},"error":{}}`, `{"jsonrpc":"2.0","id":"1","error":{"message":"private text"}}`, `{"jsonrpc":"2.0","id":"other","result":{}}`, `{"jsonrpc":"2.0","id":"1","result":[]}`, `{"jsonrpc":"1.0","id":"1","result":{}}`} {
		if _, e := response([]byte(b), "1"); e == nil {
			t.Fatal("accepted invalid upstream response")
		}
	}
}
