package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRejectAmbiguousJSON(t *testing.T) {
	for name, b := range map[string]string{"duplicate": `{"x":1,"x":2}`, "nestedDuplicate": `{"x":{"a":1,"a":2}}`, "trailing": `{} {}`, "batchTrailing": `[] true`, "invalidUTF8": string([]byte{34, 255, 34}), "depth": strings.Repeat(`[`, 34) + `0` + strings.Repeat(`]`, 34), "truncated": `{"x":`, "syntax": `{x:1}`, "number": `01`} {
		t.Run(name, func(t *testing.T) {
			if _, e := Decode([]byte(b)); e == nil {
				t.Fatal("accepted ambiguous JSON")
			}
		})
	}
}
func TestValidJSON(t *testing.T) {
	for _, b := range []string{`{}`, `[]`, `null`, `true`, `"hello"`, `{"a":1,"b":[false,null,"x"]}`, `-1.25e3`} {
		t.Run(b, func(t *testing.T) {
			v, e := Decode([]byte(b))
			if e != nil {
				t.Fatal(e)
			}
			if !json.Valid(Canonical(v)) {
				t.Fatal("invalid serialization")
			}
		})
	}
}
func TestIDs(t *testing.T) {
	for _, v := range []any{"x", json.Number("1"), json.Number("-42")} {
		if !ValidID(v) {
			t.Fatalf("invalid valid ID %v", v)
		}
	}
	for _, v := range []any{nil, "", strings.Repeat("a", 129), json.Number("1.5"), json.Number("1e400"), true, []any{}} {
		if ValidID(v) {
			t.Fatalf("accepted ID %v", v)
		}
	}
}
func TestHashOrdering(t *testing.T) {
	a, _ := Decode([]byte(`{"b":2,"a":1}`))
	b, _ := Decode([]byte(`{"a":1,"b":2}`))
	if Hash(a) != Hash(b) {
		t.Fatal("map ordering affects digest")
	}
}
func FuzzDecode(f *testing.F) {
	for _, b := range []string{`{}`, `{"a":[1]}`, `null`, `{"x":1,"x":2}`} {
		f.Add([]byte(b))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		v, e := Decode(b)
		if e == nil && !json.Valid(Canonical(v)) {
			t.Fatal("invalid round trip")
		}
	})
}
