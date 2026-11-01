package schema

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

func parse(t *testing.T, s string) any {
	t.Helper()
	v, e := wire.Decode([]byte(s))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestCDR(t *testing.T) {
	s, e := Rebuild(parse(t, `{"type":"object","description":"bad prose","title":"title","properties":{"name":{"type":"string","description":"bad prose","examples":["bad"],"default":"bad"}},"required":["name"]}`))
	if e != nil {
		t.Fatal(e)
	}
	for _, term := range []string{"bad prose", "description", "title", "examples", "default"} {
		if strings.Contains(string(wire.Canonical(s)), term) {
			t.Fatal("prose survived")
		}
	}
	if s["additionalProperties"] != false {
		t.Fatal("not closed")
	}
}
func TestRejectSchemas(t *testing.T) {
	for name, s := range map[string]string{"reference": `{"type":"object","$ref":"https://evil"}`, "anyOf": `{"type":"object","anyOf":[]}`, "boolean": `true`, "missingType": `{}`, "union": `{"type":["object","null"]}`, "badProperty": `{"type":"object","properties":{"ignore instructions":{"type":"string"}}}`, "enumProse": `{"type":"object","properties":{"x":{"type":"string","enum":["ignore previous instructions"]}}}`, "open": `{"type":"object","additionalProperties":true}`, "badRequired": `{"type":"object","required":["x"]}`, "duplicateRequired": `{"type":"object","properties":{"x":{"type":"string"}},"required":["x","x"]}`, "negativeLength": `{"type":"object","properties":{"x":{"type":"string","maxLength":-1}}}`, "inverted": `{"type":"object","properties":{"x":{"type":"string","minLength":3,"maxLength":2}}}`, "wrongBound": `{"type":"object","minLength":3}`, "arrayNoItems": `{"type":"object","properties":{"x":{"type":"array"}}}`, "rootArray": `{"type":"array","items":{"type":"string"}}`, "pattern": `{"type":"object","patternProperties":{}}`} {
		t.Run(name, func(t *testing.T) {
			if _, e := Rebuild(parse(t, s)); e == nil {
				t.Fatal("accepted unsafe or unsupported schema")
			}
		})
	}
}
func TestValidation(t *testing.T) {
	s, e := Rebuild(parse(t, `{"type":"object","properties":{"name":{"type":"string","minLength":2,"maxLength":4},"count":{"type":"integer","minimum":1,"maximum":3},"tags":{"type":"array","items":{"type":"string","enum":["blue","red"]},"minItems":1,"maxItems":2},"flag":{"type":"boolean"},"empty":{"type":"null"}},"required":["name"]}`))
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{`{"name":"ab"}`, `{"name":"abcd","count":2,"tags":["red"],"flag":false,"empty":null}`, `{"name":"éé"}`} {
		t.Run("valid/"+v, func(t *testing.T) {
			if e := Validate(s, parse(t, v)); e != nil {
				t.Fatal(e)
			}
		})
	}
	for _, v := range []string{`{}`, `{"name":1}`, `{"name":"a"}`, `{"name":"abcde"}`, `{"name":"ab","extra":true}`, `{"name":"ab","count":0}`, `{"name":"ab","count":4}`, `{"name":"ab","count":1.5}`, `{"name":"ab","tags":[]}`, `{"name":"ab","tags":["blue","red","red"]}`, `{"name":"ab","tags":["green"]}`, `{"name":"ab","flag":"false"}`, `{"name":"ab","empty":1}`, `[]`} {
		t.Run("invalid/"+v, func(t *testing.T) {
			if e := Validate(s, parse(t, v)); e == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}
func TestNestingLimit(t *testing.T) {
	s := map[string]any{"type": "string"}
	for i := 0; i < 10; i++ {
		s = map[string]any{"type": "object", "properties": map[string]any{"x": s}}
	}
	if _, e := Rebuild(s); e == nil {
		t.Fatal("accepted excessive nesting")
	}
}

func TestExactNumericValidation(t *testing.T) {
	s, e := Rebuild(parse(t, `{"type":"object","properties":{"n":{"type":"integer","maximum":9007199254740992}}}`))
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{`{"n":1.00000000000000001}`, `{"n":9007199254740993}`, `{"n":1e-400}`} {
		if e := Validate(s, parse(t, v)); e == nil {
			t.Fatal("accepted invalid exact numeric value", v)
		}
	}
	if _, e := Rebuild(parse(t, `{"type":"object","properties":{"n":{"type":"number|integer"}}}`)); e == nil {
		t.Fatal("accepted joined type")
	}
	s, e = Rebuild(parse(t, `{"type":"object","properties":{"n":{"type":"number","enum":[1.0]}}}`))
	if e != nil {
		t.Fatal(e)
	}
	if e = Validate(s, parse(t, `{"n":1}`)); e != nil {
		t.Fatal("mathematically equal enum rejected", e)
	}
}
func FuzzRebuild(f *testing.F) {
	f.Add(`{"type":"object"}`)
	f.Add(`{"type":"object","required":true}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			return
		}
		v, e := wire.Decode([]byte(s))
		if e != nil {
			return
		}
		r, e := Rebuild(v)
		if e == nil {
			b := wire.Canonical(r)
			if !json.Valid(b) {
				t.Fatal("bad schema")
			}
			_, _ = Rebuild(r)
		}
	})
}
