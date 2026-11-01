// Package schema provides bounded content disarm and reconstruction (CDR).
// Only the documented structural JSON Schema subset is accepted. Unsupported
// assertions are rejected, never silently weakened. All prose is discarded.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

var keyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
var prose = map[string]bool{"description": true, "title": true, "examples": true, "default": true, "$comment": true, "$schema": true, "deprecated": true, "readOnly": true, "writeOnly": true}
var structural = map[string]bool{"type": true, "properties": true, "required": true, "additionalProperties": true, "items": true, "enum": true, "minLength": true, "maxLength": true, "minimum": true, "maximum": true, "minItems": true, "maxItems": true}

func Rebuild(v any) (map[string]any, error) {
	n := 0
	m, e := rebuild(v, 0, &n)
	if e != nil {
		return nil, e
	}
	if m["type"] != "object" {
		return nil, errors.New("tool schema must be an object")
	}
	return m, nil
}
func rebuild(v any, depth int, n *int) (map[string]any, error) {
	*n++
	if depth > 8 || *n > 512 {
		return nil, errors.New("schema complexity limit")
	}
	in, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("schema object required")
	}
	typ := wire.String(in["type"])
	if !validType(typ) {
		return nil, errors.New("explicit supported type required")
	}
	out := map[string]any{"type": typ}
	for k := range in {
		if !prose[k] && !structural[k] {
			return nil, errors.New("unsupported schema keyword")
		}
	}
	if typ == "object" {
		props := map[string]any{}
		if p, exists := in["properties"]; exists {
			pm, ok := p.(map[string]any)
			if !ok || len(pm) > 128 {
				return nil, errors.New("invalid properties")
			}
			for k, v := range pm {
				if !keyRE.MatchString(k) {
					return nil, errors.New("unsafe property key")
				}
				child, e := rebuild(v, depth+1, n)
				if e != nil {
					return nil, e
				}
				props[k] = child
			}
		}
		out["properties"] = props
		out["additionalProperties"] = false
		if a, exists := in["additionalProperties"]; exists && a != false {
			return nil, errors.New("open object schemas are unsupported")
		}
		req := []any{}
		seen := map[string]bool{}
		if r, exists := in["required"]; exists {
			a, ok := r.([]any)
			if !ok {
				return nil, errors.New("invalid required")
			}
			for _, v := range a {
				k, ok := v.(string)
				if !ok || props[k] == nil || seen[k] {
					return nil, errors.New("invalid required key")
				}
				seen[k] = true
				req = append(req, k)
			}
		}
		out["required"] = req
	} else if in["properties"] != nil || in["required"] != nil || in["additionalProperties"] != nil {
		return nil, errors.New("object keywords on non-object")
	}
	if typ == "array" {
		child, e := rebuild(in["items"], depth+1, n)
		if e != nil {
			return nil, e
		}
		out["items"] = child
	} else if in["items"] != nil {
		return nil, errors.New("items on non-array")
	}
	for _, k := range []string{"minLength", "maxLength", "minItems", "maxItems", "minimum", "maximum"} {
		if x, exists := in[k]; exists {
			if _, ok := exact(x); !ok {
				return nil, errors.New("numeric constraint outside supported precision")
			}
			f, ok := number(x)
			if !ok || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, errors.New("invalid numeric constraint")
			}
			if k != "minimum" && k != "maximum" {
				if f < 0 || f != math.Trunc(f) || f > 1048576 {
					return nil, errors.New("invalid size constraint")
				}
				if strings.Contains(k, "Length") && typ != "string" || strings.Contains(k, "Items") && typ != "array" {
					return nil, errors.New("constraint type mismatch")
				}
			} else if typ != "number" && typ != "integer" {
				return nil, errors.New("constraint type mismatch")
			}
			out[k] = x
		}
	}
	for _, p := range [][2]string{{"minLength", "maxLength"}, {"minItems", "maxItems"}, {"minimum", "maximum"}} {
		a, aok := number(out[p[0]])
		b, bok := number(out[p[1]])
		if aok && bok && a > b {
			return nil, errors.New("inverted bounds")
		}
	}
	if v, exists := in["enum"]; exists {
		a, ok := v.([]any)
		if !ok || len(a) == 0 || len(a) > 64 || typ == "object" || typ == "array" {
			return nil, errors.New("invalid enum")
		}
		for _, v := range a {
			if e := Validate(out, v); e != nil {
				return nil, errors.New("enum type mismatch")
			}
			if s, ok := v.(string); ok && (!keyRE.MatchString(s) || len(s) > 64) {
				return nil, errors.New("unsafe enum value")
			}
		}
		out["enum"] = a
	}
	return out, nil
}
func validType(s string) bool {
	switch s {
	case "object", "array", "string", "number", "integer", "boolean", "null":
		return true
	}
	return false
}
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, e := x.Float64()
		return f, e == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	}
	return 0, false
}
func Validate(s map[string]any, v any) error {
	typ := wire.String(s["type"])
	switch typ {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return errors.New("expected object")
		}
		p := wire.Map(s["properties"])
		for _, k := range s["required"].([]any) {
			if _, ok := m[k.(string)]; !ok {
				return errors.New("missing required property")
			}
		}
		for k, v := range m {
			c, ok := p[k].(map[string]any)
			if !ok {
				return errors.New("unknown property")
			}
			if e := Validate(c, v); e != nil {
				return e
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return errors.New("expected array")
		}
		if e := bounds(s, float64(len(a)), "minItems", "maxItems"); e != nil {
			return e
		}
		for _, v := range a {
			if e := Validate(wire.Map(s["items"]), v); e != nil {
				return e
			}
		}
	case "string":
		x, ok := v.(string)
		if !ok {
			return errors.New("expected string")
		}
		if e := bounds(s, float64(utf8.RuneCountInString(x)), "minLength", "maxLength"); e != nil {
			return e
		}
	case "number", "integer":
		f, ok := exact(v)
		if !ok || typ == "integer" && !f.IsInt() {
			return errors.New("expected finite number")
		}
		if a, ok := exact(s["minimum"]); ok && f.Cmp(a) < 0 {
			return errors.New("below minimum")
		}
		if b, ok := exact(s["maximum"]); ok && f.Cmp(b) > 0 {
			return errors.New("above maximum")
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return errors.New("expected boolean")
		}
	case "null":
		if v != nil {
			return errors.New("expected null")
		}
	default:
		return errors.New("invalid schema")
	}
	if a, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range a {
			if equal(x, v) {
				found = true
			}
		}
		if !found {
			return errors.New("enum mismatch")
		}
	}
	return nil
}
func equal(a, b any) bool {
	if x, ok := exact(a); ok {
		if y, ok := exact(b); ok {
			return x.Cmp(y) == 0
		}
	}
	return string(wire.Canonical(a)) == string(wire.Canonical(b))
}

// Bound rational parsing prevents adversarial exponents from allocating huge
// integers while retaining exact comparisons for money, counters and enums.
func exact(v any) (*big.Rat, bool) {
	if _, ok := number(v); !ok {
		return nil, false
	}
	s := string(wire.Canonical(v))
	if len(s) > 64 {
		return nil, false
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exp, e := strconv.Atoi(s[i+1:])
		if e != nil || exp < -308 || exp > 308 {
			return nil, false
		}
	}
	x, ok := new(big.Rat).SetString(s)
	return x, ok
}
func bounds(s map[string]any, f float64, min, max string) error {
	if a, ok := number(s[min]); ok && f < a {
		return fmt.Errorf("below %s", min)
	}
	if b, ok := number(s[max]); ok && f > b {
		return fmt.Errorf("above %s", max)
	}
	return nil
}
