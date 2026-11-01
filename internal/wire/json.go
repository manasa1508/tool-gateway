// Package wire implements an intentionally narrow, unambiguous JSON-RPC boundary.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const MaxDepth = 32

// Decode rejects duplicate keys, malformed UTF-8, trailing values and deep nesting.
func Decode(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := value(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return v, nil
}
func value(d *json.Decoder, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, errors.New("JSON nesting limit")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			s, ok := k.(string)
			if !ok {
				return nil, errors.New("invalid key")
			}
			if _, ok = m[s]; ok {
				return nil, errors.New("duplicate JSON key")
			}
			v, e := value(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[s] = v
		}
		_, e = d.Token()
		return m, e
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, e := value(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	default:
		return t, nil
	}
}
func Object(b []byte) (map[string]any, error) {
	v, e := Decode(b)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("JSON object required")
	}
	return m, nil
}

// Canonical uses Go's deterministic map ordering and preserves JSON number spelling.
// This is a project-specific canonical form, not RFC 8785.
func Canonical(v any) []byte   { b, _ := json.Marshal(v); return b }
func Hash(v any) string        { h := sha256.Sum256(Canonical(v)); return hex.EncodeToString(h[:]) }
func String(v any) string      { s, _ := v.(string); return s }
func Map(v any) map[string]any { m, _ := v.(map[string]any); return m }
func RPC(id any, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}
func Error(id any, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}}
}
func ValidID(v any) bool {
	switch x := v.(type) {
	case string:
		return len(x) > 0 && len(x) <= 128
	case json.Number:
		_, e := x.Int64()
		return e == nil
	}
	return false
}
