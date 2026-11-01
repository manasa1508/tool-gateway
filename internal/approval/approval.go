// Package approval provides offline-issued, exact-action Ed25519 approvals.
package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

type Claims struct {
	Principal string `json:"principal"`
	Task      string `json:"task"`
	Server    string `json:"server"`
	Tool      string `json:"tool"`
	ArgsHash  string `json:"args_hash"`
	Policy    string `json:"policy"`
	Nonce     string `json:"nonce"`
	Issued    int64  `json:"issued"`
	Expires   int64  `json:"expires"`
}

func ID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("system random source unavailable")
	}
	return hex.EncodeToString(b[:])
}
func Issue(k ed25519.PrivateKey, c Claims, ttl time.Duration) (string, error) {
	if len(k) != ed25519.PrivateKeySize || ttl < time.Second || ttl > 10*time.Minute {
		return "", errors.New("valid key and TTL of 1..600 seconds required")
	}
	c.Nonce = ID()
	c.Issued = time.Now().Unix()
	c.Expires = c.Issued + int64(ttl/time.Second)
	p := wire.Canonical(c)
	sig := ed25519.Sign(k, append([]byte("tool-gateway.approval.v1\x00"), p...))
	return base64.RawURLEncoding.EncodeToString(p) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func Verify(k ed25519.PublicKey, token string, want Claims, now time.Time) (Claims, error) {
	var c Claims
	if len(token) > 4096 || len(k) != ed25519.PublicKeySize {
		return c, errors.New("invalid approval")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid approval")
	}
	p, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return c, errors.New("invalid approval")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !ed25519.Verify(k, append([]byte("tool-gateway.approval.v1\x00"), p...), sig) {
		return c, errors.New("invalid approval signature")
	}
	v, e := wire.Decode(p)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(bytes.NewReader(wire.Canonical(v)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, errors.New("invalid approval claims")
	}
	if c.Expires <= now.Unix() || c.Issued > now.Unix()+5 || c.Expires-c.Issued > 600 || c.Expires <= c.Issued || len(c.Nonce) != 48 {
		return c, errors.New("approval outside validity window")
	}
	if c.Principal != want.Principal || c.Task != want.Task || c.Server != want.Server || c.Tool != want.Tool || c.ArgsHash != want.ArgsHash || c.Policy != want.Policy {
		return c, errors.New("approval action mismatch")
	}
	return c, nil
}
