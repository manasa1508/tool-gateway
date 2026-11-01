// Package policy compiles immutable, operator-owned capability contracts.
package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

type Limits struct {
	MaxMessageBytes   int `json:"max_message_bytes"`
	RequestTimeoutMS  int `json:"request_timeout_ms"`
	MaxSessions       int `json:"max_sessions"`
	SessionTTLSeconds int `json:"session_ttl_seconds"`
	MaxCalls          int `json:"max_calls"`
	MaxOutputBytes    int `json:"max_output_bytes"`
}
type Tool struct {
	Description     string              `json:"description"`
	SHA256          string              `json:"sha256,omitempty"`
	Effect          string              `json:"effect"`
	Produces        []string            `json:"produces,omitempty"`
	Accepts         []string            `json:"accepts,omitempty"`
	RequireApproval bool                `json:"require_approval,omitempty"`
	MaxCalls        int                 `json:"max_calls,omitempty"`
	URLFields       map[string][]string `json:"url_fields,omitempty"`
}
type Context struct {
	Description string          `json:"description"`
	SHA256      string          `json:"sha256,omitempty"`
	Produces    []string        `json:"produces,omitempty"`
	Arguments   map[string]bool `json:"arguments,omitempty"`
}
type Server struct {
	Command   []string           `json:"command,omitempty"`
	Env       []string           `json:"env,omitempty"`
	URL       string             `json:"url,omitempty"`
	TokenEnv  string             `json:"token_env,omitempty"`
	Tools     map[string]Tool    `json:"tools"`
	Resources map[string]Context `json:"resources,omitempty"`
	Prompts   map[string]Context `json:"prompts,omitempty"`
}
type Artifact struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}
type Config struct {
	Version           int                 `json:"version"`
	Mode              string              `json:"mode"`
	Listen            string              `json:"listen"`
	TokenEnv          string              `json:"token_env"`
	Principal         string              `json:"principal"`
	Origins           []string            `json:"origins,omitempty"`
	AuditPath         string              `json:"audit_path"`
	ApprovalPublicKey string              `json:"approval_public_key,omitempty"`
	Limits            Limits              `json:"limits"`
	Servers           map[string]Server   `json:"servers"`
	Artifacts         map[string]Artifact `json:"artifacts,omitempty"`
	Hash              string              `json:"-"`
}

var Name = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

func Load(path string) (*Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return Parse(b)
}
func Parse(b []byte) (*Config, error) {
	if len(b) > 1048576 {
		return nil, errors.New("policy too large")
	}
	v, e := wire.Decode(b)
	if e != nil {
		return nil, e
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(wire.Canonical(v)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return nil, e
	}
	if e = c.Validate(); e != nil {
		return nil, e
	}
	c.Hash = wire.Hash(c)
	return &c, nil
}
func (c *Config) Validate() error {
	if c.Version != 1 {
		return errors.New("policy version must be 1")
	}
	if c.Mode != "strict" && c.Mode != "lenient" && c.Mode != "audit" {
		return errors.New("mode must be strict, lenient or audit")
	}
	if c.Principal == "" || len(c.Principal) > 128 || c.AuditPath == "" {
		return errors.New("principal and audit_path required")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8844"
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || host == "" {
		return errors.New("explicit listen host and port required")
	}
	if c.TokenEnv == "" {
		return errors.New("token_env required")
	}
	l := &c.Limits
	if l.MaxMessageBytes == 0 {
		l.MaxMessageBytes = 1048576
	}
	if l.RequestTimeoutMS == 0 {
		l.RequestTimeoutMS = 15000
	}
	if l.MaxSessions == 0 {
		l.MaxSessions = 64
	}
	if l.SessionTTLSeconds == 0 {
		l.SessionTTLSeconds = 900
	}
	if l.MaxCalls == 0 {
		l.MaxCalls = 100
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = 8388608
	}
	if l.MaxMessageBytes < 1024 || l.MaxMessageBytes > 8388608 || l.RequestTimeoutMS < 100 || l.RequestTimeoutMS > 120000 || l.MaxSessions < 1 || l.MaxSessions > 4096 || l.SessionTTLSeconds < 10 || l.SessionTTLSeconds > 86400 || l.MaxCalls < 1 || l.MaxCalls > 100000 || l.MaxOutputBytes < 1024 || l.MaxOutputBytes > 1073741824 {
		return errors.New("limits outside supported bounds")
	}
	if c.ApprovalPublicKey != "" {
		k, e := base64.StdEncoding.DecodeString(c.ApprovalPublicKey)
		if e != nil || len(k) != ed25519.PublicKeySize {
			return errors.New("invalid Ed25519 public key")
		}
	}
	if len(c.Servers) < 1 || len(c.Servers) > 32 {
		return errors.New("configure 1..32 servers")
	}
	for id, s := range c.Servers {
		if !Name.MatchString(id) {
			return errors.New("invalid server id")
		}
		if (len(s.Command) > 0) == (s.URL != "") {
			return errors.New("server needs exactly one command or URL")
		}
		if len(s.Command) > 0 && (!strings.HasPrefix(s.Command[0], "/") || len(s.Command) > 64) {
			return errors.New("server command must use an absolute executable path")
		}
		if s.URL != "" {
			u, e := url.Parse(s.URL)
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
				return errors.New("upstream URL must be HTTPS without credentials, query or fragment")
			}
		}
		for _, key := range append(append([]string{}, s.Env...), s.TokenEnv) {
			if key != "" && key == c.TokenEnv {
				return errors.New("gateway authentication token must not be shared with an upstream")
			}
			if key != "" && !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) {
				return errors.New("invalid environment variable name")
			}
		}
		if len(s.Tools) > 256 {
			return errors.New("too many tool contracts")
		}
		for name, t := range s.Tools {
			if !Name.MatchString(name) || len(t.Description) > 1024 {
				return errors.New("invalid tool contract")
			}
			if t.Effect != "read" && t.Effect != "write" && t.Effect != "egress" {
				return errors.New("effect must be read, write or egress")
			}
			if c.Mode == "strict" && !validHash(t.SHA256) {
				return fmt.Errorf("strict mode requires reviewed sha256 pin for %s/%s", id, name)
			}
			if t.SHA256 != "" && !validHash(t.SHA256) {
				return errors.New("invalid tool pin")
			}
			if t.MaxCalls < 0 || t.MaxCalls > l.MaxCalls {
				return errors.New("invalid per-tool budget")
			}
			if (t.RequireApproval || t.Effect == "write") && c.ApprovalPublicKey == "" {
				return errors.New("approval public key required for sensitive tools")
			}
			for _, label := range append(append([]string{}, t.Produces...), t.Accepts...) {
				if !Name.MatchString(label) {
					return errors.New("invalid data label")
				}
			}
			for field, origins := range t.URLFields {
				if !Name.MatchString(field) || len(origins) == 0 {
					return errors.New("invalid URL field contract")
				}
				for _, origin := range origins {
					if !ValidOrigin(origin) {
						return errors.New("URL allowlist entries must be exact HTTPS origins")
					}
				}
			}
		}
		for _, contexts := range []map[string]Context{s.Resources, s.Prompts} {
			if len(contexts) > 256 {
				return errors.New("too many context contracts")
			}
			for name, x := range contexts {
				if name == "" || len(name) > 512 || len(x.Description) > 1024 || (c.Mode == "strict" && !validHash(x.SHA256)) || (x.SHA256 != "" && !validHash(x.SHA256)) {
					return errors.New("invalid context contract or missing strict pin")
				}
				for a := range x.Arguments {
					if !Name.MatchString(a) {
						return errors.New("invalid prompt argument")
					}
				}
				for _, label := range x.Produces {
					if !Name.MatchString(label) {
						return errors.New("invalid data label")
					}
				}
			}
		}
	}
	for id, a := range c.Artifacts {
		if !Name.MatchString(id) || !validHash(a.SHA256) || (a.Kind != "skill" && a.Kind != "plugin" && a.Kind != "connector") {
			return errors.New("invalid artifact contract")
		}
	}
	for _, origin := range c.Origins {
		u, e := url.Parse(origin)
		if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return errors.New("invalid browser origin")
		}
	}
	return nil
}
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func ValidOrigin(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && strings.ToLower(u.Host) == u.Host
}
func CheckURLs(t Tool, args map[string]any) error {
	for field, allow := range t.URLFields {
		v, ok := args[field].(string)
		if !ok {
			return errors.New("URL field must be present and a string")
		}
		u, e := url.Parse(v)
		if e != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Fragment != "" || strings.ContainsAny(v, "\r\n\\") {
			return errors.New("invalid destination URL")
		}
		origin := u.Scheme + "://" + strings.ToLower(u.Host)
		found := false
		for _, a := range allow {
			if a == origin {
				found = true
			}
		}
		if !found {
			return errors.New("destination origin is not allowed")
		}
	}
	return nil
}
