// Package scan provides deterministic, bounded heuristic detection. A clean
// verdict is not a proof that natural language is safe.
package scan

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/manasa1508/tool-gateway/internal/wire"
	"golang.org/x/text/unicode/norm"
)

type Finding struct {
	ID     string `json:"id"`
	Weight int    `json:"weight"`
	Secret bool   `json:"secret,omitempty"`
}
type Report struct {
	Score    int       `json:"score"`
	Findings []Finding `json:"findings"`
	Secret   bool      `json:"secret"`
}
type rule struct {
	id     string
	weight int
	secret bool
	re     *regexp.Regexp
}

func r(id string, w int, secret bool, pattern string) rule {
	return rule{id, w, secret, regexp.MustCompile(pattern)}
}

var rules = []rule{
	r("instruction.override", 50, false, `(?i)(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|system|developer)\s+(instructions?|prompts?|rules?|messages?)`),
	r("role.spoof", 45, false, `(?i)(<\|?(im_start|system|developer|assistant)\b|\[/?INST\]|\[SYSTEM\]|^\s*(system|developer)\s*:)`),
	r("credential.exfiltration", 60, false, `(?i)(send|upload|exfiltrate|forward|transmit|post)\b.{0,100}\b(credentials?|secrets?|api[ _-]?keys?|access[ _-]?tokens?|passwords?|private[ _-]?keys?)`),
	r("instruction.conceal", 35, false, `(?i)(do not|don't|never)\s+(tell|inform|notify|mention|reveal)\b.{0,50}\b(user|human|operator)`),
	r("instruction.tool-hijack", 45, false, `(?i)(you must|you should|always|before (answering|responding)).{0,70}(call|invoke|execute|run)\s+(the\s+)?(tool|command|shell|function)`),
	r("instruction.policy-disable", 50, false, `(?i)(disable|bypass|turn off|ignore)\s+(the\s+|all\s+)?(safety|security|policy|guardrails?|filters?|firewall)`),
	r("instruction.authority", 35, false, `(?i)(new system instructions?|highest priority instruction|developer message follows|supersedes all previous)`),
	r("secret.private-key", 100, true, `-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	r("secret.aws", 100, true, `\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
	r("secret.github", 100, true, `\b(gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255})\b`),
	r("secret.provider", 100, true, `\b(sk-(proj-|ant-api[0-9]+-)?[A-Za-z0-9_-]{20,255}|xox[baprs]-[A-Za-z0-9-]{20,255})\b`),
	r("secret.bearer", 100, true, `(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}`),
	r("secret.assignment", 100, true, `(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|authorization)\b["']?\s*[:=]\s*["']?[^\s"',}]{8,}`),
	r("secret.jwt", 100, true, `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
}
var b64 = regexp.MustCompile(`[A-Za-z0-9+/_-]{12,}={0,2}`)

func normalized(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || r == '\u034f' {
			return -1
		}
		return r
	}, norm.NFKC.String(s))
}

// Analyze scans canonical JSON (including property names), normalized Unicode,
// and up to two bounded rounds of percent/base64 decoding.
func Analyze(v any) Report {
	s := string(wire.Canonical(v))
	seen := map[string]bool{}
	views := []string{s}
	found := map[string]Finding{}
	budget := len(s)*5 + 4096
	for i := 0; i < len(views) && i < 24; i++ {
		x := views[i]
		if seen[x] {
			continue
		}
		seen[x] = true
		for _, r := range rules {
			if r.re.MatchString(x) {
				found[r.id] = Finding{r.id, r.weight, r.secret}
			}
		}
		if i >= 8 {
			continue
		}
		add := func(y string) {
			if y != x && !seen[y] && len(y) <= budget && len(views) < 24 {
				budget -= len(y)
				views = append(views, y)
			}
		}
		add(normalized(x))
		if y, e := url.QueryUnescape(x); e == nil {
			add(y)
		}
		for _, m := range b64.FindAllString(x, 16) {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, e := enc.DecodeString(m); e == nil && utf8.Valid(b) {
					add(string(b))
					break
				}
			}
		}
	}
	out := Report{Findings: []Finding{}}
	for _, f := range found {
		out.Findings = append(out.Findings, f)
		out.Score += f.Weight
		out.Secret = out.Secret || f.Secret
	}
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].ID < out.Findings[j].ID })
	if out.Score > 100 {
		out.Score = 100
	}
	return out
}
func (r Report) IDs() []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}
func (r Report) Reject(mode string) bool {
	return mode != "audit" && r.Score >= map[string]int{"strict": 40, "lenient": 80}[mode]
}
