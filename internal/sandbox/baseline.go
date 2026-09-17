package sandbox

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//go:embed baseline/sandbox-permissions.json
var baselineJSON []byte

// Rule is one filesystem allow rule from the baseline. Unknown JSON keys are
// rejected at load (fail-closed).
type Rule struct {
	Path            string   `json:"path"`
	Description     string   `json:"description"`
	Writeable       bool     `json:"writeable"`
	Archs           []string `json:"archs"`           // empty => both linux and macos
	Recursive       *bool    `json:"recursive"`       // macOS subtree vs node
	Regex           bool     `json:"regex"`           // macOS SBPL regex; Linux skips these
	Optional        bool     `json:"optional"`        // Linux: --bind-try (skip if missing)
	Create          bool     `json:"create"`          // mkdir -p before binding
	ResolveSymlinks bool     `json:"resolveSymlinks"` // emit the fully-resolved target, not the link
}

type baselineFile struct {
	Schema  string          `json:"$schema"`
	Comment json.RawMessage `json:"_comment"`
	Rules   []Rule          `json:"rules"`
}

var knownLinuxTokens = map[string]bool{"HOME": true, "AGENT_CONFIG_DIR": true, "XDG_RUNTIME_DIR": true}

// baselineRules is the validated embedded baseline, parsed once at init.
var baselineRules = mustLoadBaseline()

// BaselineRules returns the validated embedded baseline rules. The returned
// slice must not be mutated.
func BaselineRules() []Rule { return baselineRules }

// RulesFor returns the embedded baseline unioned with spec's agent-contributed
// rules. The agent-neutral baseline comes first; agent rules are appended
// after (matching the baseline's own later-rule-wins ordering). Returns a fresh
// slice so the caller never mutates BaselineRules's backing array.
func RulesFor(spec SandboxSpec) []Rule {
	out := make([]Rule, 0, len(baselineRules)+len(spec.AgentRules))
	out = append(out, baselineRules...)
	out = append(out, spec.AgentRules...)
	return out
}

// ExpandPath substitutes launch tokens into a baseline rule path. ok is false
// when the path references a token that is missing or empty; such a rule must
// be skipped (fail-safe: never compile a partially-resolved path).
func ExpandPath(s string, tokens map[string]string) (out string, ok bool) {
	ok = true
	out = os.Expand(s, func(name string) string {
		v := tokens[name]
		if v == "" {
			ok = false
		}
		return v
	})
	return out, ok
}

func mustLoadBaseline() []Rule {
	rules, err := loadBaseline(baselineJSON)
	if err != nil {
		panic("sandbox: embedded baseline invalid: " + err.Error())
	}
	if err := validateLinuxTokens(rules); err != nil {
		panic("sandbox: embedded baseline invalid: " + err.Error())
	}
	if err := validateMacOSTokens(rules); err != nil {
		panic("sandbox: embedded baseline invalid: " + err.Error())
	}
	return rules
}

// loadBaseline strict-decodes the baseline JSON and validates each rule.
func loadBaseline(data []byte) ([]Rule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var bf baselineFile
	if err := dec.Decode(&bf); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(bf.Rules) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	for i, r := range bf.Rules {
		if r.Path == "" || r.Description == "" {
			return nil, fmt.Errorf("rule %d: path and description are required", i)
		}
		if strings.ContainsAny(r.Path, "\t\n") {
			return nil, fmt.Errorf("rule %d: path %q contains a tab or newline", i, r.Path)
		}
		for _, a := range r.Archs {
			if a != "linux" && a != "macos" {
				return nil, fmt.Errorf("rule %d: arch %q is not linux|macos", i, a)
			}
		}
	}
	return bf.Rules, nil
}

func validateLinuxTokens(rules []Rule) error {
	for i, r := range rules {
		if !ArchMatch(r, "linux") || r.Regex {
			continue
		}
		var unknown string
		os.Expand(r.Path, func(name string) string {
			if !knownLinuxTokens[name] {
				unknown = name
			}
			return ""
		})
		if unknown != "" {
			return fmt.Errorf("rule %d (%q): unknown Linux token $%s", i, r.Path, unknown)
		}
	}
	return nil
}

var knownMacOSTokens = map[string]bool{
	"HOME": true, "AGENT_CONFIG_DIR": true, "SESSION_TMPDIR": true, "AGENT_BIN_DIR": true,
}

func validateMacOSTokens(rules []Rule) error {
	for i, r := range rules {
		if !ArchMatch(r, "macos") {
			continue
		}
		var unknown string
		os.Expand(r.Path, func(name string) string {
			if !knownMacOSTokens[name] {
				unknown = name
			}
			return ""
		})
		if unknown != "" {
			return fmt.Errorf("rule %d (%q): unknown macOS token $%s", i, r.Path, unknown)
		}
	}
	return nil
}

// ArchMatch reports whether a rule applies to goos. Empty archs means both.
func ArchMatch(r Rule, goos string) bool {
	if len(r.Archs) == 0 {
		return true
	}
	for _, a := range r.Archs {
		if a == goos {
			return true
		}
	}
	return false
}
