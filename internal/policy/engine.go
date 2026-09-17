package policy

import "fmt"

// Rule evaluates a single policy concern against an event.
type Rule interface {
	Name() string
	// Evaluate returns a Decision and whether the rule matched. An error means the rule could
	// not reach a safe verdict; the engine propagates it and the hook harness fails closed.
	Evaluate(ev *HookEvent) (decision Decision, matched bool, err error)
}

// Engine evaluates an event against an ordered set of rules.
type Engine struct {
	rules []Rule
}

func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// Evaluate runs every rule. The first Deny short-circuits. A rule may match with an Allow — an
// audit-only "note" whose Rule/Reason is carried on the returned Allow decision. A later Deny
// wins over an earlier note. If no rule denies, the result is Allow (annotated with the first
// note, if any). Any rule error is returned and must be treated as fail-closed by the caller.
func (e *Engine) Evaluate(ev *HookEvent) (Decision, error) {
	var note Decision
	for _, r := range e.rules {
		d, matched, err := r.Evaluate(ev)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q: %w", r.Name(), err)
		}
		if !matched {
			continue
		}
		if d.Action == Deny {
			if d.Rule == "" {
				d.Rule = r.Name()
			}
			return d, nil
		}
		if note.Rule == "" {
			if d.Rule == "" {
				d.Rule = r.Name()
			}
			note = d
		}
	}
	if note.Rule != "" {
		return note, nil
	}
	return Decision{Action: Allow}, nil
}

// BlockedPathRule denies any tool call touching a path equal to or nested under one of the
// configured roots. Paths are canonicalized before matching, defeating symlink and traversal
// bypasses. Roots must already be canonical.
type BlockedPathRule struct {
	RuleName string
	Roots    []string
}

func (r *BlockedPathRule) Name() string {
	if r.RuleName != "" {
		return r.RuleName
	}
	return "blocked-path"
}

func (r *BlockedPathRule) Evaluate(ev *HookEvent) (Decision, bool, error) {
	paths, err := ev.FilePaths()
	if err != nil {
		return Decision{}, false, err
	}
	for _, raw := range paths {
		canon, err := Canonicalize(raw, ev.Cwd)
		if err != nil {
			return Decision{}, false, err
		}
		for _, root := range r.Roots {
			if Within(canon, root) {
				return Decision{
					Action: Deny,
					Rule:   r.Name(),
					Reason: fmt.Sprintf("access to %s is blocked by corral policy (resolved %q -> %q)", root, raw, canon),
				}, true, nil
			}
		}
	}
	return Decision{}, false, nil
}
