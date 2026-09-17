package policy

// Action is the outcome of evaluating an event against policy.
type Action int

const (
	Allow Action = iota
	Deny
)

// String renders the lowercase action name. Every value other than Allow renders as "deny",
// mirroring the hook's allow-list gate so the audit log can never label a non-Allow verdict as "allow".
func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	default:
		return "deny"
	}
}

// Decision is the result of policy evaluation. There is no "error" action: evaluation errors are
// returned as Go errors and the hook harness fails closed (blocks).
type Decision struct {
	Action Action
	Rule   string // the rule that produced a Deny (audit log + block message)
	Reason string // human-readable explanation shown to Claude on a block
}
