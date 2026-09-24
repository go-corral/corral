// Package health holds the result type of corral's readiness checks.
package health

// State is the outcome of one check.
type State int

const (
	OK State = iota
	Warn
	Fail
)

// Check is one readiness check. Reason explains a Warn or Fail; Fix is a command that resolves it.
type Check struct {
	State  State
	Label  string
	Value  string
	Reason string
	Fix    string
}
