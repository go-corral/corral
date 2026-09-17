package cli

import (
	"slices"
	"testing"

	"github.com/go-corral/corral/internal/agents/claude/claudecfg"
)

// The events corral writes into settings.json (claudecfg.Subcommands) and the events cmdHook
// dispatches (hookDispatch) are separate string sets in separate packages. A rename or addition
// on one side only would register a hook that falls through to cmdHook's fail-closed "unknown
// event" block, breaking the session. This test is that coupling's guard, replacing the prose
// comment that once named it.
func TestHookDispatchMatchesRegisteredSubcommands(t *testing.T) {
	registered := claudecfg.Subcommands()
	for _, sub := range registered {
		if _, ok := hookDispatch[sub]; !ok {
			t.Errorf("claudecfg registers %q but cmdHook dispatches no such event (it would fall through to the fail-closed block)", sub)
		}
	}
	for event := range hookDispatch {
		if !slices.Contains(registered, event) {
			t.Errorf("cmdHook dispatches %q but claudecfg registers no such subcommand (dead handler?)", event)
		}
	}
}
