package opencode

import _ "embed"

//go:embed opencode-policy.js
var policySource []byte

//go:embed opencode-presence.js
var presenceSource []byte
