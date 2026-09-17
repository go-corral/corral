package pi

import _ "embed"

//go:embed pi-bridge.ts
var bridgeSource []byte

//go:embed pi-presence.ts
var presenceSource []byte
