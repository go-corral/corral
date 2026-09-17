package policy

// SecretDirComponents and SecretDirPairs expose the unexported secret-directory classifier tables
// to the external drift-guard test, which lives in package policy_test because it also imports
// config (config imports policy, so an internal test importing config would be a cycle).
var (
	SecretDirComponents = secretDirComponents
	SecretDirPairs      = secretDirPairs
)
