package policy

// Fixes maps each rule name that a pre-tool-use deny can carry to its fix,
// the sentence after "Fix: ".
var Fixes = map[string]string{
	"always-blocked": "None, by design. No setting opens an always-blocked directory. Supported access goes through a provider, such as the SSH or Kubernetes provider. For a cloud credential in an environment variable, ask the user to add the variable to `providers.env.passthrough`.",
	"blocked-path":   "Ask the user to remove the entry from `providers.block.directories` or `providers.block.files` in the config that adds it.",
	"ai-ignore":      "If the task needs this path, ask the user to change the AI ignore file or `providers.aiignore.sources`.",
	"bash":           "None, by design. No setting allows this command. Do the task without the blocked operation, or ask the user to run the command outside the session.",
	"path-pattern":   "None, by design. No setting exempts this path. Ask the user to do this step outside the session.",
	"secret-scan":    "For a Read, ask the user whether the file holds a real credential. If it does not, the user can add the directory to `policy.secretScan.skipPaths`. For a Write or an MCP call, use a placeholder or an environment variable reference instead of the value. If the reason names a high-entropy secret that is not a credential, the user can raise `policy.secretScan.entropyThreshold`.",
}

const (
	failClosedFix     = "None. Corral could not check this call, so it blocked it. Tell the user the error."
	responseSecretFix = "Do not print the credential again. Pass it through an environment variable or a file path instead. If it is a high-entropy secret that is not a credential, the user can raise `policy.secretScan.entropyThreshold`."
)

// FailClosed is the block text for a call that corral could not check.
func FailClosed(detail string) string {
	return "blocked by corral policy [hook:fail-closed]: " + detail + ". Fix: " + failClosedFix
}

// Unscanned is the text that replaces a tool output that corral could not scan.
func Unscanned(why string) string {
	return withheld("fail-closed", "corral could not scan the output ("+why+")", "Tell the user the error.")
}

func withheld(rule, detail, fix string) string {
	return "output withheld by corral policy [hook:" + rule + "]: " + detail + ". The call ran. Fix: " + fix
}
