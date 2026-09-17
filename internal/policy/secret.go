package policy

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"unicode/utf8"
)

// IncidentHint is the default incident-response next step appended to every secret-detection
// deny/withhold message. Exported so the PreToolUse, PostToolUse, and UserPromptSubmit paths share
// one consistent wording. It names no secret value.
const IncidentHint = "Treat this credential as potentially exposed: rotate/revoke it and inform IT/Security."

func incidentHintOr(configured string) string {
	if configured != "" {
		return configured
	}
	return IncidentHint
}

const defaultScanBytes int64 = 1 << 20 // 1 MiB

func scanLimit(maxScanBytes int64) int64 {
	if maxScanBytes <= 0 {
		return defaultScanBytes
	}
	return maxScanBytes
}

// capForScan returns b truncated to the scan cap. The result aliases b's backing array.
func capForScan(b []byte, maxScanBytes int64) []byte {
	if limit := scanLimit(maxScanBytes); int64(len(b)) > limit {
		return b[:limit]
	}
	return b
}

// SecretKind classifies a detected secret. The scanner reports only the kind and location, never
// the value, so deny messages and audit logs never leak the credential they caught.
type SecretKind string

const (
	KindPEMPrivateKey SecretKind = "a private key (PEM)"
	KindPEMBody       SecretKind = "PEM-encoded key material (a base64 body fragment)"
	KindAWSKey        SecretKind = "an AWS access key id"
	KindJWT           SecretKind = "a JWT"
	KindGitHubToken   SecretKind = "a GitHub token"
	KindSlackToken    SecretKind = "a Slack token"
	KindGoogleAPIKey  SecretKind = "a Google API key"
	KindStripeKey     SecretKind = "a Stripe live key"
	KindGCPServiceKey SecretKind = "a GCP service-account key"
	KindHighEntropy   SecretKind = "a high-entropy secret"
)

var knownFormats = []struct {
	kind SecretKind
	re   *regexp.Regexp
}{
	// Match both BEGIN and END: anchoring on BEGIN alone let a partial read that drops the first
	// line slip through (`tail`, `grep -v BEGIN`, offset `sed`/`dd`). The footer anchor closes the
	// common case; the base64-body detector below covers a header-and-footer-stripped middle chunk.
	{KindPEMPrivateKey, regexp.MustCompile(`-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY-----`)},
	// Two+ consecutive whole lines of base64 — the shape of a PEM/OpenSSH key body even when both
	// markers are stripped. Requiring consecutive full lines (not a single long token) keeps false
	// positives down: inline hashes and single data-URI lines don't match.
	{KindPEMBody, regexp.MustCompile(`(?m)^[A-Za-z0-9+/]{60,}={0,2}\r?$\n^[A-Za-z0-9+/]{60,}={0,2}\r?$`)},
	{KindAWSKey, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{KindJWT, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{KindGitHubToken, regexp.MustCompile(`\b(?:gh[opsru]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b`)},
	{KindSlackToken, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{KindGoogleAPIKey, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{KindStripeKey, regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{16,}\b`)},
	{KindGCPServiceKey, regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN`)},
}

// entropyTokenRe finds base64/base64url-ish runs that are candidate secrets for the (opt-in)
// entropy heuristic. Hex-only runs are excluded so git SHAs / checksums don't trip it.
var entropyTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)

type scanResult struct {
	kind SecretKind
}

// scanSecrets scans data for known-format secrets, and (when entropyThreshold > 0) high-entropy
// tokens, returning the first hit. It never returns the matched value, only the kind.
//
// It scans the raw bytes and each successively backslash-decoded copy. Raw JSON bytes are the
// problem: a token abutting a JSON escape (`…removed.\n\nghp_…`) has a word char before it, which
// defeats the leading \b anchor in every known-format regex — a fail-open. Decoding restores the
// boundary. MCP results are JSON-in-JSON (double-escaped `\\n`), so it loops to a fixed point;
// scanning every level is strictly additive, so it only ever catches more, never less.
func scanSecrets(data []byte, entropyThreshold float64) (scanResult, bool) {
	buf := data
	for pass := 0; ; pass++ {
		if res, hit := scanOnce(buf, entropyThreshold); hit {
			return res, hit
		}
		if pass >= maxUnescapePasses {
			break
		}
		decoded, changed := jsonUnescape(buf)
		if !changed {
			break
		}
		buf = decoded
	}
	return scanResult{}, false
}

// maxUnescapePasses bounds the decode loop. Realistic nesting is two levels (JSON-in-JSON for MCP
// results); the cap leaves headroom. jsonUnescape strictly shrinks, so the loop also terminates on
// its own via changed=false.
const maxUnescapePasses = 6

func scanOnce(data []byte, entropyThreshold float64) (scanResult, bool) {
	for _, f := range knownFormats {
		if f.re.Match(data) {
			return scanResult{kind: f.kind}, true
		}
	}
	if entropyThreshold > 0 {
		for _, tok := range entropyTokenRe.FindAll(data, -1) {
			if looksMixed(tok) && shannonEntropy(tok) >= entropyThreshold {
				return scanResult{kind: KindHighEntropy}, true
			}
		}
	}
	return scanResult{}, false
}

// jsonUnescape decodes backslash escape sequences in data and reports whether any decoding
// happened. It is deliberately lenient — not a JSON parser: it rewrites only recognized escapes
// and passes every other byte through unchanged, so it works on partial or non-JSON tool output.
// The point is to turn an escape whose trailing char is a word character (e.g. the 'n' in `\n`)
// back into its real, non-word byte, so the word-boundary anchors in knownFormats match a
// credential that abuts such an escape.
func jsonUnescape(data []byte) ([]byte, bool) {
	if !bytes.ContainsRune(data, '\\') {
		return data, false
	}
	out := make([]byte, 0, len(data))
	changed := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c != '\\' || i+1 >= len(data) {
			out = append(out, c)
			continue
		}
		switch data[i+1] {
		case 'n':
			out, i, changed = append(out, '\n'), i+1, true
		case 't':
			out, i, changed = append(out, '\t'), i+1, true
		case 'r':
			out, i, changed = append(out, '\r'), i+1, true
		case 'f':
			out, i, changed = append(out, '\f'), i+1, true
		case 'b':
			out, i, changed = append(out, '\b'), i+1, true
		case '/', '"', '\\':
			out, i, changed = append(out, data[i+1]), i+1, true
		case 'u':
			if r, ok := parseHex4(data, i+2); ok {
				out = utf8.AppendRune(out, r)
				i += 5
				changed = true
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out, changed
}

func parseHex4(data []byte, off int) (rune, bool) {
	if off+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[off : off+4] {
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		r = r<<4 | d
	}
	return r, true
}

// looksMixed requires a token to contain at least one letter and one digit, filtering out
// single-class runs (all-hex hashes, all-letter identifiers) that are rarely secrets.
func looksMixed(tok []byte) bool {
	var hasLetter, hasDigit bool
	for _, c := range tok {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetter = true
		}
	}
	return hasLetter && hasDigit
}

func shannonEntropy(s []byte) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range s {
		freq[b]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ScanResponseBytes scans tool-response bytes for secret material. Used by the PostToolUse ingress
// scan to withhold a secret-bearing MCP response from the model.
func ScanResponseBytes(data []byte, entropyThreshold float64) (SecretKind, bool) {
	res, hit := scanSecrets(data, entropyThreshold)
	return res.kind, hit
}

// ScanPromptText scans a user prompt for secret material. It caps the scanned bytes so a huge
// pasted prompt cannot dominate the hook. Used by the UserPromptSubmit hook to warn before a
// pasted credential reaches the model provider.
func ScanPromptText(text []byte, entropyThreshold float64, maxScanBytes int64) (SecretKind, bool) {
	res, hit := scanSecrets(capForScan(text, maxScanBytes), entropyThreshold)
	return res.kind, hit
}

// SecretScanRule denies writing or reading content that contains a secret. For write-style tools
// it scans the content being persisted; for Read it scans the target file's bytes, catching a
// secret in a renamed file the path-pattern gates would miss.
type SecretScanRule struct {
	EntropyThreshold float64  // >0 enables the high-entropy heuristic; 0 = known formats only
	MaxScanBytes     int64    // caps how much of a file is read for the Read scan; 0 → 1 MiB
	SkipRoots        []string // canonical directory prefixes exempt from scanning
	IncidentHint     string   // overrides the built-in IncidentHint; empty → default
}

func (r *SecretScanRule) Name() string { return "secret-scan" }

func (r *SecretScanRule) Evaluate(ev *HookEvent) (Decision, bool, error) {
	if ev.isMCP() {
		return r.evalMCPArgs(ev)
	}
	switch ev.ToolName {
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return r.evalWrite(ev)
	case "Read":
		return r.evalRead(ev)
	}
	return Decision{}, false, nil
}

// evalMCPArgs scans an MCP tool call's raw arguments for secret material — the egress footgun
// where a credential is pasted into an MCP argument a remote server could forward off the machine.
// It scans raw tool_input bytes so a secret at any depth is caught, and a non-object tool_input
// is handled without a fail-closed error.
func (r *SecretScanRule) evalMCPArgs(ev *HookEvent) (Decision, bool, error) {
	data := []byte(ev.ToolInput)
	if len(data) == 0 {
		return Decision{}, false, nil
	}
	if res, hit := scanSecrets(capForScan(data, r.MaxScanBytes), r.EntropyThreshold); hit {
		return Decision{
			Action: Deny,
			Rule:   r.Name(),
			Reason: fmt.Sprintf("the arguments to %s contain %s; sending a secret to an MCP tool is blocked by corral policy. %s", ev.ToolName, res.kind, incidentHintOr(r.IncidentHint)),
		}, true, nil
	}
	return Decision{}, false, nil
}

func (r *SecretScanRule) evalWrite(ev *HookEvent) (Decision, bool, error) {
	contents, err := ev.WriteContents()
	if err != nil {
		return Decision{}, false, err
	}
	for _, c := range contents {
		if res, hit := scanSecrets([]byte(c), r.EntropyThreshold); hit {
			return Decision{
				Action: Deny,
				Rule:   r.Name(),
				Reason: fmt.Sprintf("the content being written contains %s; writing secrets is blocked by corral policy. %s", res.kind, incidentHintOr(r.IncidentHint)),
			}, true, nil
		}
	}
	return Decision{}, false, nil
}

func (r *SecretScanRule) evalRead(ev *HookEvent) (Decision, bool, error) {
	paths, err := ev.FilePaths()
	if err != nil {
		return Decision{}, false, err
	}
	for _, raw := range paths {
		canon, err := Canonicalize(raw, ev.Cwd)
		if err != nil {
			return Decision{}, false, err
		}
		if r.skip(canon) {
			continue
		}
		res, hit, serr := r.scanFile(canon)
		if serr != nil {
			// The Read itself will surface the same error; do not block on a non-policy I/O failure.
			continue
		}
		if hit {
			return Decision{
				Action: Deny,
				Rule:   r.Name(),
				Reason: fmt.Sprintf("%s appears to contain %s; reading it is blocked by corral policy (resolved %q). %s", canon, res.kind, raw, incidentHintOr(r.IncidentHint)),
			}, true, nil
		}
	}
	return Decision{}, false, nil
}

func (r *SecretScanRule) skip(canon string) bool {
	for _, root := range r.SkipRoots {
		if Within(canon, root) {
			return true
		}
	}
	return false
}

// scanFile reads up to the byte cap from a regular file and scans it. Non-regular files are skipped.
func (r *SecretScanRule) scanFile(path string) (scanResult, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return scanResult{}, false, err
	}
	if !fi.Mode().IsRegular() {
		return scanResult{}, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return scanResult{}, false, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, scanLimit(r.MaxScanBytes)))
	if err != nil {
		return scanResult{}, false, err
	}
	res, hit := scanSecrets(data, r.EntropyThreshold)
	return res, hit, nil
}
