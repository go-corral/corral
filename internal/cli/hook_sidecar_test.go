package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
)

// bareSession makes the hook evaluate in-process, as in a session started without corral run.
func bareSession(t *testing.T) {
	t.Helper()
	t.Setenv(sandbox.SandboxEnvVar, "")
	t.Setenv(sandbox.SidecarSocketEnvVar, "")
}

// serveHandler serves h on a sidecar and points the hook at it, as inside the sandbox.
func serveHandler(t *testing.T, h sidecar.Handler) {
	t.Helper()
	// Start creates the socket under $TMPDIR. A test TMPDIR under t.TempDir() can push the
	// socket path over the unix socket limit, so the socket goes under the default temp dir.
	// The test's TMPDIR comes back after Start, because the hook markers live under it.
	tmp := os.Getenv("TMPDIR")
	t.Setenv("TMPDIR", "")
	s, err := sidecar.Start(h)
	t.Setenv("TMPDIR", tmp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv(sandbox.SidecarSocketEnvVar, s.Path())
}

// serveTestSidecar serves the policy built from in, as the launcher does.
func serveTestSidecar(t *testing.T, in engineInputs) {
	t.Helper()
	h, err := policyHandler(in)
	if err != nil {
		t.Fatal(err)
	}
	serveHandler(t, h)
}

// startTestSidecar isolates the config under home, runs from proj, and serves the policy
// localEngineInputs resolves there.
func startTestSidecar(t *testing.T, home, proj string) {
	t.Helper()
	isolateConfigEnv(t, home, proj)
	in, err := localEngineInputs()
	if err != nil {
		t.Fatal(err)
	}
	serveTestSidecar(t, in)
}

// blockedProject creates home/proj with a .corral.yml that blocks home/vault.
func blockedProject(t *testing.T) (home, proj string) {
	t.Helper()
	home = t.TempDir()
	proj = filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCorralYML(t, proj, "providers:\n  block:\n    directories: ["+filepath.Join(home, "vault")+"]\n")
	return home, proj
}

// testEngineInputs blocks home/vault and logs to home/audit.
func testEngineInputs(t *testing.T) (in engineInputs, vault string) {
	t.Helper()
	home := t.TempDir()
	vault = filepath.Join(home, "vault")
	cfg := &config.Config{}
	cfg.Providers.Block.Directories = []string{vault}
	return engineInputs{
		cfg:       cfg,
		home:      home,
		env:       map[string]string{"HOME": home},
		workDir:   home,
		auditPath: filepath.Join(home, "audit", "corral-audit.jsonl"),
	}, vault
}

// sandboxFS is a hook-side filesystem with symlinks and files the host does not have. Other
// paths resolve on the host.
type sandboxFS struct {
	links map[string]string
	files map[string]string
}

func (f sandboxFS) EvalSymlinks(p string) (string, error) {
	if target, ok := f.links[p]; ok {
		return target, nil
	}
	if _, ok := f.files[p]; ok {
		return p, nil
	}
	return policy.OSFS{}.EvalSymlinks(p)
}

func (f sandboxFS) ReadRegular(p string, limit int64) ([]byte, bool, error) {
	if c, ok := f.files[p]; ok {
		return []byte(c), true, nil
	}
	return policy.OSFS{}.ReadRegular(p, limit)
}

func writePreToolUse(file string) string {
	return fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/","tool_input":{"file_path":%q,"content":"{}"}}`, file)
}

func TestPolicyHandler(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	in, vault := testEngineInputs(t)
	h, err := policyHandler(in)
	if err != nil {
		t.Fatal(err)
	}
	blocked := []byte(preToolUseEvent(t, in.home, filepath.Join(vault, "creds")))

	resp := h(sidecar.Request{Type: "pre-tool-use", Decision: "json"}, blocked, policy.OSFS{})
	if resp.Code != policy.ExitAllow || !strings.Contains(resp.Stdout, `"permissionDecision":"deny"`) || resp.Stderr != "" || resp.Error != "" {
		t.Errorf("JSON deny: got %+v", resp)
	}

	resp = h(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, blocked, policy.OSFS{})
	if resp.Code != policy.ExitBlock || resp.Stdout != "" || !strings.Contains(resp.Stderr, "[hook:blocked-path]") || resp.Error != "" {
		t.Errorf("exit2 deny: got %+v", resp)
	}

	post := `{"hook_event_name":"PostToolUse","tool_name":"mcp__db__get","tool_response":"the value is ` + promptAWSKey + `"}`
	resp = h(sidecar.Request{Type: "post-tool-use"}, []byte(post), policy.OSFS{})
	if resp.Code != policy.ExitAllow || !strings.Contains(resp.Stdout, `"updatedToolOutput"`) || strings.Contains(resp.Stdout, promptAWSKey) || resp.Error != "" {
		t.Errorf("secret response: got %+v", resp)
	}

	resp = h(sidecar.Request{Type: "user-prompt-submit"}, []byte(promptEvent("s1", "key "+promptAWSKey)), policy.OSFS{})
	if resp.Code != policy.ExitAllow || !strings.Contains(resp.Stdout, `"block"`) || strings.Contains(resp.Stdout, promptAWSKey) || resp.Error != "" {
		t.Errorf("secret prompt: got %+v", resp)
	}

	if resp = h(sidecar.Request{Type: "session-start"}, nil, policy.OSFS{}); resp.Error == "" {
		t.Errorf("unknown request type: got %+v, want an error", resp)
	}

	data, err := os.ReadFile(in.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{`"rule":"blocked-path"`, `"rule":"response-secret"`, `"rule":"prompt-secret-scan"`} {
		if !strings.Contains(string(data), rule) {
			t.Errorf("audit log missing %s:\n%s", rule, data)
		}
	}
}

// lexicalFS sees the paths under dir without resolving symlinks, as bwrap does for a bind
// whose host parent is a symlink. Other paths resolve on the host.
type lexicalFS struct{ dir string }

func (f lexicalFS) EvalSymlinks(p string) (string, error) {
	if p == f.dir || strings.HasPrefix(p, f.dir+string(filepath.Separator)) {
		return filepath.Clean(p), nil
	}
	return policy.OSFS{}.EvalSymlinks(p)
}

func (f lexicalFS) ReadRegular(p string, limit int64) ([]byte, bool, error) {
	return policy.OSFS{}.ReadRegular(p, limit)
}

// A blocked directory and an AI ignore root behind a host symlink stay protected when the
// sandbox sees the paths without the symlink.
func TestPolicyHandlerResolvesRootsInTheEventFS(t *testing.T) {
	in, _ := testEngineInputs(t)
	link := filepath.Join(in.home, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(link, "vault")
	in.cfg.Providers.Block.Directories = []string{vault}
	in.workDir = filepath.Join(link, "proj")
	if err := os.Mkdir(in.workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.workDir, ".aiignore"), []byte("notes.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := policyHandler(in)
	if err != nil {
		t.Fatal(err)
	}
	for file, rule := range map[string]string{
		filepath.Join(vault, "creds"):          "[hook:blocked-path]",
		filepath.Join(in.workDir, "notes.txt"): "[hook:ai-ignore]",
	} {
		event := []byte(preToolUseEvent(t, in.home, file))
		resp := h(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, event, lexicalFS{dir: link})
		if resp.Code != policy.ExitBlock || !strings.Contains(resp.Stderr, rule) {
			t.Errorf("%s: got %+v, want a %s deny", file, resp, rule)
		}
	}
}

// The sidecar serves connections concurrently, so the handler is called concurrently.
func TestPolicyHandlerConcurrent(t *testing.T) {
	in, vault := testEngineInputs(t)
	h, err := policyHandler(in)
	if err != nil {
		t.Fatal(err)
	}
	blocked := []byte(preToolUseEvent(t, in.home, filepath.Join(vault, "creds")))

	const n = 8
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := h(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, blocked, policy.OSFS{}); resp.Code != policy.ExitBlock {
				t.Errorf("concurrent deny: got %+v", resp)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(in.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"); got != n {
		t.Errorf("want %d audit records, got %d:\n%s", n, got, data)
	}
}

func TestEvaluateInsideSandboxWithoutSidecar(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv(sandbox.SidecarSocketEnvVar, "")
	resp := evaluate(sidecar.Request{Type: "pre-tool-use"}, []byte(bashPreToolUse("ls")))
	if !strings.Contains(resp.Error, sandbox.SidecarSocketEnvVar) {
		t.Errorf("got %+v, want an error naming %s", resp, sandbox.SidecarSocketEnvVar)
	}
}

// A bare session denies a path its own config blocks and audits to the path its own
// environment and config resolve.
func TestEvaluateBareSessionBlocksConfiguredPath(t *testing.T) {
	home, proj := blockedProject(t)
	isolateConfigEnv(t, home, proj)
	bareSession(t)

	resp := evaluate(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, []byte(preToolUseEvent(t, proj, filepath.Join(home, "vault", "creds"))))
	if resp.Error != "" || resp.Code != policy.ExitBlock {
		t.Fatalf("got %+v, want a deny", resp)
	}
	data, err := os.ReadFile(defaultAuditPath(filepath.Join(home, ".local", "state"), filepath.Join(home, ".claude")))
	if err != nil || !strings.Contains(string(data), `"rule":"blocked-path"`) {
		t.Errorf("audit record missing (err %v):\n%s", err, data)
	}
}

// A bare session fails closed on a relative agent config dir for every event, also for the
// events that build no engine.
func TestEvaluateBareSessionRefusesRelativeConfigDir(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	isolateConfigEnv(t, home, proj)
	bareSession(t)
	t.Setenv("CLAUDE_CONFIG_DIR", "relcfg")

	for _, typ := range []string{"pre-tool-use", "post-tool-use", "user-prompt-submit"} {
		resp := evaluate(sidecar.Request{Type: typ}, []byte(bashPreToolUse("ls")))
		if !strings.Contains(resp.Error, `relative path "relcfg"`) {
			t.Errorf("%s: got %+v, want an error naming the relative config dir", typ, resp)
		}
	}
}

func TestEvaluateBareSessionConfigLoadError(t *testing.T) {
	home := t.TempDir()
	writeCorralYML(t, home, "providers:\n  block: {directories: [/data/vault\n")
	isolateConfigEnv(t, home, home)
	bareSession(t)

	resp := evaluate(sidecar.Request{Type: "pre-tool-use"}, []byte(bashPreToolUse("ls")))
	if !strings.Contains(resp.Error, "load config") {
		t.Errorf("got %+v, want a load config error", resp)
	}
}

// A bare session applies the profiles in CORRAL_PROFILES, and a missing one fails with an
// error that names it.
func TestEvaluateBareSessionAppliesProfiles(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, "strict-only.txt")
	writeCorralYML(t, proj, "profiles:\n  strict:\n    providers:\n      block:\n        files:\n          - "+secret+"\n")
	isolateConfigEnv(t, home, proj)
	bareSession(t)
	ev := []byte(preToolUseEvent(t, proj, secret))
	req := sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}

	for _, tc := range []struct {
		profiles string
		want     int
	}{
		{profiles: "strict", want: policy.ExitBlock},
		{profiles: "", want: policy.ExitAllow},
	} {
		t.Setenv(sandbox.ProfilesEnvVar, tc.profiles)
		if resp := evaluate(req, ev); resp.Error != "" || resp.Code != tc.want {
			t.Errorf("%s=%q: got %+v, want code %d", sandbox.ProfilesEnvVar, tc.profiles, resp, tc.want)
		}
	}

	t.Setenv(sandbox.ProfilesEnvVar, "gone")
	if resp := evaluate(req, ev); !strings.Contains(resp.Error, `"gone"`) {
		t.Errorf("missing profile: got %+v, want an error naming it", resp)
	}
}

// The same event gives the same answer through the sidecar and in a bare session, both built
// from the values localEngineInputs resolves.
func TestSidecarAndBareSessionAgree(t *testing.T) {
	home, proj := blockedProject(t)
	isolateConfigEnv(t, home, proj)
	bareSession(t)
	in, err := localEngineInputs()
	if err != nil {
		t.Fatal(err)
	}
	ev := []byte(preToolUseEvent(t, proj, filepath.Join(home, "vault", "creds")))
	reqs := []sidecar.Request{{Type: "pre-tool-use", Decision: "json"}, {Type: "pre-tool-use", Decision: "exit2"}}

	var bare []sidecar.Response
	for _, req := range reqs {
		bare = append(bare, evaluate(req, ev))
	}
	serveTestSidecar(t, in)
	for i, req := range reqs {
		got := evaluate(req, ev)
		if got.Error != "" {
			t.Fatalf("%+v: sidecar answered with an error: %s", req, got.Error)
		}
		if got != bare[i] {
			t.Errorf("%+v: sidecar answer %+v differs from bare answer %+v", req, got, bare[i])
		}
	}
}

func TestCmdHookPreToolUseRejectsRemovedFlags(t *testing.T) {
	for _, args := range [][]string{{"--block-path", "/x"}, {"--profile", "strict"}, {"-p", "strict"}} {
		var code int
		stderr := captureStderr(t, func() { code = cmdHook(append([]string{"pre-tool-use"}, args...)) })
		if code != policy.ExitBlock || !strings.Contains(stderr, "bad hook arguments") {
			t.Errorf("%v: got exit %d, stderr %q; want exit 2 with a bad-arguments message", args, code, stderr)
		}
	}
}

func TestCmdHookPreToolUseRejectsUnknownDecision(t *testing.T) {
	serveHandler(t, func(sidecar.Request, []byte, policy.FS) sidecar.Response { return sidecar.Response{} })
	var code int
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			withStdin(t, bashPreToolUse("ls -la"), func() { code = cmdHook([]string{"pre-tool-use", "--decision", "yaml"}) })
		})
	})
	if code != policy.ExitBlock {
		t.Errorf("got exit %d, want %d", code, policy.ExitBlock)
	}
	if !strings.Contains(stderr, "corral: "+policy.FailClosed("bad hook arguments")) {
		t.Errorf("stderr = %q, want the bad-arguments message", stderr)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
}

// Inside the sandbox, a missing or dead sidecar blocks with a message that names the cause.
func TestCmdHookPreToolUseWithoutSidecarBlocks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		socket func(t *testing.T) string
		want   string
	}{
		{"unset", func(*testing.T) string { return "" }, sandbox.SidecarSocketEnvVar},
		{"dead socket", func(t *testing.T) string { return filepath.Join(t.TempDir(), "sock") }, "dial sidecar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(sandbox.SandboxEnvVar, "1")
			t.Setenv(sandbox.SidecarSocketEnvVar, tc.socket(t))
			var code int
			stderr := captureStderr(t, func() {
				withStdin(t, bashPreToolUse("ls -la"), func() { code = cmdHook([]string{"pre-tool-use"}) })
			})
			if code != policy.ExitBlock {
				t.Errorf("got exit %d, want %d", code, policy.ExitBlock)
			}
			if !strings.Contains(stderr, "[hook:fail-closed]: cannot evaluate policy: ") || !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr must name the cause %q, got %q", tc.want, stderr)
			}
		})
	}
}

func TestCmdHookPreToolUseForwardsSidecarDeny(t *testing.T) {
	home, proj := blockedProject(t)
	startTestSidecar(t, home, proj)
	ev := preToolUseEvent(t, proj, filepath.Join(home, "vault", "creds"))
	want := sidecar.Call(os.Getenv(sandbox.SidecarSocketEnvVar), sidecar.Request{Type: "pre-tool-use", Decision: "json"}, []byte(ev), policy.OSFS{})
	if !strings.Contains(want.Stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("sidecar answer is not a JSON deny: %+v", want)
	}

	var code int
	out := captureStdout(t, func() {
		withStdin(t, ev, func() { code = cmdHook([]string{"pre-tool-use"}) })
	})
	if code != policy.ExitAllow {
		t.Errorf("got exit %d, want %d", code, policy.ExitAllow)
	}
	if out != want.Stdout {
		t.Errorf("stdout = %q, want the sidecar answer %q", out, want.Stdout)
	}
}

// The hook exits with the answer's code only when it is 0 or 2.
func TestCmdHookPreToolUseAnswerCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer sidecar.Response
		want   int
	}{
		{"allow", sidecar.Response{}, policy.ExitAllow},
		{"block", sidecar.Response{Code: policy.ExitBlock}, policy.ExitBlock},
		{"other code", sidecar.Response{Code: 1}, policy.ExitBlock},
		{"error", sidecar.Response{Error: "boom"}, policy.ExitBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serveHandler(t, func(sidecar.Request, []byte, policy.FS) sidecar.Response { return tc.answer })
			var code int
			captureStderr(t, func() {
				withStdin(t, bashPreToolUse("ls -la"), func() { code = cmdHook([]string{"pre-tool-use"}) })
			})
			if code != tc.want {
				t.Errorf("got exit %d, want %d", code, tc.want)
			}
		})
	}
}

// updatedToolOutput decodes the replacement a post-tool-use hook wrote.
func updatedToolOutput(t *testing.T, out string) any {
	t.Helper()
	var top struct {
		HookSpecificOutput struct {
			UpdatedToolOutput any `json:"updatedToolOutput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("replacement is not valid JSON: %v (%q)", err, out)
	}
	return top.HookSpecificOutput.UpdatedToolOutput
}

// A dead sidecar withholds the result in the shape of the original: an MCP content-block array.
func TestCmdHookPostToolUseDeadSidecarWithholds(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv(sandbox.SidecarSocketEnvVar, filepath.Join(t.TempDir(), "sock"))
	ev := `{"hook_event_name":"PostToolUse","tool_name":"mcp__docs__search","tool_response":[{"type":"text","text":"hello"}]}`

	var code int
	out := captureStdout(t, func() {
		captureStderr(t, func() {
			withStdin(t, ev, func() { code = cmdHook([]string{"post-tool-use"}) })
		})
	})
	if code != policy.ExitAllow {
		t.Errorf("got exit %d, want %d", code, policy.ExitAllow)
	}
	blocks, ok := updatedToolOutput(t, out).([]any)
	if !ok || len(blocks) != 1 || !strings.Contains(out, "withheld") {
		t.Errorf("want a content-block array carrying the withheld marker, got %q", out)
	}
}

func TestCmdHookPostToolUseSidecarWithholdsSecret(t *testing.T) {
	home := t.TempDir()
	startTestSidecar(t, home, home)
	ev := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"key=` + promptAWSKey + `","stderr":"","interrupted":false}}`

	var code int
	out := captureStdout(t, func() {
		withStdin(t, ev, func() { code = cmdHook([]string{"post-tool-use"}) })
	})
	if code != policy.ExitAllow {
		t.Errorf("got exit %d, want %d", code, policy.ExitAllow)
	}
	obj, ok := updatedToolOutput(t, out).(map[string]any)
	if !ok || !strings.Contains(out, "withheld") || strings.Contains(out, promptAWSKey) {
		t.Errorf("want a Bash-shaped replacement without the secret, got %q", out)
	}
	if _, ok := obj["interrupted"]; !ok {
		t.Errorf("the replacement must keep the original's other fields, got %v", obj)
	}
}

// The sidecar resolves event paths in the hook's filesystem: a symlink and a file that only the
// hook sees decide the answer.
func TestSidecarEvaluatesPathsInHookFS(t *testing.T) {
	in, _ := testEngineInputs(t)
	serveTestSidecar(t, in)
	sock := os.Getenv(sandbox.SidecarSocketEnvVar)
	tmp := t.TempDir()
	link, result := filepath.Join(tmp, "e"), filepath.Join(tmp, "result.txt")
	hookFS := sandboxFS{
		links: map[string]string{link: filepath.Join(in.home, ".claude", "settings.json")},
		files: map[string]string{result: "key=" + promptAWSKey},
	}
	req := sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}
	for name, ev := range map[string]string{
		"Write through a symlink": writePreToolUse(link),
		"Bash redirect":           bashPreToolUse("cat payload > " + link),
		"Read a secret":           preToolUseEvent(t, "/", result),
	} {
		t.Run(name, func(t *testing.T) {
			if resp := sidecar.Call(sock, req, []byte(ev), policy.OSFS{}); resp.Error != "" || resp.Code != policy.ExitAllow {
				t.Fatalf("host view: got %+v, want an allow", resp)
			}
			if resp := sidecar.Call(sock, req, []byte(ev), hookFS); resp.Error != "" || resp.Code != policy.ExitBlock {
				t.Errorf("hook view: got %+v, want a deny", resp)
			}
		})
	}
}

// A bare session builds the engine only for pre-tool-use: a block path that cannot be
// canonicalized fails that event and no other.
func TestEvaluateBareSessionBuildsEngineOnlyForPreToolUse(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeCorralYML(t, home, "providers:\n  block:\n    directories: ["+filepath.Join(file, "sub")+"]\n")
	isolateConfigEnv(t, home, home)
	bareSession(t)

	if resp := evaluate(sidecar.Request{Type: "pre-tool-use"}, []byte(bashPreToolUse("ls"))); !strings.Contains(resp.Error, "canonicalize") {
		t.Errorf("pre-tool-use: got %+v, want a canonicalize error", resp)
	}
	post := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"ok","stderr":"","interrupted":false}}`
	for req, payload := range map[string]string{"post-tool-use": post, "user-prompt-submit": promptEvent("s1", "hello")} {
		if resp := evaluate(sidecar.Request{Type: req}, []byte(payload)); resp.Error != "" {
			t.Errorf("%s: got %+v, want no error", req, resp)
		}
	}
}

// bwrapHookEnv carries a bwrapHookCase to the test binary inside bwrap.
const bwrapHookEnv = "CORRAL_TEST_BWRAP_HOOK"

type bwrapHookCase struct {
	Socket, Target, Link, Result, Plain string
}

// Inside bwrap, /tmp is private. A secret in it and a symlink in it to the agent config are
// denied, although the host sees neither.
func TestSidecarSeesSandboxPrivateTmp(t *testing.T) {
	if raw := os.Getenv(bwrapHookEnv); raw != "" {
		var c bwrapHookCase
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		bwrapHookClient(t, c)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("bwrap is Linux-only")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not available on this system")
	}
	in, _ := testEngineInputs(t)
	target := filepath.Join(in.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	serveTestSidecar(t, in)
	sock := os.Getenv(sandbox.SidecarSocketEnvVar)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("/tmp/corral-bwrap-test-%d-", os.Getpid())
	c := bwrapHookCase{Socket: sock, Target: target, Link: prefix + "e", Result: prefix + "result.txt", Plain: prefix + "plain.txt"}
	raw, _ := json.Marshal(c)
	cmd := exec.Command(bwrap,
		"--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
		"--ro-bind", filepath.Dir(sock), filepath.Dir(sock),
		"--bind", in.home, in.home,
		"--ro-bind", self, self,
		"--chdir", "/",
		self, "-test.run=^TestSidecarSeesSandboxPrivateTmp$", "-test.v")
	cmd.Env = append(os.Environ(), bwrapHookEnv+"="+string(raw))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Creating new namespace failed") {
			t.Skipf("bwrap cannot run here: %s", out)
		}
		t.Fatalf("in-sandbox hook failed: %v\n%s", err, out)
	}
	for _, p := range []string{c.Link, c.Result, c.Plain} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s is visible on the host (err %v), so the test does not exercise a private /tmp", p, err)
		}
	}
}

func bwrapHookClient(t *testing.T, c bwrapHookCase) {
	t.Helper()
	if err := os.Symlink(c.Target, c.Link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Result, []byte("key="+"AKIA"+strings.Repeat("Q", 16)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Plain, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv(sandbox.SidecarSocketEnvVar, c.Socket)
	req := sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}
	for _, tc := range []struct {
		name, ev string
		want     int
	}{
		{"Read a secret", preToolUseEvent(t, "/", c.Result), policy.ExitBlock},
		{"Write through a symlink", writePreToolUse(c.Link), policy.ExitBlock},
		{"Bash redirect", bashPreToolUse("cat payload > " + c.Link), policy.ExitBlock},
		{"Read a plain file", preToolUseEvent(t, "/", c.Plain), policy.ExitAllow},
	} {
		if resp := evaluate(req, []byte(tc.ev)); resp.Error != "" || resp.Code != tc.want {
			t.Errorf("%s: got %+v, want code %d", tc.name, resp, tc.want)
		}
	}
}
