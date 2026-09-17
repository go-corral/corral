// Bridge harness: loads the corral pi bridge with a MOCK pi and a FAKE corral, and asserts
// the wire mapping + pi's asymmetric fail-closed behavior. Run by the gated Go test
// TestPiBridgeNodeHarness (node present). argv[2] = absolute path to pi-bridge.ts.
//
// The bridge is dependency-free annotation-free JS-in-.ts; we copy it to a .mjs and import it
// so this harness does not depend on node's TypeScript handling. CORRAL_BIN is read at the
// bridge's module load, so it is set BEFORE the import and never changed; per-call behavior is
// driven through the fake corral via FC_EXIT / FC_STDOUT / FC_MODE (read at each spawn).
import { writeFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const bridgePath = process.argv[2];
const tmp = mkdtempSync(join(tmpdir(), "corral-bridge-"));
const capture = join(tmp, "capture.json");
const fakeCorral = join(tmp, "fake-corral.sh");
// Captures the hook event on stdin; FC_MODE=signal kills itself (spawnSync .signal -> the
// bridge sees an infra failure); otherwise it prints FC_STDOUT and exits FC_EXIT.
writeFileSync(
  fakeCorral,
  `#!/bin/sh\ncat > "${capture}"\nif [ "$FC_MODE" = "signal" ]; then kill -KILL $$; fi\nprintf '%s' "$FC_STDOUT"\nexit \${FC_EXIT:-0}\n`,
  { mode: 0o755 },
);
process.env.CORRAL_BIN = fakeCorral;

// Copy the annotation-free bridge to .mjs and import its factory.
const mjs = join(tmp, "bridge.mjs");
writeFileSync(mjs, readFileSync(bridgePath, "utf8"));
const factory = (await import(pathToFileURL(mjs).href)).default;

const handlers = {};
factory({ on: (ev, fn) => (handlers[ev] = fn) });

let failures = 0;
const check = (cond, msg) => {
  if (!cond) {
    console.error("FAIL:", msg);
    failures++;
  }
};
const drive = (exit, stdout, mode) => {
  process.env.FC_EXIT = String(exit);
  process.env.FC_STDOUT = stdout || "";
  if (mode) process.env.FC_MODE = mode;
  else delete process.env.FC_MODE;
};
const sent = () => JSON.parse(readFileSync(capture, "utf8"));

// ---- tool_call: mapping + allow / deny / fail-closed-by-throw ----
drive(0, "");
let r = await handlers.tool_call({ toolName: "read", input: { path: "/x/secret" } });
check(r === undefined, "tool_call allow (exit 0) returns undefined");
let ev = sent();
check(ev.tool_name === "Read", "read -> Read");
check(ev.tool_input.file_path === "/x/secret", "read path -> file_path");
check(ev.hook_event_name === "PreToolUse", "tool_call sends PreToolUse");

drive(2, "");
r = await handlers.tool_call({ toolName: "read", input: { path: "/x" } });
check(r && r.block === true, "tool_call deny (exit 2) returns {block:true}");

drive(0, "", "signal"); // infra failure -> tool_call MUST throw (pi turns it into a block)
let threw = false;
try {
  await handlers.tool_call({ toolName: "read", input: { path: "/x" } });
} catch {
  threw = true;
}
check(threw, "tool_call throws when corral cannot run (fail-closed)");

drive(0, ""); // edit mapping
await handlers.tool_call({ toolName: "edit", input: { path: "/f", edits: [{ oldText: "a", newText: "b" }] } });
ev = sent();
check(ev.tool_name === "MultiEdit", "edit -> MultiEdit");
check(ev.tool_input.file_path === "/f", "edit path -> file_path");
check(
  ev.tool_input.edits[0].old_string === "a" && ev.tool_input.edits[0].new_string === "b",
  "edit oldText/newText -> old_string/new_string",
);

// ---- tool_result: withhold / clean / fail-closed-by-RETURN ----
drive(0, JSON.stringify({ hookSpecificOutput: { updatedToolOutput: [{ type: "text", text: "WITHHELD" }] } }));
r = await handlers.tool_result({ toolName: "read", input: {}, content: [{ type: "text", text: "secret" }] });
check(r && Array.isArray(r.content) && r.content[0].text === "WITHHELD", "tool_result withhold replaces content");

drive(0, "");
r = await handlers.tool_result({ toolName: "read", input: {}, content: [{ type: "text", text: "ok" }] });
check(r === undefined, "tool_result clean returns undefined (keep original)");

drive(0, "", "signal"); // infra failure -> MUST return a withhold, NOT throw (pi swallows throws)
r = await handlers.tool_result({ toolName: "read", input: {}, content: [{ type: "text", text: "secret" }] });
check(
  r && Array.isArray(r.content) && /withheld/i.test(r.content[0].text),
  "tool_result fails closed by RETURN (not throw) on infra error",
);

// ---- user_bash: deny / allow / fail-closed-by-RETURN ----
drive(2, "");
r = await handlers.user_bash({ command: "rm -rf /", cwd: "/" });
check(r && r.result && r.result.exitCode === 1, "user_bash deny returns a synthetic BashResult");
ev = sent();
check(ev.tool_name === "Bash" && ev.tool_input.command === "rm -rf /", "user_bash -> Bash{command}");

drive(0, "");
r = await handlers.user_bash({ command: "ls", cwd: "/" });
check(r === undefined, "user_bash allow returns undefined");

drive(0, "", "signal"); // infra failure -> MUST return a deny, NOT throw
r = await handlers.user_bash({ command: "x", cwd: "/" });
check(r && r.result && r.result.exitCode === 1, "user_bash fails closed by RETURN (not throw) on infra error");

// ---- before_agent_start: note ----
drive(0, JSON.stringify({ hookSpecificOutput: { additionalContext: "NOTE" } }));
r = await handlers.before_agent_start();
check(r && r.message && r.message.content === "NOTE", "before_agent_start returns the note as a message");

// ---- input: prompt secret scan (advisory: continue on clean/error, swallow+notify on hit) ----
let notified = null;
const inputCtx = { ui: { notify: (msg) => (notified = msg) } };

drive(0, ""); // clean prompt -> continue, no notify
notified = null;
r = await handlers.input({ type: "input", text: "hello", source: "interactive" }, inputCtx);
check(r && r.action === "continue", "input clean prompt -> continue");
check(notified === null, "input clean prompt -> no notify");
ev = sent();
check(ev.hook_event_name === "UserPromptSubmit" && ev.prompt === "hello", "input -> UserPromptSubmit{prompt}");

drive(0, JSON.stringify({ decision: "block", reason: "REDACT" })); // secret hit -> swallow + notify
notified = null;
r = await handlers.input({ type: "input", text: "ghp_x", source: "interactive" }, inputCtx);
check(r && r.action === "handled", "input secret prompt -> handled (swallowed)");
check(notified === "REDACT", "input secret prompt -> notifies corral's reason");

drive(0, "", "signal"); // hook error -> advisory: continue (do NOT gate the user on a scan failure)
r = await handlers.input({ type: "input", text: "x", source: "interactive" }, inputCtx);
check(r && r.action === "continue", "input continues (advisory) on a hook error");

if (failures > 0) {
  console.error(`${failures} bridge assertion(s) failed`);
  process.exit(1);
}
console.log("bridge harness: all assertions passed");
