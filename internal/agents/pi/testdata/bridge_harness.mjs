// Bridge harness: loads the corral pi bridge with a MOCK pi and talks to the sidecar that the Go
// test serves at CORRAL_SIDECAR_SOCKET. argv[2] = path to pi-bridge.ts, argv[3] = mode:
//
//   events            asserts the event mapping and pi's fail-closed rules against the scripted
//                     sidecar of TestPiBridgeNodeHarness.
//   tool_call <json>  runs one tool_call with {toolName, input} and prints {result} or {threw}.
//   oversize          sends a tool_call over the event cap.
//
// The bridge is dependency-free annotation-free JS-in-.ts; we copy it to a .mjs and import it
// so this harness does not depend on node's TypeScript handling.
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [bridgePath, mode, arg] = process.argv.slice(2);
const tmp = mkdtempSync(join(tmpdir(), "corral-bridge-"));
process.on("exit", () => rmSync(tmp, { recursive: true, force: true }));

const TIMEOUT_MS = 1000;
const MAX_BUFFER = 64 * 1024;
let src = readFileSync(bridgePath, "utf8");
if (mode === "events") {
  for (const [from, to] of [
    ["const HOOK_TIMEOUT_MS = 15000;", `const HOOK_TIMEOUT_MS = ${TIMEOUT_MS};`],
    ["const MAX_BUFFER = 64 * 1024 * 1024;", `const MAX_BUFFER = ${MAX_BUFFER};`],
  ]) {
    if (!src.includes(from)) {
      console.error(`bridge has no ${JSON.stringify(from)} to lower`);
      process.exit(1);
    }
    src = src.replace(from, to);
  }
}
const mjs = join(tmp, "bridge.mjs");
writeFileSync(mjs, src);
const bridge = await import(pathToFileURL(mjs).href);

const handlers = {};
bridge.default({ on: (ev, fn) => (handlers[ev] = fn) });

let failures = 0;
const check = (cond, msg) => {
  if (!cond) {
    console.error("FAIL:", msg);
    failures++;
  }
};

if (mode === "tool_call") {
  const { toolName, input } = JSON.parse(arg);
  try {
    console.log(JSON.stringify({ result: (await handlers.tool_call({ toolName, input })) ?? null }));
  } catch (e) {
    console.log(JSON.stringify({ threw: e.message }));
  }
  process.exit(0);
}

if (mode === "oversize") {
  await handlers.tool_call({ toolName: "write", input: { path: "/x", content: "a".repeat(16 * 1024 * 1024) } });
  process.exit(0);
}

if (mode !== "events") {
  console.error(`unknown mode ${JSON.stringify(mode)}`);
  process.exit(1);
}

const socket = process.env.CORRAL_SIDECAR_SOCKET;
const useSocket = (p) => {
  if (p === undefined) delete process.env.CORRAL_SIDECAR_SOCKET;
  else process.env.CORRAL_SIDECAR_SOCKET = p;
};
const FAIL_PREFIX = "blocked by corral policy [hook:fail-closed]: cannot evaluate policy: ";
const FAIL_SUFFIX = ". Fix: None. Corral could not check this call, so it blocked it. Tell the user the error.";
const UNSCANNED_PREFIX = "output withheld by corral policy [hook:fail-closed]: corral could not scan the output";
const failText = (why) => FAIL_PREFIX + why + FAIL_SUFFIX;
const promptFailText = (why) => FAIL_PREFIX + why + ". The prompt was not sent. Fix: Restart the corral session.";
const unscannedText = (why) =>
  UNSCANNED_PREFIX + " (cannot evaluate policy: " + why + "). The call ran. Fix: Tell the user the error.";

const toolCallThrow = async (event) => {
  try {
    const r = await handlers.tool_call(event);
    return "returned " + JSON.stringify(r);
  } catch (e) {
    return e.message;
  }
};
let notified = null;
let notifiedLevel = null;
const inputCtx = {
  hasUI: true,
  ui: {
    notify: (msg, level) => {
      notified = msg;
      notifiedLevel = level;
    },
  },
};
const noteRun = async () => {
  const start = { systemPromptOptions: { sections: {} } };
  const r = await handlers.before_agent_start(start).catch(() => "threw");
  return { r, sections: JSON.stringify(start.systemPromptOptions.sections) };
};

// ---- tool_call: mapping, allow, deny ----
let r = await handlers.tool_call({ toolName: "read", input: { path: "/echo/secret" } });
let ev = JSON.parse(r.reason);
check(r && r.block === true, "tool_call /echo blocks");
check(ev.hook_event_name === "PreToolUse", "tool_call sends PreToolUse");
check(ev.tool_name === "Read" && ev.tool_input.file_path === "/echo/secret", "read{path} -> Read{file_path}");
check(/^pi-\d+$/.test(ev.session_id) && ev.cwd === process.cwd(), "tool_call sends session_id and cwd");

r = await handlers.tool_call({ toolName: "edit", input: { path: "/echo/f", edits: [{ oldText: "a", newText: "b" }] } });
ev = JSON.parse(r.reason);
check(ev.tool_name === "MultiEdit" && ev.tool_input.file_path === "/echo/f", "edit -> MultiEdit{file_path}");
check(
  ev.tool_input.edits[0].old_string === "a" && ev.tool_input.edits[0].new_string === "b",
  "edit oldText/newText -> old_string/new_string",
);

r = await handlers.tool_call({ toolName: "read", input: { path: "/ok" } });
check(r === undefined, "tool_call allow (exit 0) returns undefined");

r = await handlers.tool_call({ toolName: "read", input: { path: "/deny" } });
check(r && r.block === true && r.reason === "corral: DENIED", "tool_call deny blocks with the sidecar's reason");

// ---- user_bash: mapping, allow, deny ----
r = await handlers.user_bash({ command: "cat /echo", cwd: "/w" });
ev = JSON.parse(r.result.output);
check(ev.tool_name === "Bash" && ev.tool_input.command === "cat /echo" && ev.cwd === "/w", "user_bash -> Bash{command}");

r = await handlers.user_bash({ command: "ls", cwd: "/" });
check(r === undefined, "user_bash allow returns undefined");

r = await handlers.user_bash({ command: "cat /deny", cwd: "/" });
check(
  r && r.result && r.result.exitCode === 1 && r.result.output === "corral: DENIED" && r.result.cancelled === false,
  "user_bash deny returns a failed command with the reason as output",
);

// ---- tool_result: withhold, clean, non-zero exit, error answer ----
r = await handlers.tool_result({ toolName: "read", input: { path: "/echo" }, content: [{ type: "text", text: "s" }] });
ev = JSON.parse(r.content[0].text);
check(r && r.isError === false && ev.hook_event_name === "PostToolUse", "tool_result /echo returns the marker text");
check(ev.tool_name === "Read" && ev.tool_response[0].text === "s", "tool_result sends the mapped tool and its content");

r = await handlers.tool_result({ toolName: "read", input: { path: "/ok" }, content: [{ type: "text", text: "ok" }] });
check(r === undefined, "tool_result clean returns undefined (keep original)");

r = await handlers.tool_result({ toolName: "read", input: { path: "/deny" }, content: [] });
check(r && r.content[0].text === unscannedText("exit code 2"), "tool_result with exit code 2 is withheld");

r = await handlers.tool_result({ toolName: "read", input: { path: "/error" }, content: [] }).catch(() => "threw");
check(r && r.content && r.content[0].text === unscannedText("scripted error"), "tool_result error answer is withheld, no throw");

// ---- input: prompt block, clean, non-zero exit, unreadable output, error answer ----
notified = null;
r = await handlers.input({ type: "input", text: "hello", source: "interactive" }, inputCtx);
check(r && r.action === "continue" && notified === null, "input clean prompt continues without notify");

r = await handlers.input({ type: "input", text: "token /echo", source: "interactive" }, inputCtx);
ev = JSON.parse(notified);
check(r && r.action === "handled" && notifiedLevel === "warning", "input block decision swallows the prompt");
check(ev.hook_event_name === "UserPromptSubmit" && ev.prompt === "token /echo", "input notifies the sidecar's reason");

for (const [text, why] of [
  ["/deny", "exit code 2"],
  ["/garbage", "the policy hook output is unreadable"],
  ["/error", "scripted error"],
]) {
  notified = null;
  r = await handlers.input({ type: "input", text: text, source: "interactive" }, inputCtx);
  check(
    r && r.action === "handled" && notified === promptFailText(why) && notifiedLevel === "error",
    `input ${text} swallows the prompt with the fail-closed text (got ${notified})`,
  );
}

const stderrWrite = process.stderr.write;
let written = "";
process.stderr.write = (s) => ((written += s), true);
notified = null;
r = await handlers.input({ type: "input", text: "/deny", source: "rpc" }, { hasUI: false, ui: inputCtx.ui });
process.stderr.write = stderrWrite;
check(
  r && r.action === "handled" && notified === null && written === promptFailText("exit code 2") + "\n",
  `input without a UI writes the fail-closed text to stderr (got ${written})`,
);

// ---- before_agent_start: section on each run ----
for (const run of [1, 2]) {
  const n = await noteRun();
  check(n.r === undefined && n.sections === JSON.stringify({ corral_sandbox_note: "NOTE" }), `run ${run} sets the note`);
}

// ---- tool_call failures through the scripted sidecar ----
let msg = await toolCallThrow({ toolName: "read", input: { path: "/error" } });
check(msg === failText("scripted error"), `tool_call error answer throws the fail-closed text (got ${msg})`);

// ---- socket unset ----
useSocket(undefined);
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(
  msg === failText("no sidecar: CORRAL_SIDECAR_SOCKET is not set inside the sandbox"),
  `tool_call with no socket names CORRAL_SIDECAR_SOCKET (got ${msg})`,
);
let n = await noteRun();
check(n.r === undefined && n.sections === "{}", "before_agent_start with no socket sets no note");

// ---- no listener ----
const missingSock = join(tmp, "missing.sock");
const missing = "dial sidecar " + missingSock + ": ENOENT";
useSocket(missingSock);
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(msg === failText(missing), `tool_call on a missing socket fails closed (got ${msg})`);
r = await handlers.user_bash({ command: "ls", cwd: "/" });
check(
  r && r.result && r.result.exitCode === 1 && r.result.output === failText(missing),
  "user_bash on a missing socket returns a failed command",
);

// ---- protocol faults from scripted node servers ----
const fake = async (name, onConn) => {
  const p = join(tmp, name);
  const srv = createServer(onConn);
  await new Promise((res) => srv.listen(p, res));
  return p;
};
useSocket(await fake("silent.sock", () => {}));
const t0 = Date.now();
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(msg === failText("timeout"), `tool_call times out with the fail-closed text (got ${msg})`);
check(Date.now() - t0 < TIMEOUT_MS * 3, "tool_call timeout fires at the lowered deadline");

useSocket(await fake("nonote.sock", (c) => c.end(JSON.stringify({ response: { code: 0, stdout: "", stderr: "", error: "" } }) + "\n")));
n = await noteRun();
check(n.r === undefined && n.sections === "{}", "before_agent_start with no note sets no note");

useSocket(await fake("both.sock", (c) => c.end('{"question":{"op":"eval-symlinks","path":"/"},"response":{"code":0}}\n')));
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(msg.startsWith(FAIL_PREFIX + "malformed sidecar answer"), `a line with question and response fails (got ${msg})`);

useSocket(await fake("garbage.sock", (c) => c.end("not json\n")));
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(msg.startsWith(FAIL_PREFIX + "malformed sidecar answer"), `a malformed line fails (got ${msg})`);

useSocket(await fake("long.sock", (c) => c.end("x".repeat(MAX_BUFFER + 1))));
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(msg === failText(`sidecar line exceeds ${MAX_BUFFER} characters`), `a line over MAX_BUFFER fails (got ${msg})`);

useSocket(
  await fake("unknown.sock", (c) => {
    c.on("error", () => {});
    c.write('{"question":{"op":"bogus","path":"/"}}\n');
  }),
);
msg = await toolCallThrow({ toolName: "read", input: { path: "/x" } });
check(msg === failText('unknown sidecar question "bogus"'), `an unknown op fails (got ${msg})`);

useSocket(socket);
if (failures > 0) {
  console.error(`${failures} bridge assertion(s) failed`);
  process.exit(1);
}
console.log("bridge harness: all assertions passed");
process.exit(0);
