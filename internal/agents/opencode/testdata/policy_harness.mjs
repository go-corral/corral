// Policy harness: loads the corral opencode policy plugin with a MOCK opencode V2 ctx and talks to
// the sidecar that the Go test serves at CORRAL_SIDECAR_SOCKET. argv[2] = path to
// opencode-policy.js, argv[3] = mode:
//
//   events            asserts the hooks against the scripted sidecar of TestOpencodePolicyNodeHarness.
//   tool <json>       runs execute.before with {tool, input} and prints {threw}.
//
// We copy the plugin to a .mjs so node loads it as an ES module without a package.json.
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [pluginPath, mode, arg] = process.argv.slice(2);
const tmp = mkdtempSync(join(tmpdir(), "corral-opencode-policy-"));
process.on("exit", () => rmSync(tmp, { recursive: true, force: true }));

const TIMEOUT_MS = 1000;
const MAX_BUFFER = 64 * 1024;
let src = readFileSync(pluginPath, "utf8");
if (mode === "events") {
  for (const [from, to] of [
    ["const HOOK_TIMEOUT_MS = 15000;", `const HOOK_TIMEOUT_MS = ${TIMEOUT_MS};`],
    ["const MAX_BUFFER = 64 * 1024 * 1024;", `const MAX_BUFFER = ${MAX_BUFFER};`],
  ]) {
    if (!src.includes(from)) {
      console.error(`plugin has no ${JSON.stringify(from)} to lower`);
      process.exit(1);
    }
    src = src.replace(from, to);
  }
}
const mjs = join(tmp, "index.mjs");
writeFileSync(mjs, src);
const mod = await import(pathToFileURL(mjs).href);

let failures = 0;
const check = (cond, msg) => {
  if (!cond) {
    console.error("FAIL:", msg);
    failures++;
  }
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sameKeys = (a, b) => same(Object.entries(a).sort(), Object.entries(b).sort());

const DIR = mode === "events" ? "/work/app" : process.cwd();
const hooks = {};
const register = (domain) => (name, fn) => {
  hooks[domain + "." + name] = fn;
};
// registry is the mock tool and MCP server registry. The tests mutate it between calls.
const registry = {
  tools: [],
  servers: [],
  toolsError: null,
  serversError: null,
  toolCalls: 0,
  serverCalls: 0,
};
const ctx = {
  tool: {
    hook: register("tool"),
    list: async () => {
      registry.toolCalls++;
      if (registry.toolsError) throw new Error(registry.toolsError);
      return registry.tools;
    },
  },
  mcp: {
    list: async () => {
      registry.serverCalls++;
      if (registry.serversError) throw new Error(registry.serversError);
      return { location: {}, data: registry.servers };
    },
  },
  session: { hook: register("session") },
  location: { directory: DIR },
};

check(same(Object.keys(mod), ["default"]), `one export, the default (got ${Object.keys(mod)})`);
const plugin = mod.default;
check(
  plugin && plugin.id === "corral-policy" && typeof plugin.setup === "function" && same(Object.keys(plugin).sort(), ["id", "setup"]),
  "the default export is {id: \"corral-policy\", setup}",
);
await plugin.setup(ctx);
check(
  same(Object.keys(hooks).sort(), ["session.context", "session.prompt", "tool.execute.after", "tool.execute.before"]),
  `setup registers execute.before, execute.after, prompt, and context (got ${Object.keys(hooks)})`,
);

const before = async (tool, input) => {
  const ev = { tool, sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_1", input };
  try {
    await hooks["tool.execute.before"](ev);
    return { threw: null, ev };
  } catch (e) {
    return { threw: e.message, ev };
  }
};

if (mode === "tool") {
  const { tool, input } = JSON.parse(arg);
  console.log(JSON.stringify({ threw: (await before(tool, input)).threw }));
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
const PROMPT_PREFIX = "[corral withheld the user's prompt] ";
const PROMPT_SUFFIX = " Tell the user, without guessing the prompt's content.";
const promptFailedText = (why) =>
  PROMPT_PREFIX + FAIL_PREFIX + why + ". The prompt was not sent. Fix: Restart the corral session." + PROMPT_SUFFIX;
const DENIED = "DENIED";
const NO_SOCKET = "no sidecar: CORRAL_SIDECAR_SOCKET is not set inside the sandbox";
const failText = (why) => FAIL_PREFIX + why + FAIL_SUFFIX;
const unscannedText = (why) =>
  UNSCANNED_PREFIX + " (cannot evaluate policy: " + why + "). The call ran. Fix: Tell the user the error.";
const PLUGIN_FAILED = UNSCANNED_PREFIX + " (the opencode plugin failed). The call ran. Fix: Tell the user the error.";
const parse = (s) => {
  try {
    return JSON.parse(s);
  } catch (e) {
    return null;
  }
};

// echoed runs a call that the sidecar denies with the event as the reason, and returns the event.
const echoed = async (tool, input) => parse((await before(tool, input)).threw);
// logged returns the events that the sidecar received since the last call, without this call.
const logged = async () => parse((await before("log", { command: "/log" })).threw);

const after = async (tool, input, status, result) => {
  const ev = { tool, sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_1", input, status };
  if (status === "completed") ev.result = result;
  else ev.error = new Error("tool failed");
  try {
    await hooks["tool.execute.after"](ev);
    return { threw: false, ev };
  } catch (e) {
    return { threw: true, ev };
  }
};
const toolResult = (text) => ({ content: [{ type: "text", text }], output: text, metadata: { output: text } });
const withheldAs = (r, marker) =>
  !r.threw &&
  same(r.ev.result.content, [{ type: "text", text: marker }]) &&
  r.ev.result.output === marker &&
  !("metadata" in r.ev.result);

const prompt = async (text) => {
  const ev = { sessionID: "ses_1", messageID: "msg_1", prompt: { text, files: [] }, metadata: {}, delivery: "immediate" };
  try {
    await hooks["session.prompt"](ev);
    return { threw: false, text: ev.prompt.text };
  } catch (e) {
    return { threw: true, text: ev.prompt.text };
  }
};

const BASE = { type: "text", text: "base" };
const context = async () => {
  const ev = { sessionID: "ses_1", system: [BASE] };
  try {
    await hooks["session.context"](ev);
    return { threw: false, system: ev.system };
  } catch (e) {
    return { threw: true, system: ev.system };
  }
};

const fake = async (name, onConn) => {
  const p = join(tmp, name);
  const srv = createServer(onConn);
  await new Promise((res) => srv.listen(p, res));
  return p;
};

// ---- execute.before: mapping, session id, cwd ----
let ev = await echoed("read", { path: "/echo/r" });
check(ev?.hook_event_name === "PreToolUse", "execute.before sends PreToolUse");
check(ev?.session_id === "ses_1" && ev.cwd === DIR, "execute.before sends sessionID and the session directory");

const passInput = { path: "rel/echo", code: "x", n: 1 };
for (const [tool, input, name, want, ordered] of [
  ["read", { path: "/echo/r", offset: 2 }, "Read", { file_path: "/echo/r", offset: 2 }],
  ["write", { path: "/echo/w", content: "c" }, "Write", { file_path: "/echo/w", content: "c" }],
  [
    "edit",
    { path: "/echo/e", oldString: "a", newString: "b", replaceAll: true },
    "Edit",
    { file_path: "/echo/e", old_string: "a", new_string: "b", replace_all: true },
  ],
  // a renamed key wins over an extra key with the target name
  ["read", { path: "/echo/secret", file_path: "/tmp/ok" }, "Read", { file_path: "/echo/secret" }],
  [
    "edit",
    { path: "/echo/e", oldString: "a", old_string: "x", newString: "b", new_string: "y" },
    "Edit",
    { file_path: "/echo/e", old_string: "a", new_string: "b" },
  ],
  ["shell", { command: "cat /echo", workdir: "/w", timeout: 5 }, "Bash", { command: "cat /echo", workdir: "/w", timeout: 5 }],
  ["glob", { pattern: "*.go", path: "/echo/g" }, "Glob", { pattern: "*.go", path: "/echo/g" }],
  ["grep", { pattern: ".", path: "/echo/g", include: "*.pem" }, "Grep", { pattern: ".", path: "/echo/g", glob: "*.pem" }],
  ["webfetch", { url: "https://example.com/echo", format: "text" }, "WebFetch", { url: "https://example.com/echo", format: "text" }],
  // unmapped tools pass through with their keys and relative paths unchanged
  ["constructor", passInput, "constructor", passInput, true],
  ["execute", passInput, "execute", passInput, true],
]) {
  ev = await echoed(tool, input);
  check(ev?.tool_name === name && (ordered ? same : sameKeys)(ev.tool_input, want), `${tool} ${JSON.stringify(input)} -> ${name} (got ${JSON.stringify(ev)})`);
}

for (const [tool, workdir, cwd] of [
  ["shell", "~/.config/opencode", join(homedir(), ".config/opencode")],
  ["shell", "sub/dir", DIR + "/sub/dir"],
  ["shell", 5, DIR],
  ["read", "/other", DIR],
]) {
  ev = await echoed(tool, { command: "cat /echo", path: "/echo/r", workdir });
  check(ev?.cwd === cwd, `${tool} workdir ${workdir} -> cwd ${cwd} (got ${JSON.stringify(ev?.cwd)})`);
}

// ---- MCP tools ----
{
  const mcpTool = (ns, name) => ({ id: ns + "_" + name, name, options: { namespace: ns } });
  const server = (name) => ({ name, status: "connected" });
  registry.tools = [
    mcpTool("github", "get_file"),
    mcpTool("my_server", "do_it"),
    mcpTool("opencode", "session_rename"),
    { id: "myplugin", name: "myplugin" },
  ];
  registry.servers = [server("github"), server("my.server")];

  let r, log;
  const calls = registry.toolCalls;
  await echoed("read", { path: "/echo/r" });
  check(registry.toolCalls === calls && registry.serverCalls === 0, "a built-in tool needs no lookup");
  await echoed("patch", { patchText: "*** Add File: /echo/p\n+x" });
  check(registry.toolCalls === calls && registry.serverCalls === 0, "patch needs no lookup");

  const mcpInput = { path: "/echo/m", ref: "main", file_path: "x" };
  ev = await echoed("github_get_file", mcpInput);
  check(ev?.tool_name === "mcp__github__get_file" && same(ev.tool_input, mcpInput), `an MCP tool is sent as mcp__<server>__<tool> with its input unchanged (got ${JSON.stringify(ev)})`);
  for (const [id, want, what] of [
    ["my_server_do_it", "mcp__my_server__do_it", "a server name is sanitized before the match"],
    ["opencode_session_rename", "opencode_session_rename", "a namespaced non-MCP tool keeps its id"],
    ["myplugin", "myplugin", "a plugin tool without a namespace keeps its id"],
    ["unlisted_tool", "unlisted_tool", "a tool that is not in the list keeps its id"],
  ]) {
    ev = await echoed(id, { path: "/echo/m" });
    check(ev?.tool_name === want, `${what} (got ${JSON.stringify(ev)})`);
  }

  ev = await echoed("linear_search", { path: "/echo/m" });
  check(ev?.tool_name === "linear_search", "an MCP tool that is not registered yet keeps its id");
  registry.tools.push(mcpTool("linear", "search"));
  ev = await echoed("linear_search", { path: "/echo/m" });
  check(ev?.tool_name === "linear_search", "a tool of a server that is not connected yet keeps its id");
  registry.servers.push(server("linear"));
  ev = await echoed("linear_search", { path: "/echo/m" });
  check(ev?.tool_name === "mcp__linear__search", `an MCP tool that appears during the session is classified as MCP (got ${JSON.stringify(ev)})`);

  await logged();
  const okInput = { path: "/ok", ref: "main" };
  await after("github_get_file", okInput, "completed", toolResult("fine"));
  log = await logged();
  check(
    log.length === 1 && log[0].hook_event_name === "PostToolUse" && log[0].tool_name === "mcp__github__get_file" && same(log[0].tool_input, okInput),
    `execute.after sends the mcp__ name (got ${JSON.stringify(log)})`,
  );

  for (const [field, what] of [
    ["toolsError", "ctx.tool.list"],
    ["serversError", "ctx.mcp.list"],
  ]) {
    registry[field] = "scripted list error";
    r = await before("github_get_file", { path: "/ok" });
    check(r.threw === failText("scripted list error"), `a failing ${what} throws the fail-closed text in execute.before (got ${r.threw})`);
    r = await after("github_get_file", { path: "/ok" }, "completed", toolResult("s"));
    check(withheldAs(r, PLUGIN_FAILED), `a failing ${what} withholds in execute.after without a throw (got ${JSON.stringify(r.ev.result)})`);
    r = await before("read", { path: "/ok" });
    check(r.threw === null, `a failing ${what} does not affect a built-in tool`);
    registry[field] = null;
  }
  r = await before("github_get_file", { path: "/ok" });
  check(r.threw === null, "an MCP tool runs again after the lists recover");
  await logged();
}

// ---- execute.before: path normalization ----
await logged();
const home = homedir();
for (const [tool, name, key] of [
  ["read", "Read", "file_path"],
  ["write", "Write", "file_path"],
  ["edit", "Edit", "file_path"],
  ["glob", "Glob", "path"],
  ["grep", "Grep", "path"],
]) {
  const cases = [
    ["~/.ssh/id_rsa", join(home, ".ssh/id_rsa")],
    ["~", home],
    [".corral.yml", "/work/app/.corral.yml"],
    ["../x/y", "/work/x/y"],
    ["/abs/z", "/abs/z"],
    [7, 7],
  ];
  const threw = [];
  for (const [given] of cases) threw.push((await before(tool, { path: given })).threw);
  check(threw.every((t) => t === null), `${tool} paths are allowed (got ${JSON.stringify(threw)})`);
  const got = (await logged()).map((e) => [e.tool_name, e.tool_input[key]]);
  check(
    same(got, cases.map(([, want]) => [name, want])),
    `${tool} paths reach the sidecar as absolute paths (got ${JSON.stringify(got)})`,
  );
}

let r = await before("edit", { path: "~/x", oldString: "a", newString: "b" });
check(
  r.threw === null && r.ev.tool === "edit" && same(r.ev.input, { path: "~/x", oldString: "a", newString: "b" }),
  "execute.before leaves opencode's tool and input unchanged",
);
await logged();

// ---- execute.before: patch ----
const patch = [
  "*** Begin Patch",
  "*** Add File: a.txt",
  "+hello",
  "  *** Update File: ~/b.txt",
  "*** Move to: /abs/c.txt",
  "@@",
  "-x",
  "+y",
  "\t*** Delete File: sub/d.txt",
  "*** End Patch",
].join("\r\n");
r = await before("patch", { patchText: patch });
check(r.threw === null, `an allowed patch runs (got ${r.threw})`);
let log = await logged();
check(
  same(
    log.map((e) => [e.tool_name, e.tool_input.file_path]),
    [
      ["Write", "/work/app/a.txt"],
      ["Write", join(home, "b.txt")],
      ["Write", "/abs/c.txt"],
      ["Write", "/work/app/sub/d.txt"],
    ],
  ),
  `patch sends one Write per header with absolute paths (got ${JSON.stringify(log.map((e) => e.tool_input && e.tool_input.file_path))})`,
);
check(
  log.every((e) => e.hook_event_name === "PreToolUse" && e.session_id === "ses_1" && e.cwd === DIR && same(Object.keys(e.tool_input), ["file_path", "content"]) && e.tool_input.content === patch),
  "each patch Write carries the whole patch text as content",
);

r = await before("patch", { patchText: "*** Begin Patch\n*** Add File: x/deny.txt\n+s\n*** End Patch" });
check(r.threw === DENIED, `a denied patch path throws the reason (got ${r.threw})`);
await logged();
for (const bad of [{ patchText: "*** Begin Patch\n+no header\n*** End Patch" }, {}, { patchText: 5 }]) {
  r = await before("patch", bad);
  check(r.threw === failText("the patch has no file header"), `a headerless patch ${JSON.stringify(bad)} throws the fail-closed reason (got ${r.threw})`);
}
check(same(await logged(), []), "a headerless patch sends nothing");

// ---- execute.before: allow, deny, failures ----
r = await before("read", { path: "/deny" });
check(r.threw === DENIED, `a deny throws the sidecar's stderr text without the corral: prefix (got ${r.threw})`);
r = await before("read", { path: "/error" });
check(r.threw === failText("scripted error"), `an error answer throws the fail-closed text (got ${r.threw})`);
const t0 = Date.now();
r = await before("read", { path: "/hang" });
check(r.threw === failText("timeout"), `a hung sidecar throws the fail-closed text (got ${r.threw})`);
check(Date.now() - t0 < TIMEOUT_MS * 3, "the timeout fires at the lowered deadline");

ctx.location = {};
r = await before("read", { path: "x" });
check(r.threw !== null && r.threw.startsWith(FAIL_PREFIX), `a missing session directory fails closed (got ${r.threw})`);
ctx.location = { directory: DIR };

// ---- execute.after ----
await logged();
r = await after("read", { path: "/ok" }, "completed", toolResult("fine"));
check(!r.threw && same(r.ev.result, toolResult("fine")), "execute.after leaves a clean result unchanged");
log = await logged();
check(
  log.length === 1 &&
    log[0].hook_event_name === "PostToolUse" &&
    log[0].session_id === "ses_1" &&
    log[0].cwd === DIR &&
    log[0].tool_name === "Read" &&
    same(log[0].tool_input, { file_path: "/ok" }) &&
    same(log[0].tool_response, toolResult("fine").content),
  `execute.after sends PostToolUse with result.content as tool_response (got ${JSON.stringify(log)})`,
);

r = await after("read", { path: "/echo" }, "error");
check(!r.threw && same(await logged(), []), "execute.after ignores status error");

r = await after("read", { path: "/echo" }, "completed", toolResult("s"));
const marker = r.ev.result.output;
check(withheldAs(r, marker), `execute.after withholds with one text item, the marker as output, and no metadata (got ${JSON.stringify(r.ev.result)})`);
ev = parse(marker);
check(ev?.hook_event_name === "PostToolUse" && ev.tool_response[0].text === "s", "the marker is the sidecar's marker text");

for (const [path, why] of [
  ["/deny", "exit code 2"],
  ["/error", "scripted error"],
]) {
  r = await after("read", { path }, "completed", toolResult("s"));
  check(withheldAs(r, unscannedText(why)), `execute.after ${path} withholds with the unscanned text (got ${JSON.stringify(r.ev.result)})`);
}

// ---- session.prompt ----
await logged();
let p = await prompt("hello");
check(!p.threw && p.text === "hello", "prompt leaves a clean prompt unchanged");
log = await logged();
check(
  log.length === 1 && log[0].hook_event_name === "UserPromptSubmit" && log[0].prompt === "hello" && log[0].session_id === "ses_1" && log[0].cwd === DIR,
  `prompt sends UserPromptSubmit with the text, sessionID, and cwd (got ${JSON.stringify(log)})`,
);

p = await prompt("token /echo");
check(!p.threw && p.text.startsWith(PROMPT_PREFIX) && p.text.endsWith(PROMPT_SUFFIX), `prompt replaces the text on a block (got ${p.text})`);
ev = parse(p.text.slice(PROMPT_PREFIX.length, p.text.length - PROMPT_SUFFIX.length));
check(ev?.hook_event_name === "UserPromptSubmit" && ev.prompt === "token /echo", "the replaced text holds the sidecar's reason");

for (const [text, why] of [
  ["/deny", "exit code 2"],
  ["/garbage", "the policy hook output is unreadable"],
  ["/error", "scripted error"],
]) {
  p = await prompt(text);
  check(!p.threw && p.text === promptFailedText(why), `prompt ${text} fails closed with the reason (got ${p.text})`);
}
useSocket(undefined);

// ---- session.context ----
let c = await context();
check(!c.threw && same(c.system, [BASE]), "context with no socket adds nothing");
useSocket(await fake("nonote.sock", (conn) => conn.end(JSON.stringify({ response: { code: 0, stdout: "", stderr: "", error: "" } }) + "\n")));
c = await context();
check(!c.threw && same(c.system, [BASE]), "context with no note adds nothing");
useSocket(socket);
for (const call of [1, 2]) {
  c = await context();
  check(!c.threw && same(c.system, [BASE, { type: "text", text: "NOTE" }]), `context call ${call} pushes the note as the last system part`);
}
useSocket(undefined);
c = await context();
check(!c.threw && same(c.system, [BASE, { type: "text", text: "NOTE" }]), "context keeps the note after the first success");

// ---- socket failures ----
r = await before("read", { path: "/x" });
check(r.threw === failText(NO_SOCKET), `execute.before with no socket names CORRAL_SIDECAR_SOCKET (got ${r.threw})`);

const missingSock = join(tmp, "missing.sock");
useSocket(missingSock);
r = await before("read", { path: "/x" });
check(r.threw === failText("dial sidecar " + missingSock + ": ENOENT"), `execute.before with no listener fails closed (got ${r.threw})`);

useSocket(await fake("both.sock", (conn) => conn.end('{"question":{"op":"eval-symlinks","path":"/"},"response":{"code":0}}\n')));
r = await before("read", { path: "/x" });
check(r.threw?.startsWith(FAIL_PREFIX + "malformed sidecar answer"), `a line with question and response fails (got ${r.threw})`);

useSocket(await fake("garbage.sock", (conn) => conn.end("not json\n")));
r = await before("read", { path: "/x" });
check(r.threw?.startsWith(FAIL_PREFIX + "malformed sidecar answer"), `a malformed line fails (got ${r.threw})`);

useSocket(await fake("long.sock", (conn) => conn.end("x".repeat(MAX_BUFFER + 1))));
r = await before("read", { path: "/x" });
check(r.threw === failText(`sidecar line exceeds ${MAX_BUFFER} characters`), `a line over MAX_BUFFER fails (got ${r.threw})`);

useSocket(
  await fake("unknown.sock", (conn) => {
    conn.on("error", () => {});
    conn.write('{"question":{"op":"bogus","path":"/"}}\n');
  }),
);
r = await before("read", { path: "/x" });
check(r.threw === failText('unknown sidecar question "bogus"'), `an unknown op fails (got ${r.threw})`);

if (failures > 0) {
  console.error(`${failures} policy plugin assertion(s) failed`);
  process.exit(1);
}
console.log("policy harness: all assertions passed");
process.exit(0);
