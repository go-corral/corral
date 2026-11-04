/**
 * corral opencode policy plugin.
 *
 * Embedded in the corral binary and loaded by opencode 2.x as a plugin. It translates
 * opencode's V2 hook events into corral's Claude-shaped hook events and sends each one to the
 * sidecar of `corral run` over the unix socket in CORRAL_SIDECAR_SOCKET. The sidecar asks
 * filesystem questions back, and the plugin answers them from opencode's view of the filesystem.
 *
 * Plain JavaScript with Node built-ins only and no build step: a plugin that fails to load runs
 * opencode with no policy.
 *
 * Fail-closed differs per hook, because only a throw in tool `execute.before` fails cleanly, and a
 * throw in any other hook is a defect:
 *   - tool execute.before: throws on a deny and on any failure.
 *   - tool execute.after: replaces the result with a marker on a withhold or a failure.
 *   - session prompt: replaces the text on a block and on a failure.
 *   - session context: adds no note on a failure.
 */
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import * as readline from "node:readline";

const HOOK_TIMEOUT_MS = 15000;
const MAX_BUFFER = 64 * 1024 * 1024;
// The sidecar takes at most MAX_EVENT_BYTES+1 payload bytes.
const MAX_EVENT_BYTES = 16 * 1024 * 1024;
const GENERIC_WITHHELD = unscanned("the policy hook output is unreadable");

// opencode tool name/keys -> Claude tool name/keys, so corral's name-gated rules apply. `paths`
// lists the mapped keys that hold a path. Other tools pass through under their id, except MCP
// tools (see policyToolName); corral's name-agnostic rules still apply to them through the
// `path`, `file_path`, and `command` keys.
const TOOL_MAP = {
  shell: { name: "Bash" },
  read: { name: "Read", keys: { path: "file_path" }, paths: ["file_path"] },
  write: { name: "Write", keys: { path: "file_path" }, paths: ["file_path"] },
  edit: {
    name: "Edit",
    keys: { path: "file_path", oldString: "old_string", newString: "new_string", replaceAll: "replace_all" },
    paths: ["file_path"],
  },
  glob: { name: "Glob", paths: ["path"] },
  grep: { name: "Grep", keys: { include: "glob" }, paths: ["path"] },
  webfetch: { name: "WebFetch" },
};

const PATCH_HEADERS = ["*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"];

// resolvePath resolves a tool path like opencode's resolvePath, because the policy expands
// neither `~` nor a relative path.
function resolvePath(dir, p) {
  if (typeof p !== "string") return p;
  if (p === "~" || p.startsWith("~/")) return path.resolve(os.homedir(), p.slice(2));
  return path.resolve(dir, p);
}

// eventCwd returns the directory a tool call runs in: the resolved workdir of a shell call, else
// the session directory.
function eventCwd(tool, input, dir) {
  if (tool === "shell" && input && typeof input.workdir === "string") return resolvePath(dir, input.workdir);
  return dir;
}

// policyToolName returns the tool name that the policy sees. opencode's tool id of an MCP tool is
// `<server>_<tool>`, which the policy does not know as MCP. A tool whose namespace is the
// sanitized name of an MCP server is sent as `mcp__<server>__<tool>`. The lists are read per call,
// because MCP tools can be reloaded during a session. A built-in tool without a namespace needs
// no lookup.
async function policyToolName(ctx, id) {
  if (Object.hasOwn(TOOL_MAP, id) || id === "patch") return id;
  const tool = (await ctx.tool.list()).find((t) => t.id === id);
  const ns = tool?.options?.namespace;
  if (typeof ns !== "string") return id;
  const servers = (await ctx.mcp.list()).data;
  if (!servers.some((s) => String(s.name).replace(/[^a-zA-Z0-9_-]/g, "_") === ns)) return id;
  return "mcp__" + ns + "__" + tool.name;
}

// A renamed key is copied last, so an extra input key with the target name cannot replace the
// value that opencode uses.
function mapTool(tool, input, dir) {
  const src = input && typeof input === "object" ? input : {};
  const m = Object.hasOwn(TOOL_MAP, tool) ? TOOL_MAP[tool] : undefined;
  if (!m) return { tool_name: String(tool), tool_input: src };
  const keys = m.keys || {};
  const out = {};
  for (const k of Object.keys(src)) if (!Object.hasOwn(keys, k)) out[k] = src[k];
  for (const k of Object.keys(keys)) if (Object.hasOwn(src, k)) out[keys[k]] = src[k];
  for (const k of m.paths || []) if (Object.hasOwn(out, k)) out[k] = resolvePath(dir, out[k]);
  return { tool_name: m.name, tool_input: out };
}

// toolCalls returns the Claude-shaped calls to check for one opencode tool call. A patch becomes
// one Write per file header, read like opencode's patch parser reads a header line (trim also
// removes a trailing \r).
function toolCalls(tool, input, dir) {
  if (tool !== "patch") return [mapTool(tool, input, dir)];
  const text = input && typeof input.patchText === "string" ? input.patchText : "";
  const calls = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const header = PATCH_HEADERS.find((h) => line.startsWith(h));
    if (header === undefined) continue;
    const file = resolvePath(dir, line.slice(header.length).trim());
    calls.push({ tool_name: "Write", tool_input: { file_path: file, content: text } });
  }
  if (calls.length === 0) throw new Error("the patch has no file header");
  return calls;
}

// callSidecar sends one event to the sidecar and answers its filesystem questions. ran=false
// means no response arrived or the response holds an error; why names the cause.
function callSidecar(type, decision, event) {
  return new Promise((resolve) => {
    const socketPath = process.env.CORRAL_SIDECAR_SOCKET;
    if (!socketPath) {
      resolve(failed("no sidecar: CORRAL_SIDECAR_SOCKET is not set inside the sandbox"));
      return;
    }
    const payload =
      event === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(event)).subarray(0, MAX_EVENT_BYTES + 1);
    let done = false;
    const sock = net.createConnection(socketPath);
    const timer = setTimeout(() => finish(failed("timeout")), HOOK_TIMEOUT_MS);
    const finish = (res) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(res);
    };
    sock.write(JSON.stringify({ type: type, decision: decision, size: payload.length }) + "\n");
    if (payload.length > 0) sock.write(payload);
    const rl = readline.createInterface({ input: sock });
    rl.on("line", (line) => {
      if (line.length > MAX_BUFFER) return finish(failed("sidecar line exceeds " + MAX_BUFFER + " characters"));
      let m;
      try {
        m = JSON.parse(line);
      } catch (e) {
        return finish(failed("malformed sidecar answer: " + e.message));
      }
      const q = m == null ? null : m.question;
      const r = m == null ? null : m.response;
      if (r != null && q == null) {
        if (r.error) return finish(failed(r.error));
        return finish({
          ran: true,
          why: "",
          status: r.code,
          stdout: r.stdout.trim(),
          stderr: r.stderr.trim(),
        });
      }
      if (q == null || r != null) {
        return finish(failed("malformed sidecar answer: want exactly one of question and response"));
      }
      const a = answerQuestion(q);
      if (a === null) return finish(failed("unknown sidecar question " + JSON.stringify(q.op)));
      sock.write(JSON.stringify(a) + "\n");
    });
    rl.on("error", (e) => finish(failed("dial sidecar " + socketPath + ": " + (e.code || e.message))));
    rl.on("close", () => finish(failed("the sidecar closed the connection")));
  });
}

function failed(why) {
  return { ran: false, why: why, status: null, stdout: "", stderr: "" };
}

// answerQuestion answers a sidecar question like policy.OSFS, or returns null for an unknown op.
function answerQuestion(q) {
  try {
    if (q.op === "eval-symlinks") return { path: fs.realpathSync(q.path) };
    if (q.op === "read-regular") {
      if (!fs.lstatSync(q.path).isFile()) return {};
      return readRegularFile(q.path, q.limit || 0);
    }
    return null;
  } catch (e) {
    const a = { err: e.message };
    if (e.code === "ENOENT") a.kind = "not-exist";
    else if (e.code === "EACCES" || e.code === "EPERM") a.kind = "permission";
    return a;
  }
}

function readRegularFile(file, limit) {
  const fd = fs.openSync(file, "r");
  try {
    const chunks = [];
    let total = 0;
    while (total < limit) {
      const buf = Buffer.alloc(Math.min(limit - total, 64 * 1024));
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      chunks.push(buf.subarray(0, n));
      total += n;
    }
    return { data: Buffer.concat(chunks).toString("base64"), regular: true };
  } finally {
    fs.closeSync(fd);
  }
}

// blockReason returns the exit2 stderr without the "corral: " prefix of the hook's stderr lines.
function blockReason(res) {
  return res.stderr.replace(/^corral: /gm, "") || "blocked by corral policy";
}

function failClosed(detail) {
  return "blocked by corral policy [hook:fail-closed]: " + detail + ". Fix: None. Corral could not check this call, so it blocked it. Tell the user the error.";
}

function unscanned(why) {
  return "output withheld by corral policy [hook:fail-closed]: corral could not scan the output (" + why + "). The call ran. Fix: Tell the user the error.";
}

// markerFrom pulls corral's withhold-marker text out of a PostToolUse updatedToolOutput,
// whatever shape it took (content-block array or a Bash result object). Any parse trouble
// still withholds (returns a generic marker) — the original result is never passed through.
function markerFrom(stdout) {
  try {
    const u = JSON.parse(stdout)?.hookSpecificOutput?.updatedToolOutput;
    if (Array.isArray(u) && u[0] && u[0].text) return u[0].text;
    if (u && typeof u === "object") return u.stdout || u.output || GENERIC_WITHHELD;
  } catch {}
  return GENERIC_WITHHELD;
}

function promptFailed(why) {
  return "blocked by corral policy [hook:fail-closed]: cannot evaluate policy: " + why + ". The prompt was not sent. Fix: Restart the corral session.";
}

function withheldPrompt(reason) {
  return "[corral withheld the user's prompt] " + reason + " Tell the user, without guessing the prompt's content.";
}

// promptBlockReason returns corral's UserPromptSubmit block reason from its stdout
// ({"decision":"block","reason":...}), or "" when the output is unusable.
function promptBlockReason(stdout) {
  try {
    const d = JSON.parse(stdout);
    if (d && d.decision === "block" && d.reason) return d.reason;
  } catch {}
  return "";
}

function setup(ctx) {
  // execute.before: the exit2 presentation reports allow as exit 0 and a block as a non-zero
  // exit with the reason on stderr. opencode turns the throw into a tool error with the message.
  ctx.tool.hook("execute.before", async (ev) => {
    let cwd, calls;
    try {
      const dir = ctx.location.directory;
      calls = toolCalls(await policyToolName(ctx, ev.tool), ev.input, dir);
      cwd = eventCwd(ev.tool, ev.input, dir);
    } catch (e) {
      throw new Error(failClosed("cannot evaluate policy: " + e.message));
    }
    for (const call of calls) {
      const res = await callSidecar("pre-tool-use", "exit2", {
        hook_event_name: "PreToolUse",
        session_id: ev.sessionID,
        cwd: cwd,
        tool_name: call.tool_name,
        tool_input: call.tool_input,
      });
      if (!res.ran) throw new Error(failClosed("cannot evaluate policy: " + res.why));
      if (res.status !== 0) throw new Error(blockReason(res));
    }
  });

  // execute.after: post-tool-use exits 0 and prints an updatedToolOutput object only when it
  // withheld the result; empty stdout means clean. The model reads `content`, a code-mode script
  // reads `output`, and storage and clients read `metadata`.
  ctx.tool.hook("execute.after", async (ev) => {
    if (ev.status !== "completed") return;
    let marker;
    try {
      const dir = ctx.location.directory;
      const mapped = mapTool(await policyToolName(ctx, ev.tool), ev.input, dir);
      const res = await callSidecar("post-tool-use", "", {
        hook_event_name: "PostToolUse",
        session_id: ev.sessionID,
        cwd: eventCwd(ev.tool, ev.input, dir),
        tool_name: mapped.tool_name,
        tool_input: mapped.tool_input,
        tool_response: Array.isArray(ev.result.content) ? ev.result.content : [],
      });
      if (!res.ran) marker = unscanned("cannot evaluate policy: " + res.why);
      else if (res.status !== 0) marker = unscanned("cannot evaluate policy: exit code " + res.status);
      else if (res.stdout !== "") marker = markerFrom(res.stdout);
    } catch (e) {
      marker = unscanned("the opencode plugin failed");
    }
    if (marker === undefined) return;
    try {
      ev.result.content = [{ type: "text", text: marker }];
      ev.result.output = marker;
      delete ev.result.metadata;
    } catch {}
  });

  // prompt: opencode stores and sends prompt.text after this hook, so a replaced text keeps the
  // credential out of the request and the session. corral marks a prompt once-seen per session id,
  // so a verbatim resubmit proceeds.
  ctx.session.hook("prompt", async (ev) => {
    let text;
    try {
      const res = await callSidecar("user-prompt-submit", "", {
        hook_event_name: "UserPromptSubmit",
        session_id: ev.sessionID,
        cwd: ctx.location.directory,
        prompt: ev.prompt.text,
      });
      if (!res.ran) text = withheldPrompt(promptFailed(res.why));
      else if (res.status !== 0) text = withheldPrompt(promptFailed("exit code " + res.status));
      else if (res.stdout !== "") {
        const reason = promptBlockReason(res.stdout);
        text = withheldPrompt(reason || promptFailed("the policy hook output is unreadable"));
      }
    } catch {
      text = withheldPrompt(promptFailed("the opencode plugin failed"));
    }
    if (text === undefined) return;
    try {
      ev.prompt.text = text;
    } catch {}
  });

  // context: runs for each primary model request. The session-start answer holds the note as
  // hookSpecificOutput.additionalContext.
  let note = "";
  ctx.session.hook("context", async (ev) => {
    try {
      if (!note) {
        const res = await callSidecar("session-start", "", undefined);
        if (!res.ran || res.status !== 0) return;
        const text = JSON.parse(res.stdout)?.hookSpecificOutput?.additionalContext;
        if (typeof text === "string") note = text;
      }
      if (note) ev.system.push({ type: "text", text: note });
    } catch {}
  });
}

export default { id: "corral-policy", setup };
