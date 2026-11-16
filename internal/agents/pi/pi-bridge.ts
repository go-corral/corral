/**
 * corral pi policy bridge.
 *
 * Embedded in the corral binary, materialized to the host and bound read-only into the
 * sandbox, and activated via `pi -e <this file>` (corral owns pi's argv, so a prompt-injected
 * agent cannot disable it). It translates pi's in-process events into corral's Claude-shaped
 * hook events and sends each one to the sidecar of `corral run` over the unix socket in
 * CORRAL_SIDECAR_SOCKET. The sidecar asks filesystem questions back, and the bridge answers
 * them from pi's view of the filesystem.
 *
 * Loaded raw via pi's jiti loader — NO build step and NO dependencies (Node built-ins only).
 * Deliberately written as plain, annotation-free JavaScript-in-.ts so a transpile/load
 * failure (which would run pi with no policy) cannot happen.
 *
 * Fail-closed differs per event:
 *   - tool_call:  pi turns a thrown handler into a BLOCK, so any anomaly may throw.
 *   - tool_result / user_bash / input: fail closed by RETURNING a withhold/deny/handled
 *     value, never by throwing, so the result does not depend on how a pi version treats a
 *     throw.
 *   - before_agent_start: a model-only note; fail-open is acceptable (never throw).
 */
import * as fs from "node:fs";
import * as net from "node:net";
import * as readline from "node:readline";

const HOOK_TIMEOUT_MS = 15000;
const MAX_BUFFER = 64 * 1024 * 1024;
// The sidecar takes at most MAX_EVENT_BYTES+1 payload bytes.
const MAX_EVENT_BYTES = 16 * 1024 * 1024;
const SESSION_ID = "pi-" + process.pid;
const GENERIC_WITHHELD = unscanned("the policy hook output is unreadable");

// pi tool name/key -> Claude tool name/keys, so corral's name-gated rules (sensitive-path
// classification, the write-content secret scan, the /etc + self-protect write guards) apply
// to pi exactly as to Claude. Tools not listed pass through unchanged; corral's name-agnostic
// rules still apply to them — blocked paths / the always-blocked paths via the `path`/`file_path` key,
// and the bash-command scan via the `command` key.
const TOOL_MAP = {
  bash: { name: "Bash" },
  read: { name: "Read", keys: { path: "file_path" } },
  write: { name: "Write", keys: { path: "file_path" } },
  edit: { name: "MultiEdit", keys: { path: "file_path" }, edits: true },
  ls: { name: "Read", keys: { path: "file_path" } },
  find: { name: "Glob" },
  grep: { name: "Grep" },
};

// toClaude maps a pi tool name + input object to the Claude-shaped {tool_name, tool_input}
// corral's rules expect. An unknown tool passes through with its name and input untouched.
function toClaude(piName, input) {
  const src = input && typeof input === "object" ? input : {};
  const m = TOOL_MAP[piName];
  if (!m) return { tool_name: String(piName), tool_input: src };
  const keys = m.keys || {};
  const out = {};
  for (const k of Object.keys(src)) out[keys[k] || k] = src[k];
  if (m.edits && Array.isArray(out.edits)) {
    out.edits = out.edits.map((e) => ({
      old_string: e && e.oldText != null ? e.oldText : (e && e.old_string) || "",
      new_string: e && e.newText != null ? e.newText : (e && e.new_string) || "",
    }));
  }
  return { tool_name: m.name, tool_input: out };
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

function readRegularFile(path, limit) {
  const fd = fs.openSync(path, "r");
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

function blockReason(res) {
  return res.stderr || "blocked by corral policy";
}

function failClosed(detail) {
  return "blocked by corral policy [hook:fail-closed]: " + detail + ". Fix: None. Corral could not check this call, so it blocked it. Tell the user the error.";
}

function unscanned(why) {
  return "output withheld by corral policy [hook:fail-closed]: corral could not scan the output (" + why + "). The call ran. Fix: Tell the user the error.";
}

function withheld(text) {
  return { content: [{ type: "text", text: text }], isError: false };
}

function denyBash(msg) {
  return { result: { output: msg, exitCode: 1, cancelled: false, truncated: false } };
}

// markerFrom pulls corral's withhold-marker text out of a PostToolUse updatedToolOutput,
// whatever shape it took (MCP content-block array or a Bash result object). Any parse trouble
// still withholds (returns a generic marker) — the original result is never passed through.
function markerFrom(stdout) {
  try {
    const u = JSON.parse(stdout)?.hookSpecificOutput?.updatedToolOutput;
    if (Array.isArray(u) && u[0] && u[0].text) return u[0].text;
    if (u && typeof u === "object") return u.stdout || u.output || GENERIC_WITHHELD;
  } catch (e) {}
  return GENERIC_WITHHELD;
}

function promptFailed(why) {
  return "blocked by corral policy [hook:fail-closed]: cannot evaluate policy: " + why + ". The prompt was not sent. Fix: Restart the corral session.";
}

// promptBlockReason returns corral's UserPromptSubmit block reason from its stdout
// ({"decision":"block","reason":...}), or "" when the output is unusable.
function promptBlockReason(stdout) {
  try {
    const d = JSON.parse(stdout);
    if (d && d.decision === "block" && d.reason) return d.reason;
  } catch (e) {}
  return "";
}

export default (pi) => {
  // tool_call: a true pre-exec veto. The exit2 presentation reports allow as exit 0 and a
  // block as a non-zero exit with the reason on stderr; any non-zero (a real deny OR a
  // corral error) blocks. A sidecar failure throws — valid here, pi turns it into a block.
  pi.on("tool_call", async (event) => {
    const mapped = toClaude(event.toolName, event.input);
    const res = await callSidecar("pre-tool-use", "exit2", {
      hook_event_name: "PreToolUse",
      session_id: SESSION_ID,
      cwd: process.cwd(),
      tool_name: mapped.tool_name,
      tool_input: mapped.tool_input,
    });
    if (!res.ran) throw new Error(failClosed("cannot evaluate policy: " + res.why));
    if (res.status !== 0) return { block: true, reason: blockReason(res) };
    return undefined; // allow
  });

  // tool_result: ingress withhold-replace. post-tool-use exits 0 and prints an
  // updatedToolOutput object only when it withheld the result; empty stdout means clean. A
  // throw here is SWALLOWED by pi (fail-OPEN), so every anomaly RETURNS a withhold instead.
  pi.on("tool_result", async (event) => {
    try {
      const mapped = toClaude(event.toolName, event.input);
      const res = await callSidecar("post-tool-use", "", {
        hook_event_name: "PostToolUse",
        session_id: SESSION_ID,
        cwd: process.cwd(),
        tool_name: mapped.tool_name,
        tool_input: mapped.tool_input,
        tool_response: Array.isArray(event.content) ? event.content : [],
      });
      if (!res.ran) return withheld(unscanned("cannot evaluate policy: " + res.why));
      if (res.status !== 0) return withheld(unscanned("cannot evaluate policy: exit code " + res.status));
      if (res.stdout === "") return undefined; // clean: keep the original result
      return withheld(markerFrom(res.stdout)); // corral withheld it
    } catch (e) {
      return withheld(unscanned("the pi bridge failed"));
    }
  });

  // user_bash: policy the user's `!` command, which Claude does not expose to hooks.
  // user_bash has no {block,reason}; a deny SUBSTITUTES a synthetic BashResult for execution.
  // A throw is SWALLOWED (the real command would run — fail-OPEN), so every anomaly RETURNS a
  // deny. Interactive-mode only (print/rpc never emit user_bash).
  pi.on("user_bash", async (event) => {
    try {
      const res = await callSidecar("pre-tool-use", "exit2", {
        hook_event_name: "PreToolUse",
        session_id: SESSION_ID,
        cwd: event.cwd || process.cwd(),
        tool_name: "Bash",
        tool_input: { command: event.command },
      });
      if (!res.ran) return denyBash(failClosed("cannot evaluate policy: " + res.why));
      if (res.status !== 0) return denyBash(blockReason(res));
      return undefined; // allow: pi runs the real command
    } catch (e) {
      return denyBash(failClosed("the pi bridge failed"));
    }
  });

  // input: scan the user's prompt for secrets before it reaches the model (a credential pasted
  // into a prompt goes straight to the model provider). On a hit, swallow the prompt
  // (`handled`) and show corral's reason; the user can redact or resubmit (corral marks a
  // prompt once-seen so a verbatim resubmit proceeds). A scan failure also swallows the
  // prompt: the extension only loads in a corral session, so a failed sidecar call means the
  // session is broken. A throw is SWALLOWED (the prompt would continue), so every anomaly
  // RETURNS `handled`. Covers interactive AND rpc/print input, unlike user_bash. Print and JSON
  // modes have no UI, so the message goes to stderr.
  pi.on("input", async (event, ctx) => {
    const notify = (msg, level) => {
      if (ctx && ctx.hasUI) ctx.ui.notify(msg, level);
      else process.stderr.write(msg + "\n");
    };
    try {
      const res = await callSidecar("user-prompt-submit", "", {
        hook_event_name: "UserPromptSubmit",
        session_id: SESSION_ID,
        cwd: process.cwd(),
        prompt: event.text,
      });
      if (!res.ran) notify(promptFailed(res.why), "error");
      else if (res.status !== 0) notify(promptFailed("exit code " + res.status), "error");
      else if (res.stdout === "") return { action: "continue" };
      else {
        const reason = promptBlockReason(res.stdout);
        if (reason) notify(reason, "warning");
        else notify(promptFailed("the policy hook output is unreadable"), "error");
      }
    } catch (e) {
      notify(promptFailed("the pi bridge failed"), "error");
    }
    return { action: "handled" }; // swallow: the prompt is NOT sent to the model
  });

  // before_agent_start: set corral's model-only sandbox note (the session-start answer holds
  // it as hookSpecificOutput.additionalContext) as a system prompt section. pi needs it on
  // each run, but stores it once per session. Informational — never throw.
  pi.on("before_agent_start", async (event) => {
    try {
      const res = await callSidecar("session-start", "", undefined);
      if (!res.ran || res.status !== 0) return;
      const note = JSON.parse(res.stdout)?.hookSpecificOutput?.additionalContext;
      if (note) event.systemPromptOptions.sections.corral_sandbox_note = note;
    } catch (e) {}
  });
};
