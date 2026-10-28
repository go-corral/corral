/**
 * corral opencode policy bridge.
 *
 * Embedded in the corral binary, materialized to the host and bound read-only into the
 * sandbox, and activated through OPENCODE_CONFIG_CONTENT (`{"plugins":[<this dir>]}`) by
 * `corral run opencode`. It runs inside opencode's server process, the process that executes
 * every tool, and translates opencode's plugin hooks into corral's Claude-shaped hook wire by
 * shelling out to `corral hook ...`, so the Go policy engine is reused unchanged.
 *
 * Plain JavaScript with Node built-ins only: opencode loads it without a build step or
 * dependencies (opencode >= 2.1.0, Promise plugin API).
 *
 * Fail-closed per hook:
 *   - tool execute.before: opencode awaits every hook and fails the call on a rejection, so
 *     any anomaly throws.
 *   - tool execute.after: has no failure channel, so every anomaly replaces the result with a
 *     withhold marker.
 *   - permission evaluate: allows what corral's `ask` fallback rule would otherwise prompt
 *     for; execute.before has already decided.
 *   - session prompt / context: advisory, never throw.
 */
import { spawnSync } from "node:child_process";

const CORRAL = process.env.CORRAL_BIN || "corral";
const HOOK_TIMEOUT_MS = 15000;
const MAX_BUFFER = 64 * 1024 * 1024;
const SESSION_ID = "opencode-" + process.pid;
const GENERIC_WITHHELD = unscanned("the policy hook output is unreadable");

// opencode tool -> Claude tool name/keys, so corral's name-gated rules (the write-content and
// Read secret scans) apply. Unlisted tools pass through unchanged; corral's name-agnostic rules
// still apply to them through the `path` and `command` keys.
const TOOL_MAP = {
  shell: { name: "Bash" },
  read: { name: "Read", keys: { path: "file_path" } },
  write: { name: "Write", keys: { path: "file_path" } },
  edit: { name: "Edit", keys: { path: "file_path", oldString: "old_string", newString: "new_string", replaceAll: "replace_all" } },
  glob: { name: "Glob" },
  grep: { name: "Grep" },
  webfetch: { name: "WebFetch" },
};

function toClaude(name, input) {
  const src = input && typeof input === "object" ? input : {};
  const m = TOOL_MAP[name];
  if (!m) return { tool_name: String(name), tool_input: src };
  const keys = m.keys || {};
  const out = {};
  for (const k of Object.keys(src)) out[keys[k] || k] = src[k];
  return { tool_name: m.name, tool_input: out };
}

// patchCalls splits an apply-patch envelope into one Write check per touched file, so every
// path and the added text go through the path rules and the write-content secret scan.
function patchCalls(input) {
  const text = input && typeof input.patchText === "string" ? input.patchText : "";
  const paths = [];
  for (const line of text.split("\n")) {
    const m = /^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/.exec(line);
    if (m) paths.push(m[1].trim());
  }
  if (paths.length === 0) return [{ tool_name: "patch", tool_input: input || {} }];
  return paths.map((p) => ({ tool_name: "Write", tool_input: { file_path: p, content: text } }));
}

function callCorral(args, event) {
  const r = spawnSync(CORRAL, args, {
    input: JSON.stringify(event),
    encoding: "utf8",
    timeout: HOOK_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  return {
    ran: !r.error && r.signal == null && typeof r.status === "number",
    why: r.error ? r.error.code || r.error.message : r.signal || "exit status " + r.status,
    status: r.status,
    stdout: (r.stdout || "").trim(),
    stderr: (r.stderr || "").trim(),
  };
}

function failClosed(detail) {
  return "blocked by corral policy [hook:fail-closed]: " + detail + ". Fix: None. Corral could not check this call, so it blocked it. Tell the user the error.";
}

function unscanned(why) {
  return "output withheld by corral policy [hook:fail-closed]: corral could not scan the output (" + why + "). The call ran. Fix: Tell the user the error.";
}

function markerFrom(stdout) {
  try {
    const u = JSON.parse(stdout)?.hookSpecificOutput?.updatedToolOutput;
    if (Array.isArray(u) && u[0] && u[0].text) return u[0].text;
    if (u && typeof u === "object") return u.stdout || u.output || GENERIC_WITHHELD;
  } catch (e) {}
  return GENERIC_WITHHELD;
}

function withhold(ev, text) {
  ev.result.content = [{ type: "text", text: text }];
  if ("output" in ev.result) ev.result.output = text;
  if ("metadata" in ev.result) delete ev.result.metadata;
}

function promptBlockReason(stdout) {
  try {
    const d = JSON.parse(stdout);
    if (d && d.decision === "block" && d.reason) return d.reason;
  } catch (e) {}
  return "";
}

function preToolUse(call) {
  const res = callCorral(["hook", "pre-tool-use", "--decision", "exit2"], {
    hook_event_name: "PreToolUse",
    session_id: SESSION_ID,
    cwd: process.cwd(),
    tool_name: call.tool_name,
    tool_input: call.tool_input,
  });
  if (!res.ran) throw new Error(failClosed("the policy hook did not run: " + res.why));
  if (res.status !== 0) throw new Error(res.stderr || "blocked by corral policy");
}

let sandboxNote;

export default {
  id: "corral-policy",
  setup: async (ctx) => {
    await ctx.tool.hook("execute.before", async (ev) => {
      const calls = ev.tool === "patch" ? patchCalls(ev.input) : [toClaude(ev.tool, ev.input)];
      for (const call of calls) preToolUse(call);
    });

    await ctx.tool.hook("execute.after", async (ev) => {
      if (ev.status !== "completed" || !ev.result) return;
      try {
        const mapped = ev.tool === "patch" ? { tool_name: "patch", tool_input: ev.input || {} } : toClaude(ev.tool, ev.input);
        const res = callCorral(["hook", "post-tool-use"], {
          hook_event_name: "PostToolUse",
          session_id: SESSION_ID,
          cwd: process.cwd(),
          tool_name: mapped.tool_name,
          tool_input: mapped.tool_input,
          tool_response: Array.isArray(ev.result.content) ? ev.result.content : [],
        });
        if (!res.ran || res.status !== 0) return withhold(ev, unscanned("the policy hook failed: " + res.why));
        if (res.stdout === "") return;
        withhold(ev, markerFrom(res.stdout));
      } catch (e) {
        withhold(ev, unscanned("the opencode bridge failed"));
      }
    });

    await ctx.permission.hook("evaluate", async (ev) => {
      if (ev.effect === "ask") ev.effect = "allow";
    });

    // A flagged prompt is replaced before it reaches the model; corral marks it seen, so a
    // verbatim resubmit proceeds. Advisory: a clean prompt or any hook error continues.
    await ctx.session.hook("prompt", async (ev) => {
      try {
        const text = ev.prompt && typeof ev.prompt.text === "string" ? ev.prompt.text : "";
        if (text === "") return;
        const res = callCorral(["hook", "user-prompt-submit"], {
          hook_event_name: "UserPromptSubmit",
          session_id: SESSION_ID,
          cwd: process.cwd(),
          prompt: text,
        });
        if (!res.ran || res.status !== 0 || res.stdout === "") return;
        const reason = promptBlockReason(res.stdout);
        if (reason) ev.prompt.text = "[corral withheld the user's prompt] " + reason + " Tell the user, without guessing the prompt's content.";
      } catch (e) {}
    });

    await ctx.session.hook("context", async (ev) => {
      try {
        if (sandboxNote === undefined) {
          sandboxNote = "";
          const res = callCorral(["hook", "session-start"], {
            hook_event_name: "SessionStart",
            session_id: SESSION_ID,
            cwd: process.cwd(),
          });
          if (res.ran && res.status === 0) sandboxNote = JSON.parse(res.stdout)?.hookSpecificOutput?.additionalContext || "";
        }
        if (sandboxNote) ev.system.push({ type: "text", text: sandboxNote });
      } catch (e) {}
    });
  },
};
