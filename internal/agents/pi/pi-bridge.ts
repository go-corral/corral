/**
 * corral pi policy bridge.
 *
 * Embedded in the corral binary, materialized to the host and bound read-only into the
 * sandbox, and activated via `pi -e <this file>` (corral owns pi's argv, so a prompt-injected
 * agent cannot disable it). It translates pi's in-process tool-call events into corral's
 * existing Claude-shaped hook wire and shells out to `corral hook ...`, so the Go policy
 * engine is reused unchanged (no agent-specific codec).
 *
 * Loaded raw via pi's jiti loader — NO build step and NO dependencies (Node built-ins only).
 * Deliberately written as plain, annotation-free JavaScript-in-.ts so a transpile/load
 * failure (which would run pi with no policy) cannot happen.
 *
 * Fail-closed is ASYMMETRIC in pi (verified against pi v0.79.x — see
 * scratch/pi-phase2-plan.md):
 *   - tool_call:  pi turns a thrown handler into a BLOCK, so any anomaly may throw.
 *   - tool_result / user_bash: pi SWALLOWS a thrown handler (fail-OPEN), so they must fail
 *     closed by RETURNING a withhold/deny value, never by throwing.
 *   - before_agent_start: a model-only note; fail-open is acceptable (never throw).
 */
import { spawnSync } from "node:child_process";

// The corral binary to invoke. The launcher pins its absolute path via CORRAL_BIN (valid
// inside the sandbox, where it mirrors the host); fall back to a PATH lookup.
const CORRAL = process.env.CORRAL_BIN || "corral";
const HOOK_TIMEOUT_MS = 15000;
const MAX_BUFFER = 64 * 1024 * 1024;
const SESSION_ID = "pi-" + process.pid;
const GENERIC_WITHHELD = "[corral] tool response withheld by policy (fail-closed).";

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

// callCorral runs `corral <args>` with the hook event on stdin. pi.exec ignores child stdin,
// so we use child_process directly. ran=false means corral could not be executed or did not
// finish (missing binary, timeout, signal, non-numeric status) — an infra failure the caller
// treats as fail-closed.
function callCorral(args, event) {
  const r = spawnSync(CORRAL, args, {
    input: JSON.stringify(event),
    encoding: "utf8",
    timeout: HOOK_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  return {
    ran: !r.error && r.signal == null && typeof r.status === "number",
    status: r.status,
    stdout: (r.stdout || "").trim(),
    stderr: (r.stderr || "").trim(),
  };
}

function blockReason(res) {
  return res.stderr || "blocked by corral policy";
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

// promptBlockReason returns corral's UserPromptSubmit block reason from its stdout
// ({"decision":"block","reason":...}), or "" when the prompt was allowed or the output is
// unusable (advisory → continue).
function promptBlockReason(stdout) {
  try {
    const d = JSON.parse(stdout);
    if (d && d.decision === "block" && d.reason) return d.reason;
  } catch (e) {}
  return "";
}

export default (pi) => {
  // tool_call: a true pre-exec veto. corral hook --decision exit2 reports allow as exit 0 and
  // a block as a non-zero exit with the reason on stderr; any non-zero (a real deny OR a
  // corral error) blocks. An infra failure throws — valid here, pi turns it into a block.
  pi.on("tool_call", async (event) => {
    const mapped = toClaude(event.toolName, event.input);
    const res = callCorral(["hook", "pre-tool-use", "--decision", "exit2"], {
      hook_event_name: "PreToolUse",
      session_id: SESSION_ID,
      cwd: process.cwd(),
      tool_name: mapped.tool_name,
      tool_input: mapped.tool_input,
    });
    if (!res.ran) throw new Error("corral policy hook did not run; blocking (fail-closed)");
    if (res.status !== 0) return { block: true, reason: blockReason(res) };
    return undefined; // allow
  });

  // tool_result: ingress withhold-replace. post-tool-use exits 0 and prints an
  // updatedToolOutput object only when it withheld the result; empty stdout means clean. A
  // throw here is SWALLOWED by pi (fail-OPEN), so every anomaly RETURNS a withhold instead.
  pi.on("tool_result", async (event) => {
    try {
      const mapped = toClaude(event.toolName, event.input);
      const res = callCorral(["hook", "post-tool-use"], {
        hook_event_name: "PostToolUse",
        session_id: SESSION_ID,
        cwd: process.cwd(),
        tool_name: mapped.tool_name,
        tool_input: mapped.tool_input,
        tool_response: Array.isArray(event.content) ? event.content : [],
      });
      if (!res.ran || res.status !== 0) {
        return withheld("[corral] tool response withheld — policy hook error (fail-closed).");
      }
      if (res.stdout === "") return undefined; // clean: keep the original result
      return withheld(markerFrom(res.stdout)); // corral withheld it
    } catch (e) {
      return withheld("[corral] tool response withheld — bridge error (fail-closed).");
    }
  });

  // user_bash: policy the user's `!` command, which Claude does not expose to hooks.
  // user_bash has no {block,reason}; a deny SUBSTITUTES a synthetic BashResult for execution.
  // A throw is SWALLOWED (the real command would run — fail-OPEN), so every anomaly RETURNS a
  // deny. Interactive-mode only (print/rpc never emit user_bash).
  pi.on("user_bash", async (event) => {
    try {
      const res = callCorral(["hook", "pre-tool-use", "--decision", "exit2"], {
        hook_event_name: "PreToolUse",
        session_id: SESSION_ID,
        cwd: event.cwd || process.cwd(),
        tool_name: "Bash",
        tool_input: { command: event.command },
      });
      if (!res.ran) return denyBash("[corral] command blocked — policy hook error (fail-closed).");
      if (res.status !== 0) return denyBash(blockReason(res));
      return undefined; // allow: pi runs the real command
    } catch (e) {
      return denyBash("[corral] command blocked — bridge error (fail-closed).");
    }
  });

  // input: scan the user's prompt for secrets before it reaches the model (corral's
  // UserPromptSubmit advisory — a credential pasted into a prompt goes straight to the model
  // provider). On a hit, swallow the prompt (`handled`) and show corral's reason; the user can
  // redact or resubmit (corral marks a prompt once-seen so a verbatim resubmit proceeds). This
  // is ADVISORY, matching corral's claude prompt scan: a clean prompt or any hook error
  // CONTINUES — never gate the user on a scan failure (and pi swallows a thrown input handler
  // anyway). Covers interactive AND rpc/print input, unlike user_bash.
  pi.on("input", async (event, ctx) => {
    try {
      const res = callCorral(["hook", "user-prompt-submit"], {
        hook_event_name: "UserPromptSubmit",
        session_id: SESSION_ID,
        cwd: process.cwd(),
        prompt: event.text,
      });
      if (!res.ran || res.status !== 0 || res.stdout === "") return { action: "continue" };
      const reason = promptBlockReason(res.stdout);
      if (!reason) return { action: "continue" };
      if (ctx && ctx.ui && typeof ctx.ui.notify === "function") ctx.ui.notify(reason, "warning");
      return { action: "handled" }; // swallow: the flagged prompt is NOT sent to the model
    } catch (e) {
      return { action: "continue" };
    }
  });

  // before_agent_start: inject corral's model-only sandbox note (corral hook session-start
  // returns it as hookSpecificOutput.additionalContext). Re-injected each turn, so it
  // survives compaction. Informational — never throw; a missing note simply omits it.
  pi.on("before_agent_start", async () => {
    try {
      const res = callCorral(["hook", "session-start"], {
        hook_event_name: "SessionStart",
        session_id: SESSION_ID,
        cwd: process.cwd(),
      });
      if (!res.ran || res.status !== 0 || res.stdout === "") return undefined;
      const note = JSON.parse(res.stdout)?.hookSpecificOutput?.additionalContext;
      if (!note) return undefined;
      return { message: { customType: "corral.sandbox-note", content: note } };
    } catch (e) {
      return undefined;
    }
  });
};
