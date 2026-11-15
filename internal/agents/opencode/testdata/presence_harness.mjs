// Presence-backstop harness: loads opencode-presence.js with a mock V2 ctx and asserts that it
// registers nothing inside corral (CORRAL_SANDBOX set) and warns once per root session outside.
// Run by the gated Go test. argv[2] = path to opencode-presence.js. The plugin is copied to a
// .mjs file so node loads it as an ES module.
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const tmp = mkdtempSync(join(tmpdir(), "corral-presence-"));
process.on("exit", () => rmSync(tmp, { recursive: true, force: true }));
const mjs = join(tmp, "presence.mjs");
writeFileSync(mjs, readFileSync(process.argv[2], "utf8"));
const plugin = (await import(pathToFileURL(mjs).href)).default;

let failures = 0;
const check = (c, m) => {
  if (!c) {
    console.error("FAIL:", m);
    failures++;
  }
};

check(plugin.id === "corral-presence" && typeof plugin.setup === "function", "default export has id and setup");

const parents = {};
const mockCtx = () => {
  const hooks = {};
  const ctx = {
    session: {
      hook: (name, fn) => (hooks[name] = fn),
      get: async (input) => {
        if (typeof input !== "object" || input === null) throw new Error("session.get takes {sessionID}");
        // opencode's promise adapter unwraps a `{data}`-only success body, so get returns Session.Info.
        return { id: input.sessionID, parentID: parents[input.sessionID] };
      },
    },
  };
  return { ctx, hooks };
};
const prompt = (hook, sessionID, text = "hi") => {
  const ev = { sessionID, messageID: "m", prompt: { text, files: [] }, metadata: {}, delivery: "immediate" };
  return hook(ev).then(() => ev.prompt.text);
};

// Inside corral: no hook.
process.env.CORRAL_SANDBOX = "1";
let m = mockCtx();
await plugin.setup(m.ctx);
check(Object.keys(m.hooks).length === 0, "sandboxed -> registers no hook");

// Outside corral.
delete process.env.CORRAL_SANDBOX;
m = mockCtx();
await plugin.setup(m.ctx);
check(typeof m.hooks.prompt === "function", "unsandboxed -> registers a prompt hook");
const hook = m.hooks.prompt;

let text = await prompt(hook, "root1");
for (const want of ["NOT sandboxed", "corral run opencode", mjs, "delete this file", "Relay this warning", "Run no tool"]) {
  check(text.includes(want), `the first prompt of a root session is replaced with a warning that names ${want}`);
}

text = await prompt(hook, "root1");
check(text === "hi", "second prompt of the same session passes unchanged");

text = await prompt(hook, "root2");
check(text !== "hi" && text.includes("corral run opencode"), "a new root session warns once");

parents.child1 = "root1";
text = await prompt(hook, "child1", "do the task");
check(text === "do the task", "a session with a parentID passes unchanged");

// A failing session.get counts as a root session and still warns.
m = mockCtx();
m.ctx.session.get = async () => {
  throw new Error("boom");
};
await plugin.setup(m.ctx);
text = await prompt(m.hooks.prompt, "root3");
check(text !== "hi" && text.includes("corral run opencode"), "a failing session.get -> warns");

if (failures > 0) {
  console.error(`${failures} presence assertion(s) failed`);
  process.exit(1);
}
console.log("presence harness: all assertions passed");
