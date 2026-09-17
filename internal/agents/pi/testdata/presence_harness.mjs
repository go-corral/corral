// Presence-backstop harness: loads pi-presence.ts with a mock pi + mock ctx.ui.notify and
// asserts it stays silent inside corral (CORRAL_SANDBOX set) and warns exactly once when pi
// runs outside corral. Run by the gated Go test TestPiPresenceNodeHarness. argv[2] = path to
// pi-presence.ts. Annotation-free, so we copy to .mjs and import.
import { writeFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const tmp = mkdtempSync(join(tmpdir(), "corral-presence-"));
const mjs = join(tmp, "presence.mjs");
writeFileSync(mjs, readFileSync(process.argv[2], "utf8"));
const factory = (await import(pathToFileURL(mjs).href)).default;

const handlers = {};
factory({ on: (ev, fn) => (handlers[ev] = fn) });

let failures = 0;
const check = (c, m) => {
  if (!c) {
    console.error("FAIL:", m);
    failures++;
  }
};
let notified = [];
const ctx = { ui: { notify: (msg) => notified.push(msg) } };
const input = () => handlers.input({ type: "input", text: "hi", source: "interactive" }, ctx);

// Inside corral (CORRAL_SANDBOX set): silent, never swallow.
process.env.CORRAL_SANDBOX = "1";
notified = [];
let r = await input();
check(r && r.action === "continue", "sandboxed -> continue");
check(notified.length === 0, "sandboxed -> no warning (the -e bridge does the work)");

// Outside corral, first prompt: warn AND swallow it (so it is not sent), with the message.
delete process.env.CORRAL_SANDBOX;
notified = [];
r = await input();
check(r && r.action === "handled", "unsandboxed first prompt -> handled (swallowed, not sent)");
check(notified.length === 1, "unsandboxed -> warns once");
check(
  notified[0] && /NOT sandboxed/.test(notified[0]) && /resubmit/.test(notified[0]) && /delete this file/.test(notified[0]),
  "warning includes the not-sandboxed notice, the resubmit hint, and the removal hint",
);

// Subsequent inputs (the resubmit): proceed, no repeat warning (one-time speed bump).
notified = [];
r = await input();
check(r && r.action === "continue", "resubmit after the warning -> continue (proceeds)");
check(notified.length === 0, "warns only once per session");

if (failures > 0) {
  console.error(`${failures} presence assertion(s) failed`);
  process.exit(1);
}
console.log("presence harness: all assertions passed");
