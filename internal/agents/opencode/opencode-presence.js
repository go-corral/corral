/**
 * corral presence backstop for opencode.
 *
 * `corral sync opencode` installs this file into opencode's plugins directory, so it loads in
 * every opencode session, including a bare `opencode` that started without corral. Outside
 * corral it replaces the first prompt of each root session with a warning. Inside corral
 * (CORRAL_SANDBOX set) it registers nothing: the policy plugin does the enforcement.
 */
import { fileURLToPath } from "node:url";

const seen = new Set();

function warning() {
  let self = "the corral-presence.js file in the opencode plugins directory";
  try {
    self = fileURLToPath(import.meta.url);
  } catch {}
  return [
    "corral warning: this opencode session is NOT sandboxed. It started without `corral run`.",
    "Filesystem isolation and the credential masks are OFF.",
    "To sandbox it, exit and start opencode with: corral run opencode",
    "The user's prompt was NOT sent. The user can resubmit it to proceed. This warning appears once per session.",
    "To stop this warning without corral, delete this file: " + self,
    "Relay this warning to the user now. Run no tool.",
  ].join("\n");
}

async function isChild(ctx, sessionID) {
  try {
    const session = await ctx.session.get({ sessionID });
    return Boolean(session && session.parentID);
  } catch {
    return false;
  }
}

export default {
  id: "corral-presence",
  setup(ctx) {
    if (process.env.CORRAL_SANDBOX) return;
    ctx.session.hook("prompt", async (ev) => {
      if (seen.has(ev.sessionID)) return;
      seen.add(ev.sessionID);
      if (await isChild(ctx, ev.sessionID)) return;
      ev.prompt.text = warning();
    });
  },
};
