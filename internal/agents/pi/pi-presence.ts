/**
 * corral presence backstop for pi.
 *
 * Installed GLOBALLY into pi's extensions dir (~/.pi/agent/extensions/) by `corral sync pi`,
 * so it loads on every pi session — including a bare `pi` started WITHOUT corral, which the
 * `-e` policy bridge can never reach (corral injects that only when it launches pi).
 *
 * Its only job is a one-time nudge: when pi runs OUTSIDE corral (no CORRAL_SANDBOX marker) it
 * warns that the session is not sandboxed and how to fix it. Inside corral it stays silent —
 * the `-e` bridge (corral-policy.ts) does all the enforcement, and this would be redundant.
 *
 * It enforces NOTHING (no policy, no network), so even a prompt-injected agent inside corral
 * deleting it only loses the host-side nudge — corral's in-sandbox enforcement is the separate,
 * read-only-bound bridge. Dependency-free annotation-free JS-in-.ts (jiti loads it raw).
 */
import { fileURLToPath } from "node:url";

let warned = false;

export default (pi) => {
  pi.on("input", async (event, ctx) => {
    // Inside corral the -e policy bridge is active; say nothing.
    if (process.env.CORRAL_SANDBOX) return { action: "continue" };
    // Already warned this session — let prompts through (a one-time speed bump, not a wall).
    if (warned) return { action: "continue" };
    warned = true;

    let self = "the corral presence extension under ~/.pi/agent/extensions/";
    try {
      self = fileURLToPath(import.meta.url);
    } catch (e) {}

    const msg = [
      "⚠  corral: this pi session is NOT sandboxed — it was started without `corral run`.",
      "   Filesystem isolation and the ~/.ssh / ~/.gnupg / ~/.aws masks are OFF.",
      "   To sandbox it, exit and relaunch with:  corral run pi",
      "   Your prompt was NOT sent — resubmit to proceed (this warning fires once per session).",
      "   If you've removed corral and want to stop this warning, delete this file:",
      "     " + self,
    ].join("\n");

    if (ctx && ctx.ui && typeof ctx.ui.notify === "function") ctx.ui.notify(msg, "warning");
    // Swallow this first prompt so it is NOT sent to the model — a real speed bump rather than
    // a notice that scrolls past. `warned` is now set, so a resubmit proceeds. Mirrors claude's
    // presence warning (swallow the first prompt, resubmit once).
    return { action: "handled" };
  });
};
