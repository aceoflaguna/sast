// queries/missing-authorization.ts
import { defineQuery } from "../src/query";

// Heuristic: route handlers / controller methods that perform a state-changing
// operation but never reference an auth/permission check in their body.
const AUTH_HINT = /(auth|permission|role|admin|owner|can\(|authorize|checkAccess|requireLogin|ensureLoggedIn|isAuthenticated|current_user|currentUser|req\.user|ctx\.user|session\[.user)/i;
const STATE_CHANGING = /(delete|remove|destroy|update|edit|create|insert|save|write|drop|truncate|set|put|post|patch)/i;

export default defineQuery({
  id: "missing-authorization",
  title: "Missing authorization on state-changing handler",
  severity: "high",
  cwe: "CWE-862",
  description: "A route/controller performs a mutation without any visible authorization or ownership check.",
  run({ $, profile, report }) {
    // Func selectors vary by language; use the abstract kind and inspect.
    $("Func").each((fn) => {
      const p = profile(fn);
      const info = p.func(fn);
      if (!info?.name || !STATE_CHANGING.test(info.name)) return;
      const bodyText = info.body.text;
      if (AUTH_HINT.test(bodyText)) return;
      // Only flag functions that are reachable from a route-ish context or have HTTP-ish params.
      const paramsText = info.params.map((x) => x.key).join(" ");
      if (!/(req|request|ctx|res|response|route|params|body|id)/i.test(paramsText)) return;
      report(fn, `Handler '${info.name}' mutates state without an authorization check in its body.`, {
        severity: "high",
      });
    });

    // Also catch bare route registrations that pass a handler defined elsewhere
    // where the route path itself is state-changing but no middleware is attached.
    $("Call").each((n) => {
      const p = profile(n);
      const c = p.call(n);
      if (!c) return;
      if (!/^(app|router|route|r|rtr)\.(delete|put|patch|post)$/.test(c.callee)) return;
      // If only two args (path, handler) and no middleware, flag it.
      if (c.args.length === 2 && /(delete|put|patch)/.test(c.callee)) {
        report(n, `State-changing route ${c.callee}() registered without middleware.`, { severity: "medium" });
      }
    });
  },
});