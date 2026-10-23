// queries/csrf.ts
import { defineQuery } from "../src/query";
import { textRules } from "./_lib";

const CSRF_MIDDLEWARE = /(csrf|xsrf|CsrfViewMiddleware|csrf_protect|csrf_exempt|verify_csrf|check_csrf|protect_from_forgery)/i;

export default defineQuery({
  id: "csrf",
  title: "Missing CSRF protection",
  severity: "medium",
  cwe: "CWE-352",
  description: "State-changing endpoint lacks CSRF token validation (or explicitly disables it).",
  run(ctx) {
    // 1. Explicit opt-out / exemption
    textRules(ctx, {
      python: [{ sel: "Call", re: /@csrf_exempt/ }],
      ruby: [{ sel: "Call", re: /skip_before_action\s+:verify_authenticity_token/ }],
      php: [{ sel: "Call", re: /\/\/\s*csrf\s*(disabled|off|skip)/i }],
    }, () => "CSRF protection explicitly disabled.");

    // 2. Route definitions for state-changing verbs without csrf middleware mention
    ctx.$("Call").each((n) => {
      const p = ctx.profile(n);
      const c = p.call(n);
      if (!c) return;
      if (!/\.(post|put|patch|delete)$/.test(c.callee)) return;
      // If the route's text block does not mention csrf anywhere, flag as heuristic.
      if (!CSRF_MIDDLEWARE.test(c.node.text)) {
        ctx.report(n, `State-changing route ${c.callee}() does not reference CSRF protection.`, { severity: "low" });
      }
    });

    // 3. Django/Rails: POST handler functions without @csrf_protect or protect_from_forgery in class
    ctx.$("Func").each((fn) => {
      const info = ctx.profile(fn).func(fn);
      if (!info?.name || !/^(post|put|patch|delete|create|update|destroy)/i.test(info.name)) return;
      const enclosing = [...fn.ancestors()].find((a) => a.type.includes("class") || a.type.includes("module"));
      const ctxText = (enclosing?.text ?? "") + fn.text;
      if (!CSRF_MIDDLEWARE.test(ctxText)) {
        ctx.report(fn, `Handler '${info.name}' handles state-changing requests without visible CSRF protection.`, { severity: "low" });
      }
    });
  },
});