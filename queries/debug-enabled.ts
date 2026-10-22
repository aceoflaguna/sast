import { defineQuery } from "../src/query";
import { textRules } from "./_lib";

export default defineQuery({
  id: "debug-enabled",
  title: "Debug mode / verbose errors enabled",
  severity: "medium",
  cwe: "CWE-489",
  description: "Debug features or stack traces are exposed to clients (interactive debuggers, pprof, phpinfo(), developer error pages).",
  run(ctx) {
    textRules(ctx, {
      javascript: [
        { sel: "Call", re: /^(res|response)\.(status\(\s*\d+\s*\)\.)?(send|json|end)\([^)]*\b(err|error|e)\.stack\b/ },
        { sel: "Call", re: /^app\.use\(\s*(require\(\s*['"]errorhandler['"]\s*\)|errorhandler)\(\s*\)\s*\)/ },
      ],
      python: [
        { sel: "Call", re: /\.run\([^)]*\bdebug\s*=\s*True/ },
        { sel: "Assign", re: /^(app\.debug|app\.config\[['"]DEBUG['"]\]|DEBUG)\s*=\s*True\b/ },
        { sel: "Call", re: /^(return\s+)?traceback\.format_exc\(\)/ },
      ],
      php: [
        { sel: "Call", re: /^ini_set\(\s*['"]display_errors['"]\s*,\s*(1|true|['"](1|on|true)['"])/i },
        { sel: "Call", re: /^phpinfo\(/ },
      ],
      java: [{ sel: "Call", re: /\.printStackTrace\(\s*\w+\.getWriter\(\)\s*\)/ }],
      go: [{ sel: "import_spec", re: /net\/http\/pprof/ }],
      ruby: [{ sel: "Assign", re: /consider_all_requests_local\s*=\s*true/ }, { sel: "Call", re: /^config\.consider_all_requests_local\s*=\s*true/ }],
    }, () => "Debug / verbose-error feature enabled; make sure it cannot reach production.");

    // C#: UseDeveloperExceptionPage() is fine inside `if (env.IsDevelopment())`, a finding anywhere else.
    ctx.$("Call").each((n) => {
      if (ctx.profile(n).name !== "csharp" || !/UseDeveloperExceptionPage\(\)/.test(n.text) || n.type !== "invocation_expression") return;
      const gated = [...n.ancestors()].some((a) => a.type === "if_statement" && /IsDevelopment|IsEnvironment\(\s*"Development"/.test(a.child("condition")?.text ?? a.text.slice(0, 120)));
      if (!gated) ctx.report(n, "Developer exception page enabled outside an IsDevelopment() check.");
    });
  },
});
