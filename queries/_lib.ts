/** Shared helpers for pattern (non-taint) queries. Files starting with "_" are not loaded as queries. */
import type { QueryCtx } from "../src/query";
import type { Node } from "../src/node";

/** Match calls by normalized callee, optionally requiring a string-literal argument to match a regex. */
export interface CallRule { callee: RegExp; arg?: { index: number; re: RegExp }; note?: string; when?: (n: Node) => boolean }

export function callRules(ctx: QueryCtx, rules: Record<string, CallRule[]>, message: (rule: CallRule, callee: string) => string, severity?: "critical" | "high" | "medium" | "low" | "info") {
  const seen = new Set<string>();
  ctx.$("Call").each((n) => {
    const p = ctx.profile(n);
    const list = rules[p.name];
    if (!list) return;
    const c = p.call(n);
    if (!c) return;
    for (const r of list) {
      if (!r.callee.test(c.callee)) continue;
      if (r.arg) {
        const a = c.args[r.arg.index];
        const v = a ? p.stringValue(a) : null;
        if (v == null || !r.arg.re.test(v)) continue;
      }
      if (r.when && !r.when(n)) continue;
      const key = `${n.tree.path}:${n.line}:${n.col}`;
      if (seen.has(key)) return;
      seen.add(key);
      ctx.report(n, message(r, c.callee), severity ? { severity } : undefined);
      return;
    }
  });
}

/** Match any node (selector per language) whose source text matches a regex. Deduplicated per line. */
export interface TextRule { sel: string; re: RegExp; note?: string }
export function textRules(ctx: QueryCtx, rules: Record<string, TextRule[]>, message: (rule: TextRule, n: Node) => string) {
  const seen = new Set<string>();
  for (const [lang, list] of Object.entries(rules)) {
    for (const r of list) {
      ctx.$(r.sel).each((n) => {
        if (ctx.profile(n).name !== lang) return;
        if (!r.re.test(n.text)) return;
        // report the innermost match only: skip if a child node also matches the same rule
        if ([...n.descendants()].some((d) => d.named && ctx.profile(d).name === lang && d.type === n.type && r.re.test(d.text))) return;
        const key = `${n.tree.path}:${n.line}`; // one finding per line per query
        if (seen.has(key)) return;
        seen.add(key);
        ctx.report(n, message(r, n));
      });
    }
  }
}
