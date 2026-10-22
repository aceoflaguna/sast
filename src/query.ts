import path from "node:path";
import { readdir } from "node:fs/promises";
import type { Node, Tree } from "./node";
import { makeDollar, type DollarFn } from "./q";
import { runFlows, type Flow, type FlowSpec } from "./taint";
import { profileFor, type Profile } from "./lang";
import type { Finding, Step } from "./store";
import { step } from "./taint";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface QueryCtx {
  /** jQuery-style: $("Call[function*=exec]").parent().find("Ident") */
  $: DollarFn;
  trees: Tree[];
  profile(t: Tree | Node): Profile;
  /** run the taint engine with an ad-hoc spec and get raw flows back (to post-filter with $) */
  flows(spec: FlowSpec): Flow[];
  report(node: Node, message: string, opts?: { path?: Step[]; severity?: Severity }): void;
}

export interface QueryDef {
  id: string;
  title: string;
  severity: Severity;
  cwe?: string;
  description?: string;
  /** limit to these profiles: javascript | python | php | java (default: all) */
  languages?: string[];
  /** declarative source -> sink query */
  taint?: FlowSpec;
  message?: (f: Flow) => string;
  /** imperative query using $ / flows(); call ctx.report() */
  run?: (ctx: QueryCtx) => void;
  /** set by the loader: file name inside queries/ */
  file?: string;
}
export const defineQuery = (q: QueryDef) => q;

export function runQuery(def: QueryDef, allTrees: Tree[]): Finding[] {
  const trees = def.languages ? allTrees.filter((t) => def.languages!.includes(profileFor(t.language).name)) : allTrees;
  const out: Finding[] = [];
  const base = { queryId: def.id, title: def.title, severity: def.severity, cwe: def.cwe };
  if (def.taint) {
    for (const f of runFlows(trees, def.taint)) {
      out.push({
        ...base, message: def.message?.(f) ?? `Untrusted input reaches ${f.label}`,
        file: f.tree.path, line: f.sink.line, col: f.sink.col, language: f.language, path: f.path, sinkCode: f.sink.text.split("\n")[0].slice(0, 200),
      });
    }
  }
  if (def.run) {
    const ctx: QueryCtx = {
      $: makeDollar(trees), trees, profile: (x) => profileFor("tree" in x ? x.tree.language : x.language),
      flows: (spec) => runFlows(trees, spec),
      report(node, message, o) {
        out.push({
          ...base, severity: o?.severity ?? def.severity, message, file: node.tree.path, line: node.line, col: node.col,
          language: node.tree.language, path: o?.path ?? [step("sink", node)], sinkCode: node.text.split("\n")[0].slice(0, 200),
        });
      },
    };
    def.run(ctx);
  }
  return out;
}

/* ------------------------------------------------------------- registry */
const queriesDir = path.join(import.meta.dir, "..", "queries");
let loaded: QueryDef[] | null = null;
export async function loadQueries(reload = false): Promise<QueryDef[]> {
  if (loaded && !reload) return loaded;
  const files = (await readdir(queriesDir)).filter((f) => /\.(ts|js)$/.test(f) && !f.startsWith("_")).sort();
  const defs: QueryDef[] = [];
  for (const f of files) {
    const mod = await import(path.join(queriesDir, f) + (reload ? `?v=${Date.now()}` : ""));
    if (mod.default?.id) defs.push({ ...mod.default, file: f });
  }
  return (loaded = defs);
}
