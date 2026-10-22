/**
 * Language-agnostic taint tracking.
 *
 *  - Walks every function/module scope in source order, keeping an environment  path -> Taint.
 *  - A Taint carries the list of Steps (source -> propagations -> sink) so the UI can show the whole path.
 *  - Functions get summaries (which params reach a sink, which params flow to the return value), computed to a
 *    fixpoint over the whole project, so flows across function and file boundaries are found.
 *
 * It is a heuristic engine (flow-insensitive across branches, name-based call resolution) — intentionally simple,
 * fast and easy to extend per language through src/lang/*.ts.
 */
import type { Node, Tree } from "./node";
import type { Step } from "./store";
import { profileFor } from "./lang";
import type { Profile, CallInfo } from "./lang/types";
import { lastSeg } from "./lang/common";

export interface SinkSpec {
  /** matched against the normalized callee ("db.query", "cursor.execute", "new File", "echo") */
  callee?: RegExp;
  /** matched against the assignment target path ("el.innerHTML") */
  assign?: RegExp;
  /** which argument positions are dangerous (default: all positional args) */
  args?: number[];
  /** also check these keyword arguments by name (Ruby `where(name: x)` is NOT checked unless listed); `true` = all */
  kwargs?: string[] | true;
  when?: (c: CallInfo) => boolean;
  /** check the receiver (`x` in `x.html_safe`) instead of the arguments */
  receiver?: boolean;
  label?: string;
}
export type PerLang<T> = Record<string, T[]>; // keys: "*" or javascript | python | php | java
export interface FlowSpec {
  sinks: PerLang<SinkSpec>;
  /** extra sources on top of the built-in user-input ones. */
  sources?: PerLang<RegExp>;
  /** callees that neutralise taint for this vulnerability class */
  sanitizers?: PerLang<RegExp>;
  /** only built-in user input sources when false is not supported; set true to ignore built-ins */
  onlyCustomSources?: boolean;
}
export interface Flow { sink: Node; label: string; path: Step[]; source: Step; language: string; tree: Tree }

interface Taint { kind: "source" | "param"; param?: number; steps: Step[] }
interface PSink { steps: Step[]; node: Node; label: string }
interface Summary { retParams: Set<number>; retTaint: Taint | null; paramSinks: Map<number, PSink> }

const pick = <T,>(m: PerLang<T> | undefined, lang: string): T[] => (m ? [...(m["*"] ?? []), ...(m[lang] ?? [])] : []);
const MAX_STEPS = 40;

class Env {
  vars = new Map<string, Taint>();
  constructor(public parent: Env | null) {}
  get(k: string): Taint | undefined { return this.vars.get(k) ?? this.parent?.get(k); }
  set(k: string, t: Taint) { this.vars.set(k, t); }
  del(k: string) { this.vars.delete(k); }
}

export function step(kind: Step["kind"], n: Node, note?: string): Step {
  return { kind, file: n.tree.path, line: n.line, col: n.col, code: n.text.split("\n")[0].trim().slice(0, 160), note };
}

export class TaintEngine {
  private summaries = new Map<string, Summary>();
  private flows: Flow[] = [];
  private seen = new Set<string>();
  private collecting = false;
  // per-scope state
  private profile!: Profile;
  private spec!: FlowSpec;
  private sources: RegExp[] = [];
  private sanitizers: RegExp[] = [];
  private sinks: SinkSpec[] = [];
  private cur: Summary | null = null;

  constructor(private trees: Tree[], spec: FlowSpec) { this.spec = spec; }

  run(): Flow[] {
    for (let pass = 0; pass < 3; pass++) this.analyzeAll(false);
    this.analyzeAll(true);
    return this.flows;
  }

  private analyzeAll(collect: boolean) {
    this.collecting = collect;
    this.flows = collect ? [] : this.flows;
    for (const t of this.trees) {
      this.profile = profileFor(t.language);
      const lang = this.profile.name;
      this.sources = [...(this.spec.onlyCustomSources ? [] : this.profile.sources), ...pick(this.spec.sources, lang)];
      this.sanitizers = pick(this.spec.sanitizers, lang);
      this.sinks = pick(this.spec.sinks, lang);
      this.scope(t.root, null, null);
    }
  }

  private summary(key: string): Summary {
    let s = this.summaries.get(key);
    if (!s) this.summaries.set(key, (s = { retParams: new Set(), retTaint: null, paramSinks: new Map() }));
    return s;
  }
  private key(lang: string, name: string) { return `${lang}:${name}`; }

  private scope(root: Node, fn: ReturnType<Profile["func"]>, parent: Env | null) {
    const env = new Env(parent);
    const saved = this.cur;
    this.cur = fn?.name ? this.summary(this.key(this.profile.name, fn.name)) : fn ? { retParams: new Set(), retTaint: null, paramSinks: new Map() } : null;
    if (fn) {
      fn.params.forEach((p, i) => {
        if (this.profile.taintedParam?.(p.node)) env.set(p.key, { kind: "source", steps: [step("source", p.node, `user-controlled parameter '${p.key}'`)] });
        else env.set(p.key, { kind: "param", param: i, steps: [] });
      });
      if (fn.exprBody) this.handleReturnValue(fn.body, env);
    }
    const visit = (n: Node) => {
      const f = this.profile.func(n);
      if (f && n !== root) { this.scope(f.body, f, env); return; }
      const a = this.profile.assign(n); if (a) for (const x of Array.isArray(a) ? a : [a]) this.onAssign(x, env);
      const c = this.profile.call(n); if (c) this.onCall(c, env);
      const r = this.profile.ret(n); if (r && fn) this.handleReturnValue(r, env, n);
      for (const k of n.kids) if (k.named) visit(k);
    };
    visit(root);
    if (fn?.implicitReturn) this.handleReturnValue(fn.implicitReturn, env);
    this.cur = saved;
  }

  /* ------------------------------------------------------------ statements */
  private onAssign(a: ReturnType<Profile["assign"]> & {}, env: Env) {
    const t = this.expr(a.value, env);
    for (const tgt of a.targets) {
      const key = this.profile.pathOf(tgt);
      if (!key) continue;
      for (const s of this.sinks) {
        if (s.assign && t && s.assign.test(key) && !this.sanitizers.some((r) => r.test(key))) this.report(t, step("sink", a.node, s.label ?? `assignment to ${key}`), a.node, s.label ?? key);
      }
      if (t) {
        const prev = a.compound ? env.get(key) : undefined;
        const base = prev && prev.kind === "source" && t.kind !== "source" ? prev : t;
        env.set(key, { ...base, steps: [...base.steps, step("propagate", a.node, `'${key}' now carries tainted data`)].slice(-MAX_STEPS) });
      } else if (!a.compound) env.del(key);
    }
  }

  private onCall(c: CallInfo, env: Env) {
    const lang = this.profile.name;
    // 1. direct sinks
    for (const s of this.sinks) {
      if (!s.callee || !s.callee.test(c.callee)) continue;
      if (s.when && !s.when(c)) continue;
      const idxs = s.receiver ? [0] : s.args ?? c.args.map((_, i) => i);
      const cands: Node[] = idxs.map((i) => (s.receiver ? c.receiver : c.args[i])).filter(Boolean) as Node[];
      if (s.kwargs && c.kwargs) for (const k of c.kwargs) if (s.kwargs === true || s.kwargs.includes(k.name)) cands.push(k.value);
      for (const arg of cands) {
        const t = this.expr(arg, env);
        if (!t) continue;
        const sink = step("sink", c.node, s.label ?? c.callee);
        if (t.kind === "source") this.report(t, sink, c.node, s.label ?? c.callee);
        else if (this.cur && !this.cur.paramSinks.has(t.param!)) this.cur.paramSinks.set(t.param!, { steps: [...t.steps, sink], node: c.node, label: s.label ?? c.callee });
      }
    }
    // 2. calls to project functions whose parameters reach a sink
    const name = lastSeg(c.callee.replace(/^new /, ""));
    const sum = this.summaries.get(this.key(lang, name));
    if (sum?.paramSinks.size) {
      c.args.forEach((arg, i) => {
        const ps = sum.paramSinks.get(i);
        if (!ps) return;
        const t = this.expr(arg, env);
        if (!t) return;
        const call = step("call", c.node, `tainted value passed to ${name}() as argument ${i + 1}`);
        if (t.kind === "source") this.report(t, ps.steps.at(-1)!, ps.node, ps.label, [call, ...ps.steps]);
        else if (this.cur && !this.cur.paramSinks.has(t.param!)) this.cur.paramSinks.set(t.param!, { steps: [...t.steps, call, ...ps.steps], node: ps.node, label: ps.label });
      });
    }
  }

  private handleReturnValue(valueNode: Node, env: Env, at?: Node) {
    if (!this.cur) return;
    const t = this.expr(valueNode, env);
    if (!t) return;
    if (t.kind === "param") this.cur.retParams.add(t.param!);
    else if (!this.cur.retTaint) this.cur.retTaint = { kind: "source", steps: [...t.steps, step("return", at ?? valueNode, "tainted value returned")].slice(-MAX_STEPS) };
  }

  private report(t: Taint, sinkStep: Step, sinkNode: Node, label: string, via: Step[] = [sinkStep]) {
    if (!this.collecting) return;
    const key = `${sinkNode.tree.path}:${sinkNode.line}:${sinkNode.col}:${label}`;
    if (this.seen.has(key + "|" + (t.steps[0]?.line ?? 0))) return;
    this.seen.add(key + "|" + (t.steps[0]?.line ?? 0));
    this.flows.push({ sink: sinkNode, label, path: [...t.steps, ...via], source: t.steps[0], language: sinkNode.tree.language, tree: sinkNode.tree });
  }

  /* ------------------------------------------------------------ expressions */
  private isSource(path: string | null) { return !!path && this.sources.some((r) => r.test(path)); }
  private isSanitizer(callee: string) { return this.sanitizers.some((r) => r.test(callee)) || this.profile.numeric.test(callee); }
  private pickBest(ts: (Taint | null)[]): Taint | null {
    let best: Taint | null = null;
    for (const t of ts) { if (!t) continue; if (t.kind === "source") return t; best ??= t; }
    return best;
  }

  expr(n: Node, env: Env): Taint | null {
    const p = this.profile;
    if (!n.named) return null;
    if (p.safeCast?.(n)) return null;
    if (p.func(n)) return null;
    const kinds = p.kinds;
    const type = n.type;

    if (kinds.Call.includes(type)) {
      const c = p.call(n);
      // a call whose only "argument" is itself (shell backticks) has no callee semantics: fall through to its children
      if (c && !(c.args.length === 1 && c.args[0] === n)) {
        const path = p.pathOf(n);
        // sanitizers win over sources: `params[:id].to_i` matches the `params` source pattern but is neutralised
        if (this.isSanitizer(c.callee)) return null;
        if (this.isSource(path) || this.isSource(c.callee)) return { kind: "source", steps: [step("source", n, `user input: ${path ?? c.callee}`)] };
        const name = lastSeg(c.callee.replace(/^new /, ""));
        const sum = this.summaries.get(this.key(p.name, name));
        if (sum && (sum.retParams.size || sum.retTaint)) {
          const ts: (Taint | null)[] = [];
          for (const i of sum.retParams) { const a = c.args[i]; if (a) { const t = this.expr(a, env); if (t) ts.push({ ...t, steps: [...t.steps, step("return", n, `${name}() returns its argument ${i + 1}`)] }); } }
          if (sum.retTaint) ts.push({ kind: "source", steps: [step("call", n, `calls ${name}()`), ...sum.retTaint.steps] });
          const best = this.pickBest(ts);
          if (best) return best;
        }
        // unknown callee: assume taint flows through receiver and arguments (string builders, format, concat, ...)
        return this.pickBest([c.receiver ? this.expr(c.receiver, env) : null, ...c.args.map((a) => this.expr(a, env)), ...(c.kwargs ?? []).map((k) => this.expr(k.value, env))]);
      }
    }
    if (kinds.Member.includes(type) || kinds.Ident.includes(type)) {
      const path = p.pathOf(n);
      if (path) {
        if (this.isSource(path)) return { kind: "source", steps: [step("source", n, `user input: ${path}`)] };
        const e = env.get(path);
        if (e) return e;
      }
      const obj = p.memberObject(n);
      return obj ? this.expr(obj, env) : null;
    }
    const kids = p.exprChildren ? p.exprChildren(n) : n.namedChildren;
    return this.pickBest(kids.map((k) => this.expr(k, env)));
  }
}

export function runFlows(trees: Tree[], spec: FlowSpec): Flow[] {
  return new TaintEngine(trees, spec).run();
}
