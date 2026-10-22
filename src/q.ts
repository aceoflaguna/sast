/** jQuery-style traversal over AST nodes:  $("Call[function=eval]").parent().find("Ident").text() */
import { Node, Tree } from "./node";
import { matches, parseSelector } from "./selector";

type Pred = string | ((n: Node, i: number) => boolean);
const toFn = (p: Pred) => (typeof p === "string" ? (n: Node) => matches(n, p) : p);

export class Q implements Iterable<Node> {
  readonly nodes: Node[];
  constructor(nodes: Iterable<Node>) { this.nodes = [...new Set(nodes)]; }
  [Symbol.iterator]() { return this.nodes[Symbol.iterator](); }
  get length() { return this.nodes.length; }

  /* ---- traversal ---- */
  find(sel: string) { const s = parseSelector(sel); const out: Node[] = []; for (const n of this.nodes) for (const d of n.descendants()) if (matches(d, s)) out.push(d); return new Q(out); }
  children(sel?: string) { const out = this.nodes.flatMap((n) => n.kids); return new Q(sel ? out.filter((n) => matches(n, sel)) : out); }
  /** named children only (skips punctuation/keywords) */
  named() { return new Q(this.nodes.flatMap((n) => n.namedChildren)); }
  child(field: string) { return new Q(this.nodes.flatMap((n) => n.childrenByField(field))); }
  parent(sel?: string) { const out = this.nodes.map((n) => n.parent).filter(Boolean) as Node[]; return new Q(sel ? out.filter((n) => matches(n, sel)) : out); }
  parents(sel?: string) { const out = this.nodes.flatMap((n) => [...n.ancestors()]); return new Q(sel ? out.filter((n) => matches(n, sel)) : out); }
  closest(sel: string) { const out: Node[] = []; for (const n of this.nodes) { for (const a of [n, ...n.ancestors()]) if (matches(a, sel)) { out.push(a); break; } } return new Q(out); }
  next(sel?: string) { const out = this.nodes.map((n) => n.next).filter(Boolean) as Node[]; return new Q(sel ? out.filter((n) => matches(n, sel)) : out); }
  prev(sel?: string) { const out = this.nodes.map((n) => n.prev).filter(Boolean) as Node[]; return new Q(sel ? out.filter((n) => matches(n, sel)) : out); }
  siblings(sel?: string) { const out = this.nodes.flatMap((n) => (n.parent?.kids ?? []).filter((k) => k !== n)); return new Q(sel ? out.filter((n) => matches(n, sel)) : out); }

  /* ---- filtering ---- */
  filter(p: Pred) { return new Q(this.nodes.filter(toFn(p))); }
  not(p: Pred) { const f = toFn(p); return new Q(this.nodes.filter((n, i) => !f(n, i))); }
  has(sel: string) { return new Q(this.nodes.filter((n) => [...n.descendants()].some((d) => matches(d, sel)))); }
  is(p: Pred) { const f = toFn(p); return this.nodes.some((n, i) => f(n, i)); }
  first() { return new Q(this.nodes.slice(0, 1)); }
  last() { return new Q(this.nodes.slice(-1)); }
  eq(i: number) { return new Q([this.nodes.at(i)].filter(Boolean) as Node[]); }
  slice(a?: number, b?: number) { return new Q(this.nodes.slice(a, b)); }
  add(other: Q | Node | Node[]) { return new Q([...this.nodes, ...(other instanceof Q ? other.nodes : Array.isArray(other) ? other : [other])]); }

  /* ---- reading ---- */
  each(fn: (n: Node, i: number) => void) { this.nodes.forEach(fn); return this; }
  map<T>(fn: (n: Node, i: number) => T) { return this.nodes.map(fn); }
  get(i?: number) { return i === undefined ? this.nodes : this.nodes[i]; }
  text() { return this.nodes[0]?.text ?? ""; }
  texts() { return this.nodes.map((n) => n.text); }
  type() { return this.nodes[0]?.type; }
  /** text of the child in a given field, e.g. $(call).attr("function") */
  attr(field: string) { return this.nodes[0]?.child(field)?.text; }
  loc() { return this.nodes[0]?.loc(); }
}

export type DollarFn = (input: string | Node | Node[] | Q) => Q;

/** Build `$` bound to a set of parsed files. $("sel") searches all of them; $(node) wraps node(s). */
export function makeDollar(trees: Tree[]): DollarFn {
  return (input) => {
    if (input instanceof Q) return input;
    if (input instanceof Node) return new Q([input]);
    if (Array.isArray(input)) return new Q(input);
    const s = parseSelector(input);
    const out: Node[] = [];
    for (const t of trees) for (const n of t.nodes) if (n.named && matches(n, s)) out.push(n);
    return new Q(out);
  };
}
export { matches, parseSelector };
