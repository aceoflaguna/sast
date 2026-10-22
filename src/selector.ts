/**
 * CSS-like selectors over AST nodes.
 *
 *   call_expression                      node type
 *   Call                                 abstract kind (resolved per language: call_expression / call / method_invocation ...)
 *   *                                    any node
 *   a b | a > b | a + b | a ~ b          descendant / child / next sibling / following sibling
 *   a, b                                 union
 *   [text="x"] [text*="x"] [text^=..] [text$=..] [text~=/re/i] [text!=..]
 *   [type=..] [field=..] [line=12]       builtin attributes
 *   [callee*="query"]                    normalized callee of a Call in ANY language ("db.query", "$pdo.query", "new File", "echo")
 *   [path^="req.query"]                  normalized access path of identifiers / member chains / calls
 *   [fname=handler]                      function name of a Func in any language
 *   [function="eval"]                    any other name = text of the child in that field   (call_expression[function=eval])
 *   [arguments]                          existence of that field child
 *   :has(sel) :has(> sel) :not(sel) :is(a,b) :contains("txt") :first-child :last-child :nth-child(n) :named :leaf
 */
import type { Node } from "./node";
import { profileFor } from "./lang";

type Attr = { name: string; op?: string; value?: string | RegExp };
type Pseudo = { name: string; arg?: string; sel?: Complex };
type Compound = { tag?: string; attrs: Attr[]; pseudos: Pseudo[] };
type Complex = { parts: { comb: " " | ">" | "+" | "~" | null; c: Compound }[] };
export type Selector = Complex[];

const cache = new Map<string, Selector>();

export function parseSelector(src: string): Selector {
  const hit = cache.get(src);
  if (hit) return hit;
  const p = new SelParser(src);
  const out = p.list();
  p.ws();
  if (p.i < src.length) throw new Error(`Selector syntax error at ${p.i}: "${src.slice(p.i, p.i + 15)}"`);
  cache.set(src, out);
  return out;
}

class SelParser {
  i = 0;
  constructor(public s: string) {}
  ws() { while (/\s/.test(this.s[this.i] ?? "")) this.i++; }
  list(): Selector {
    const out = [this.complex()];
    this.ws();
    while (this.s[this.i] === ",") { this.i++; out.push(this.complex()); this.ws(); }
    return out;
  }
  complex(): Complex {
    const parts: Complex["parts"] = [];
    this.ws();
    let comb: any = null;
    // leading combinator (only valid inside :has)
    if (/[>+~]/.test(this.s[this.i] ?? "")) { comb = this.s[this.i++]; this.ws(); }
    parts.push({ comb, c: this.compound() });
    while (true) {
      const before = this.i;
      this.ws();
      const ch = this.s[this.i];
      if (ch === undefined || ch === "," || ch === ")") { break; }
      let c: any = " ";
      if (/[>+~]/.test(ch)) { c = ch; this.i++; this.ws(); }
      else if (this.i === before) break;
      parts.push({ comb: c, c: this.compound() });
    }
    return { parts };
  }
  ident() { const m = /^[A-Za-z_$*][\w$-]*|^\*/.exec(this.s.slice(this.i)); if (!m) return undefined; this.i += m[0].length; return m[0]; }
  compound(): Compound {
    const c: Compound = { attrs: [], pseudos: [] };
    const t = this.ident();
    if (t && t !== "*") c.tag = t;
    while (this.i < this.s.length) {
      const ch = this.s[this.i];
      if (ch === "[") c.attrs.push(this.attr());
      else if (ch === ":") c.pseudos.push(this.pseudo());
      else break;
    }
    if (!t && !c.attrs.length && !c.pseudos.length) throw new Error(`Selector syntax error at ${this.i}: "${this.s.slice(this.i, this.i + 15)}"`);
    return c;
  }
  attr(): Attr {
    this.i++; // [
    this.ws();
    const name = /^[A-Za-z_][\w-]*/.exec(this.s.slice(this.i))?.[0];
    if (!name) throw new Error("Bad attribute selector");
    this.i += name.length; this.ws();
    if (this.s[this.i] === "]") { this.i++; return { name }; }
    const op = /^(\*=|\^=|\$=|~=|!=|=)/.exec(this.s.slice(this.i))?.[0];
    if (!op) throw new Error("Bad attribute operator");
    this.i += op.length; this.ws();
    let value: string | RegExp;
    const q = this.s[this.i];
    if (q === '"' || q === "'") {
      let j = this.i + 1, v = "";
      while (j < this.s.length && this.s[j] !== q) { if (this.s[j] === "\\") j++; v += this.s[j++]; }
      this.i = j + 1; value = v;
    } else if (q === "/") {
      let j = this.i + 1; while (j < this.s.length && !(this.s[j] === "/" && this.s[j - 1] !== "\\")) j++;
      const body = this.s.slice(this.i + 1, j); j++;
      const flags = /^[gimsuy]*/.exec(this.s.slice(j))![0]; j += flags.length;
      this.i = j; value = new RegExp(body, flags);
    } else {
      const m = /^[^\]\s]+/.exec(this.s.slice(this.i))!; this.i += m[0].length; value = m[0];
    }
    this.ws();
    if (this.s[this.i] !== "]") throw new Error("Unterminated attribute selector");
    this.i++;
    return { name, op, value };
  }
  pseudo(): Pseudo {
    this.i++; // :
    const name = /^[\w-]+/.exec(this.s.slice(this.i))?.[0];
    if (!name) throw new Error("Bad pseudo selector");
    this.i += name.length;
    if (this.s[this.i] !== "(") return { name };
    this.i++;
    if (["has", "not", "is"].includes(name)) {
      const sel = this.list(); this.ws();
      if (this.s[this.i] !== ")") throw new Error("Unterminated :" + name);
      this.i++;
      return { name, sel: sel as any };
    }
    // raw arg (quoted string or number)
    let depth = 1, j = this.i, inq: string | null = null;
    while (j < this.s.length && depth) {
      const ch = this.s[j];
      if (inq) { if (ch === "\\") j++; else if (ch === inq) inq = null; }
      else if (ch === '"' || ch === "'") inq = ch;
      else if (ch === "(") depth++; else if (ch === ")") depth--;
      j++;
    }
    let arg = this.s.slice(this.i, j - 1).trim();
    if (/^(["']).*\1$/.test(arg)) arg = arg.slice(1, -1);
    this.i = j;
    return { name, arg };
  }
}

/* ---------------------------------------------------------------- matching */
function tagMatches(n: Node, tag: string): boolean {
  if (/^[A-Z]/.test(tag)) {
    const kinds = profileFor(n.tree.language).kinds[tag];
    return !!kinds && kinds.includes(n.type);
  }
  return n.type === tag;
}
function cmp(actual: string | undefined | null, a: Attr): boolean {
  if (!a.op) return actual != null;
  if (actual == null) return a.op === "!=";
  const v = a.value!;
  if (v instanceof RegExp) { v.lastIndex = 0; const r = v.test(actual); return a.op === "!=" ? !r : r; }
  switch (a.op) {
    case "=": return actual === v;
    case "!=": return actual !== v;
    case "*=": return actual.includes(v);
    case "^=": return actual.startsWith(v);
    case "$=": return actual.endsWith(v);
    case "~=": return new RegExp(v).test(actual);
  }
  return false;
}
function attrMatches(n: Node, a: Attr): boolean {
  switch (a.name) {
    case "text": return cmp(n.text, a);
    case "type": return cmp(n.type, a);
    case "field": return cmp(n.field, a);
    case "line": return cmp(String(n.line), a);
    case "named": return cmp(String(n.named), a);
    // language-neutral attributes resolved through the language profile
    case "callee": { const c = profileFor(n.tree.language).call(n); return c ? cmp(c.callee, a) : a.op === "!="; }
    case "path": { const v = profileFor(n.tree.language).pathOf(n); return v != null ? cmp(v, a) : a.op === "!="; }
    case "fname": { const f = profileFor(n.tree.language).func(n); return f?.name != null ? cmp(f.name, a) : a.op === "!="; }
    default: {
      // text of child in that field; for member-ish nodes this lets you write call_expression[function="eval"]
      const kids = n.childrenByField(a.name);
      if (!a.op) return kids.length > 0;
      return kids.some((k) => cmp(k.text, a));
    }
  }
}
function compoundMatches(n: Node, c: Compound): boolean {
  if (c.tag && !tagMatches(n, c.tag)) return false;
  for (const a of c.attrs) if (!attrMatches(n, a)) return false;
  for (const p of c.pseudos) if (!pseudoMatches(n, p)) return false;
  return true;
}
function pseudoMatches(n: Node, p: Pseudo): boolean {
  switch (p.name) {
    case "not": return !(p.sel as any as Selector).some((s) => complexMatches(n, s));
    case "is": return (p.sel as any as Selector).some((s) => complexMatches(n, s));
    case "has":
      return (p.sel as any as Selector).some((s) => {
        const first = s.parts[0];
        if (first.comb === ">") { const rest = { parts: [{ comb: null, c: first.c } as any, ...s.parts.slice(1)] }; return n.kids.some((k) => scopedMatches(k, rest, n, true)); }
        return [...n.descendants()].some((d) => scopedMatches(d, s, n, false));
      });
    case "contains": return n.text.includes(p.arg ?? "");
    case "first-child": return n.row.idx === 0 || (n.parent?.namedChildren[0] === n);
    case "last-child": { const k = n.parent?.namedChildren; return !!k && k[k.length - 1] === n; }
    case "nth-child": return !!n.parent && n.parent.namedChildren.indexOf(n) + 1 === Number(p.arg);
    case "named": return n.named;
    case "leaf": return n.kids.length === 0;
    default: throw new Error("Unknown pseudo :" + p.name);
  }
}
// match `n` against the *last* part of the complex selector, walking left. `scope` limits the leftmost anchor (for :has).
function scopedMatches(n: Node, s: Complex, scope: Node | null, _childOnly: boolean): boolean {
  return matchParts(n, s.parts, s.parts.length - 1, scope);
}
function matchParts(n: Node, parts: Complex["parts"], i: number, scope: Node | null): boolean {
  if (!compoundMatches(n, parts[i].c)) return false;
  if (i === 0) return true;
  const comb = parts[i].comb!;
  if (comb === ">") { const p = n.parent; return !!p && matchParts(p, parts, i - 1, scope); }
  if (comb === " ") { for (const a of n.ancestors()) { if (scope && a === scope) return false; if (matchParts(a, parts, i - 1, scope)) return true; } return false; }
  if (comb === "+") { const p = n.prev; return !!p && matchParts(p, parts, i - 1, scope); }
  if (comb === "~") { const sib = n.parent?.kids ?? []; for (let k = n.row.idx - 1; k >= 0; k--) if (matchParts(sib[k], parts, i - 1, scope)) return true; return false; }
  return false;
}
export function complexMatches(n: Node, s: Complex): boolean { return matchParts(n, s.parts, s.parts.length - 1, null); }
export function matches(n: Node, sel: string | Selector): boolean {
  const s = typeof sel === "string" ? parseSelector(sel) : sel;
  return s.some((c) => complexMatches(n, c));
}
