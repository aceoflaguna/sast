/**
 * Safe parser for jQuery-style chains typed in the UI console, e.g.
 *     $("Call[function*=query]").parent().find("Ident")
 *     Call:has(Ident[text=q])
 * Only whitelisted traversal methods are callable; arguments are string / integer literals. No eval.
 */
import { Q, makeDollar } from "./q";
import type { Tree } from "./node";

const METHODS: Record<string, (q: Q, a: any[]) => Q> = {
  find: (q, [s]) => q.find(s), children: (q, [s]) => q.children(s), named: (q) => q.named(), child: (q, [f]) => q.child(f),
  parent: (q, [s]) => q.parent(s), parents: (q, [s]) => q.parents(s), closest: (q, [s]) => q.closest(s),
  next: (q, [s]) => q.next(s), prev: (q, [s]) => q.prev(s), siblings: (q, [s]) => q.siblings(s),
  filter: (q, [s]) => q.filter(String(s)), not: (q, [s]) => q.not(String(s)), has: (q, [s]) => q.has(String(s)),
  first: (q) => q.first(), last: (q) => q.last(), eq: (q, [i]) => q.eq(Number(i)), slice: (q, [a, b]) => q.slice(a, b),
};

function readString(src: string, i: number): [string, number] {
  const quote = src[i]; let out = ""; i++;
  while (i < src.length && src[i] !== quote) { if (src[i] === "\\") i++; out += src[i++]; }
  if (src[i] !== quote) throw new Error("Unterminated string");
  return [out, i + 1];
}

export function runChain(trees: Tree[], input: string): Q {
  const src = input.trim();
  const $ = makeDollar(trees);
  let i = 0;
  let q: Q;
  if (src.startsWith("$(")) {
    i = 2; while (src[i] === " ") i++;
    const [sel, j] = readString(src, i); i = j;
    while (src[i] === " ") i++;
    if (src[i] !== ")") throw new Error("Expected ) after selector");
    i++; q = $(sel);
  } else {
    // bare selector, optionally followed by a chain starting at the first ").": keep simple – whole input is the selector
    return $(src);
  }
  while (i < src.length) {
    while (/\s/.test(src[i] ?? "")) i++;
    if (i >= src.length) break;
    if (src[i] !== ".") throw new Error(`Expected . at position ${i}`);
    i++;
    const name = /^[a-z]+/i.exec(src.slice(i))?.[0];
    if (!name || !Object.hasOwn(METHODS, name)) throw new Error(`Unknown method "${name ?? ""}". Allowed: ${Object.keys(METHODS).join(", ")}`);
    i += name.length;
    if (src[i] !== "(") throw new Error("Expected (");
    i++;
    const args: any[] = [];
    while (true) {
      while (/\s/.test(src[i] ?? "")) i++;
      if (src[i] === ")") { i++; break; }
      if (src[i] === '"' || src[i] === "'") { const [s, j] = readString(src, i); args.push(s); i = j; }
      else { const m = /^-?\d+/.exec(src.slice(i)); if (!m) throw new Error(`Bad argument at ${i}`); args.push(Number(m[0])); i += m[0].length; }
      while (/\s/.test(src[i] ?? "")) i++;
      if (src[i] === ",") i++;
    }
    q = METHODS[name](q, args);
  }
  return q;
}
