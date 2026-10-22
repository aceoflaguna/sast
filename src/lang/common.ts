import type { Node } from "../node";
export const skipTypes = new Set(["comment", "line_comment", "block_comment", "php_tag", "text", "text_interpolation"]);
export const named = (n: Node | null | undefined) => (n ? n.namedChildren.filter((k) => !skipTypes.has(k.type)) : []);
export const lastSeg = (callee: string) => callee.replace(/\(\)$/, "").split(/[.:]+/).pop() ?? callee;
export function collect(n: Node | null, types: string[], out: Node[] = []): Node[] {
  if (!n) return out;
  if (types.includes(n.type)) out.push(n);
  else for (const k of n.namedChildren) collect(k, types, out);
  return out;
}

/** Pair `a, b = x, y` element-wise; otherwise every target receives the whole right side. */
export function pairAssign(node: Node, lefts: Node[], rights: Node[], rightWhole: Node, compound: boolean): import("./types").AssignInfo[] {
  const lefts2 = lefts.filter((l) => l.text !== "_");
  if (lefts.length === rights.length) return lefts.map((l, i) => ({ node, targets: [l], value: rights[i], compound })).filter((a) => a.targets[0].text !== "_");
  const value = rights.length === 1 ? rights[0] : rightWhole;
  return lefts2.length ? [{ node, targets: lefts2, value, compound }] : [];
}
