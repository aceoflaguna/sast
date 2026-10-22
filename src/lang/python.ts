import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named, collect } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": return n.text;
    case "attribute": { const o = pathOf(n.child("object")); const a = n.child("attribute"); return o && a ? `${o}.${a.text}` : null; }
    case "subscript": { const o = pathOf(n.child("value")); return o ? `${o}[]` : null; }
    case "call": { const f = pathOf(n.child("function")); return f ? `${f}()` : null; }
    case "await": case "parenthesized_expression": return pathOf(named(n)[0]);
  }
  return null;
}
const targetsOf = (l: Node): Node[] =>
  ["identifier", "attribute", "subscript"].includes(l.type) ? [l] : collect(l, ["identifier", "attribute", "subscript"]);

export const python: Profile = {
  name: "python",
  kinds: {
    Call: ["call"],
    Assign: ["assignment", "augmented_assignment"],
    Func: ["function_definition", "lambda"],
    Ident: ["identifier"],
    Str: ["string"],
    Member: ["attribute", "subscript"],
    Return: ["return_statement"],
    Class: ["class_definition"],
  },
  pathOf,
  memberObject: (n) => (n.type === "attribute" ? n.child("object") : n.type === "subscript" ? n.child("value") : null),
  call(n): CallInfo | null {
    if (n.type !== "call") return null;
    const f = n.child("function");
    if (!f) return null;
    const args = named(n.child("arguments")).map((a) => (a.type === "keyword_argument" ? a.child("value") ?? a : a.type === "list_splat" || a.type === "dictionary_splat" ? named(a)[0] ?? a : a));
    return { node: n, callee: pathOf(f) ?? f.text.split("\n")[0].slice(0, 60), receiver: f.type === "attribute" ? f.child("object") : null, args };
  },
  assign(n): AssignInfo | null {
    if (n.type === "assignment" || n.type === "augmented_assignment") {
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      return { node: n, targets: targetsOf(l), value: r, compound: n.type === "augmented_assignment" };
    }
    if (n.type === "for_statement") {
      const l = n.child("left"), r = n.child("right");
      if (l && r) return { node: n, targets: targetsOf(l), value: r, compound: false };
    }
    return null;
  },
  func(n): FuncInfo | null {
    if (n.type !== "function_definition" && n.type !== "lambda") return null;
    const body = n.child("body");
    if (!body) return null;
    const ps = n.child("parameters");
    const list: { key: string; node: Node }[] = [];
    for (const p of named(ps)) {
      let id: Node | null = p;
      if (p.type === "default_parameter" || p.type === "typed_default_parameter") id = p.child("name");
      else if (p.type === "typed_parameter" || p.type === "list_splat_pattern" || p.type === "dictionary_splat_pattern") id = named(p)[0];
      if (!id || id.type !== "identifier") continue;
      if (list.length === 0 && (id.text === "self" || id.text === "cls")) continue;
      list.push({ key: id.text, node: p });
    }
    return { node: n, name: n.child("name")?.text ?? null, params: list, body, exprBody: n.type === "lambda" };
  },
  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),
  exprChildren(n) { return n.type === "keyword_argument" ? [n.child("value")].filter(Boolean) as Node[] : named(n); },
  sources: [
    /^request\.(args|form|values|json|data|cookies|headers|files|GET|POST|COOKIES|META|body|query_params|path|url|view_args)\b/,
    /^request\.get_(json|data)\(\)/,
    /^input\(\)$/,
    /^sys\.argv\b/,
    /^(flask\.)?request\./,
  ],
  numeric: /^(int|float|bool|len|abs|round|uuid\.UUID)$/,
  stringValue(n) {
    if (n.type !== "string") return null;
    if (n.kids.some((k) => k.type === "interpolation")) return null;
    return n.kids.filter((k) => k.type === "string_content").map((k) => k.text).join("");
  },
};
