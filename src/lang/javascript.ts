import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named, collect } from "./common";

const FUNC = ["function_declaration", "function_expression", "function", "arrow_function", "method_definition", "generator_function_declaration", "generator_function"];

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "this": case "super": case "shorthand_property_identifier": case "shorthand_property_identifier_pattern": return n.text;
    case "member_expression": { const o = pathOf(n.child("object")); const p = n.child("property"); return o && p ? `${o}.${p.text}` : null; }
    case "subscript_expression": { const o = pathOf(n.child("object")); return o ? `${o}[]` : null; }
    case "call_expression": { const f = pathOf(n.child("function")); return f ? `${f}()` : null; }
    case "await_expression": case "parenthesized_expression": case "non_null_expression": case "as_expression": case "satisfies_expression":
      return pathOf(named(n)[0]);
  }
  return null;
}

function nameOfFunc(n: Node): string | null {
  const nm = n.child("name");
  if (nm) return nm.text;
  const p = n.parent;
  if (!p) return null;
  if (p.type === "variable_declarator") return p.child("name")?.text ?? null;
  if (p.type === "pair") return p.child("key")?.text ?? null;
  if (p.type === "assignment_expression") { const l = p.child("left"); return l ? (l.type === "member_expression" ? l.child("property")!.text : l.text) : null; }
  return null;
}

function params(n: Node) {
  const ps = n.child("parameters") ?? n.child("parameter");
  const list: { key: string; node: Node }[] = [];
  if (!ps) return list;
  const els = ps.type === "identifier" ? [ps] : named(ps);
  for (const p of els) {
    let id: Node | null = p;
    if (p.type === "assignment_pattern") id = p.child("left");
    else if (p.type === "rest_pattern") id = named(p)[0];
    else if (p.type === "required_parameter" || p.type === "optional_parameter") id = p.child("pattern");
    if (id && id.type === "identifier") list.push({ key: id.text, node: p });
    else list.push({ key: `#${list.length}`, node: p }); // destructured param: keep positional slot
  }
  return list;
}

export const javascript: Profile = {
  name: "javascript",
  kinds: {
    Call: ["call_expression", "new_expression"],
    Assign: ["assignment_expression", "augmented_assignment_expression", "variable_declarator"],
    Func: FUNC,
    Ident: ["identifier", "shorthand_property_identifier"],
    Str: ["string", "template_string"],
    Member: ["member_expression", "subscript_expression"],
    Return: ["return_statement"],
    Class: ["class_declaration", "class"],
  },
  pathOf,
  memberObject: (n) => (n.type === "member_expression" || n.type === "subscript_expression" ? n.child("object") : null),
  call(n): CallInfo | null {
    if (n.type === "call_expression") {
      const f = n.child("function");
      if (!f) return null;
      const callee = pathOf(f) ?? f.text.split("\n")[0].slice(0, 60);
      const receiver = f.type === "member_expression" ? f.child("object") : null;
      return { node: n, callee, receiver, args: named(n.child("arguments")).map((a) => (a.type === "spread_element" ? named(a)[0] ?? a : a)) };
    }
    if (n.type === "new_expression") {
      const c = n.child("constructor");
      return { node: n, callee: "new " + (pathOf(c) ?? c?.text ?? "?"), receiver: null, args: named(n.child("arguments")) };
    }
    return null;
  },
  assign(n): AssignInfo | null {
    if (n.type === "variable_declarator") {
      const v = n.child("value"), t = n.child("name");
      if (!v || !t) return null;
      const targets = t.type === "identifier" ? [t] : collect(t, ["shorthand_property_identifier_pattern", "identifier"]);
      return { node: n, targets, value: v, compound: false };
    }
    if (n.type === "assignment_expression" || n.type === "augmented_assignment_expression") {
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      const targets = l.type === "identifier" || l.type === "member_expression" || l.type === "subscript_expression"
        ? [l] : collect(l, ["identifier", "shorthand_property_identifier_pattern"]);
      const compound = n.type === "augmented_assignment_expression" || !/^\s*=\s*$/.test(n.tree.source.slice(l.row.eb, r.row.sb));
      return { node: n, targets, value: r, compound };
    }
    if (n.type === "for_in_statement") {
      const l = n.child("left"), r = n.child("right");
      if (l && r) return { node: n, targets: collect(l, ["identifier"]), value: r, compound: false };
    }
    return null;
  },
  func(n): FuncInfo | null {
    if (!FUNC.includes(n.type)) return null;
    const body = n.child("body");
    if (!body) return null;
    return { node: n, name: nameOfFunc(n), params: params(n), body, exprBody: body.type !== "statement_block" };
  },
  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),
  // property keys in object literals are not variable reads
  exprChildren(n) { return n.type === "pair" ? [n.child("value")].filter(Boolean) as Node[] : named(n); },
  sources: [
    /^(req|request)\.(query|body|params|headers|cookies|url|originalUrl|files|hostname|path)\b/,
    /^(req|request)\.(get|header|param)\(\)/,
    /^ctx\.(query|params|request\.(query|body)|headers|cookies)\b/,
    /^(window\.|document\.)?location\.(search|hash|href|pathname)\b/,
    /^document\.(cookie|URL|referrer)\b/,
    /^(process\.argv)\b/,
    /^(event|e)\.data\b/,
  ],
  numeric: /^(parseInt|parseFloat|Number|Boolean|Math\.\w+|Number\.parse(Int|Float)|Number\.isInteger|BigInt)$/,
  stringValue(n) {
    if (n.type === "string") return n.text.slice(1, -1);
    if (n.type === "template_string" && !n.kids.some((k) => k.type === "template_substitution")) return n.text.slice(1, -1);
    return null;
  },
};
