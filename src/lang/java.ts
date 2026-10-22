import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "this": case "type_identifier": case "scoped_identifier": return n.text;
    case "field_access": { const o = pathOf(n.child("object")); const f = n.child("field"); return o && f ? `${o}.${f.text}` : null; }
    case "method_invocation": { const o = n.child("object"); const nm = n.child("name")!.text; const op = o ? pathOf(o) : null; return o ? (op ? `${op}.${nm}()` : null) : `${nm}()`; }
    case "array_access": { const o = pathOf(n.child("array")); return o ? `${o}[]` : null; }
    case "parenthesized_expression": return pathOf(named(n)[0]);
    case "cast_expression": return pathOf(n.child("value"));
  }
  return null;
}

export const java: Profile = {
  name: "java",
  kinds: {
    Call: ["method_invocation", "object_creation_expression"],
    Assign: ["assignment_expression", "variable_declarator"],
    Func: ["method_declaration", "constructor_declaration", "lambda_expression"],
    Ident: ["identifier"],
    Str: ["string_literal"],
    Member: ["field_access", "array_access"],
    Return: ["return_statement"],
    Class: ["class_declaration", "interface_declaration"],
  },
  pathOf,
  memberObject: (n) => (n.type === "field_access" ? n.child("object") : n.type === "array_access" ? n.child("array") : null),
  call(n): CallInfo | null {
    if (n.type === "method_invocation") {
      const o = n.child("object"), nm = n.child("name");
      if (!nm) return null;
      return { node: n, callee: o ? `${pathOf(o) ?? "?"}.${nm.text}` : nm.text, receiver: o, args: named(n.child("arguments")) };
    }
    if (n.type === "object_creation_expression") {
      return { node: n, callee: "new " + (n.child("type")?.text ?? "?"), receiver: null, args: named(n.child("arguments")) };
    }
    return null;
  },
  assign(n): AssignInfo | null {
    if (n.type === "variable_declarator") {
      const t = n.child("name"), v = n.child("value");
      return t && v ? { node: n, targets: [t], value: v, compound: false } : null;
    }
    if (n.type === "assignment_expression") {
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      return { node: n, targets: [l], value: r, compound: !/^\s*=\s*$/.test(n.tree.source.slice(l.row.eb, r.row.sb)) };
    }
    if (n.type === "enhanced_for_statement") {
      const t = n.child("name"), v = n.child("value");
      return t && v ? { node: n, targets: [t], value: v, compound: false } : null;
    }
    return null;
  },
  func(n): FuncInfo | null {
    if (!["method_declaration", "constructor_declaration", "lambda_expression"].includes(n.type)) return null;
    const body = n.child("body");
    if (!body) return null;
    const list = named(n.child("parameters")).filter((p) => p.type === "formal_parameter" || p.type === "spread_parameter")
      .map((p) => ({ key: p.child("name")?.text ?? named(p).slice(-1)[0]?.text ?? "?", node: p }));
    return { node: n, name: n.child("name")?.text ?? null, params: list, body, exprBody: n.type === "lambda_expression" && body.type !== "block" };
  },
  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),
  taintedParam: (p) => /@(RequestParam|PathVariable|RequestBody|RequestHeader|QueryParam|PathParam|FormParam|CookieValue|ModelAttribute)\b/.test(p.text),
  sources: [
    /\.(getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getInputStream|getReader|getPathInfo|getRequestURI|getRequestURL)\(\)$/,
    /^System\.getenv\(\)$|^System\.in$/,
    /^(scanner|sc|in)\.next(Line)?\(\)$/,
  ],
  numeric: /^(Integer\.(parseInt|valueOf)|Long\.(parseLong|valueOf)|Double\.parseDouble|Float\.parseFloat|Boolean\.parseBoolean|UUID\.fromString|Short\.parseShort)$/,
  stringValue(n) { return n.type === "string_literal" ? n.text.replace(/^"|"$/g, "") : null; },
};
