import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "this_expression": case "base_expression": case "predefined_type": return n.text;
    case "generic_name": return pathOf(named(n)[0]);
    case "qualified_name": return n.text;
    case "member_access_expression": { const o = pathOf(n.child("expression")); const m = n.child("name"); return o && m ? `${o}.${m.text.replace(/<.*>$/s, "")}` : null; }
    case "invocation_expression": { const f = pathOf(n.child("function")); return f ? `${f}()` : null; }
    case "element_access_expression": { const o = pathOf(n.child("expression")); return o ? `${o}[]` : null; }
    case "parenthesized_expression": case "await_expression": case "postfix_unary_expression": return pathOf(named(n)[0]);
    case "cast_expression": return pathOf(n.child("value"));
  }
  return null;
}
const argExprs = (list: Node | null | undefined) => named(list).map((a) => (a.type === "argument" ? named(a).slice(-1)[0] ?? a : a));

export const csharp: Profile = {
  name: "csharp",
  kinds: {
    Call: ["invocation_expression", "object_creation_expression"],
    Assign: ["assignment_expression", "variable_declarator"],
    Func: ["method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"],
    Ident: ["identifier"],
    Str: ["string_literal", "verbatim_string_literal", "raw_string_literal", "interpolated_string_expression"],
    Member: ["member_access_expression", "element_access_expression"],
    Return: ["return_statement"],
    Class: ["class_declaration", "record_declaration", "interface_declaration"],
  },
  pathOf,
  memberObject: (n) => (n.type === "member_access_expression" || n.type === "element_access_expression" ? n.child("expression") : null),
  call(n): CallInfo | null {
    if (n.type === "invocation_expression") {
      const f = n.child("function");
      if (!f) return null;
      return { node: n, callee: pathOf(f) ?? f.text.split("\n")[0].slice(0, 60), receiver: f.type === "member_access_expression" ? f.child("expression") : null, args: argExprs(n.child("arguments")) };
    }
    if (n.type === "object_creation_expression") {
      return { node: n, callee: "new " + (n.child("type")?.text.replace(/<.*>$/, "") ?? "?"), receiver: null, args: argExprs(n.child("arguments")) };
    }
    return null;
  },
  assign(n): AssignInfo | null {
    if (n.type === "variable_declarator") {
      const t = named(n)[0];
      const eq = n.kids.find((k) => k.type === "equals_value_clause");
      const v = eq ? named(eq)[0] : null;
      return t && v ? { node: n, targets: [t], value: v, compound: false } : null;
    }
    if (n.type === "assignment_expression") {
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      const op = n.kids.find((k) => k.type === "assignment_operator")?.text ?? "=";
      return { node: n, targets: [l], value: r, compound: op !== "=" };
    }
    if (n.type === "foreach_statement") {
      const l = n.child("left"), r = n.child("right");
      return l && r ? { node: n, targets: [l], value: r, compound: false } : null;
    }
    return null;
  },
  func(n): FuncInfo | null {
    if (!["method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"].includes(n.type)) return null;
    let body = n.child("body");
    if (!body) return null;
    let exprBody = false;
    if (body.type === "arrow_expression_clause") { body = named(body)[0] ?? body; exprBody = true; }
    else if (n.type === "lambda_expression" && body.type !== "block") exprBody = true;
    const ps = n.child("parameters");
    const list: { key: string; node: Node }[] = [];
    if (ps?.type === "identifier") list.push({ key: ps.text, node: ps });
    else for (const p of named(ps)) list.push({ key: p.child("name")?.text ?? named(p).slice(-1)[0]?.text ?? `#${list.length}`, node: p });
    return { node: n, name: n.child("name")?.text ?? null, params: list, body, exprBody };
  },
  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),
  taintedParam(p) {
    if (p.type !== "parameter") return false;
    if (/\[\s*(From(Query|Body|Form|Route|Header|Services)|ModelBinder)\b/.test(p.text)) return !/FromServices/.test(p.text);
    // public action methods of MVC controllers / Razor pages are model-bound from the request
    const method = p.parent?.parent;
    if (method?.type !== "method_declaration" || !method.kids.some((k) => k.type === "modifier" && k.text === "public")) return false;
    const cls = [...method.ancestors()].find((a) => a.type === "class_declaration");
    return /Controller|PageModel/.test(cls?.child("bases")?.text ?? "");
  },
  sources: [
    /^(this\.)?(Request|HttpContext\.Request|context\.Request|req|request)\.(Query|Form|Headers|Cookies|QueryString|Params|Path|PathBase|Body|RouteValues|Url|RawUrl|Files|ServerVariables|UserAgent)\b/,
    /^(this\.)?(RouteData\.Values|ViewData|TempData)\b/,
    /^Console\.(ReadLine|In\.ReadLine)\(\)$/,
    /^Environment\.GetCommandLineArgs\(\)$/,
  ],
  numeric: /^((int|long|short|byte|uint|ulong|double|float|decimal|bool|Int16|Int32|Int64|Double|Boolean|Decimal|Guid|DateTime)\.(Parse|TryParse)|Convert\.To(Int16|Int32|Int64|Double|Boolean|Decimal|Single|Byte)|Guid\.Parse)$/,
  stringValue(n) {
    if (n.type === "string_literal") return n.text.slice(1, -1);
    if (n.type === "verbatim_string_literal") return n.text.slice(2, -1);
    return null;
  },
};
