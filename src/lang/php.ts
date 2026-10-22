import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named, collect } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "variable_name": return "$" + n.text.replace(/^\$/, "");
    case "name": case "qualified_name": return n.text;
    case "member_access_expression": case "nullsafe_member_access_expression": { const o = pathOf(n.child("object")); const m = n.child("name"); return o && m ? `${o}.${m.text}` : null; }
    case "subscript_expression": { const o = pathOf(named(n)[0]); return o ? `${o}[]` : null; }
    case "function_call_expression": { const f = pathOf(n.child("function")); return f ? `${f}()` : null; }
    case "member_call_expression": case "nullsafe_member_call_expression": { const o = pathOf(n.child("object")); const m = n.child("name"); return o && m ? `${o}.${m.text}()` : null; }
    case "scoped_call_expression": { const s = n.child("scope"), m = n.child("name"); return s && m ? `${s.text}.${m.text}()` : null; }
    case "parenthesized_expression": return pathOf(named(n)[0]);
  }
  return null;
}
const argExprs = (args: Node | null | undefined) => named(args).map((a) => (a.type === "argument" ? named(a).slice(-1)[0] ?? a : a));
const INCLUDES = ["include_expression", "include_once_expression", "require_expression", "require_once_expression"];

export const php: Profile = {
  name: "php",
  kinds: {
    Call: ["function_call_expression", "member_call_expression", "scoped_call_expression", "object_creation_expression", "echo_statement", "print_intrinsic", "shell_command_expression", ...INCLUDES],
    Assign: ["assignment_expression", "augmented_assignment_expression"],
    Func: ["function_definition", "method_declaration", "anonymous_function", "arrow_function"],
    Ident: ["variable_name", "name"],
    Str: ["string", "encapsed_string"],
    Member: ["member_access_expression", "subscript_expression"],
    Return: ["return_statement"],
    Class: ["class_declaration"],
  },
  pathOf,
  memberObject: (n) => n.type === "member_access_expression" ? n.child("object") : n.type === "subscript_expression" ? named(n)[0] ?? null : null,
  call(n): CallInfo | null {
    switch (n.type) {
      case "function_call_expression": {
        const f = n.child("function");
        return f ? { node: n, callee: pathOf(f) ?? f.text.slice(0, 60), receiver: null, args: argExprs(n.child("arguments")) } : null;
      }
      case "member_call_expression": case "nullsafe_member_call_expression": {
        const o = n.child("object"), m = n.child("name");
        return o && m ? { node: n, callee: `${pathOf(o) ?? "?"}.${m.text}`, receiver: o, args: argExprs(n.child("arguments")) } : null;
      }
      case "scoped_call_expression": {
        const s = n.child("scope"), m = n.child("name");
        return s && m ? { node: n, callee: `${s.text}.${m.text}`, receiver: null, args: argExprs(n.child("arguments")) } : null;
      }
      case "object_creation_expression": {
        const nm = named(n).find((k) => k.type === "name" || k.type === "qualified_name");
        return { node: n, callee: "new " + (nm?.text ?? "?"), receiver: null, args: argExprs(n.kids.find((k) => k.type === "arguments")) };
      }
      case "echo_statement": return { node: n, callee: "echo", receiver: null, args: named(n) };
      case "print_intrinsic": return { node: n, callee: "print", receiver: null, args: named(n) };
      case "shell_command_expression": return { node: n, callee: "shell_exec", receiver: null, args: [n] };
    }
    if (INCLUDES.includes(n.type)) return { node: n, callee: "include", receiver: null, args: named(n) };
    return null;
  },
  assign(n): AssignInfo | null {
    if (n.type !== "assignment_expression" && n.type !== "augmented_assignment_expression") return null;
    const l = n.child("left"), r = n.child("right");
    if (!l || !r) return null;
    const targets = ["variable_name", "member_access_expression", "subscript_expression"].includes(l.type) ? [l] : collect(l, ["variable_name"]);
    return { node: n, targets, value: r, compound: n.type === "augmented_assignment_expression" };
  },
  func(n): FuncInfo | null {
    if (!["function_definition", "method_declaration", "anonymous_function", "arrow_function"].includes(n.type)) return null;
    const body = n.child("body");
    if (!body) return null;
    const list: { key: string; node: Node }[] = [];
    for (const p of named(n.child("parameters"))) {
      const v = p.child("name");
      list.push({ key: pathOf(v) ?? `#${list.length}`, node: p });
    }
    return { node: n, name: n.child("name")?.text ?? null, params: list, body, exprBody: n.type === "arrow_function" };
  },
  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),
  safeCast(n) { return n.type === "cast_expression" && /^(int|integer|float|double|bool|boolean)$/i.test(n.child("type")?.text ?? ""); },
  sources: [
    /^\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b/,
    /^\$request\.(input|get|query|post|all|json|cookie|header|route|only)\(\)/,
    /^\$this\.request\./,
    /^(file_get_contents)\(\)$/,
  ],
  numeric: /^(intval|floatval|doubleval|boolval|abs|count|strlen|round|floor|ceil|is_numeric|ctype_digit)$/,
  stringValue(n) { return n.type === "string" ? n.text.slice(1, -1) : n.type === "encapsed_string" && !n.kids.some((k) => k.type !== "string_content" && k.named) ? n.text.slice(1, -1) : null; },
};
