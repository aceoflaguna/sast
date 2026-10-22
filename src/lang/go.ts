import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "field_identifier": case "package_identifier": case "type_identifier": return n.text;
    case "selector_expression": { const o = pathOf(n.child("operand")); const f = n.child("field"); return o && f ? `${o}.${f.text}` : null; }
    case "call_expression": { const f = pathOf(n.child("function")); return f ? `${f}()` : null; }
    case "index_expression": case "slice_expression": { const o = pathOf(n.child("operand")); return o ? `${o}[]` : null; }
    case "parenthesized_expression": return pathOf(named(n)[0]);
    case "unary_expression": return pathOf(n.child("operand"));
    case "type_assertion_expression": return pathOf(n.child("operand"));
  }
  return null;
}
/** expression_list with exactly one element -> that element */
const unwrap = (n: Node) => (n.type === "expression_list" && named(n).length === 1 ? named(n)[0] : n);
const targetsOf = (l: Node) => (l.type === "expression_list" ? named(l) : [l]).filter((t) => t.text !== "_");

export const go: Profile = {
  name: "go",
  kinds: {
    Call: ["call_expression"],
    Assign: ["short_var_declaration", "assignment_statement", "var_spec", "const_spec"],
    Func: ["function_declaration", "method_declaration", "func_literal"],
    Ident: ["identifier", "field_identifier"],
    Str: ["interpreted_string_literal", "raw_string_literal"],
    Member: ["selector_expression", "index_expression"],
    Return: ["return_statement"],
    Class: ["type_spec"],
  },
  pathOf,
  memberObject: (n) => (n.type === "selector_expression" || n.type === "index_expression" ? n.child("operand") : null),
  call(n): CallInfo | null {
    if (n.type !== "call_expression") return null;
    const f = n.child("function");
    if (!f) return null;
    return { node: n, callee: pathOf(f) ?? f.text.split("\n")[0].slice(0, 60), receiver: f.type === "selector_expression" ? f.child("operand") : null, args: named(n.child("arguments")) };
  },
  assign(n): AssignInfo | null {
    switch (n.type) {
      case "short_var_declaration": case "assignment_statement": {
        const l = n.child("left"), r = n.child("right");
        if (!l || !r) return null;
        const compound = n.type === "assignment_statement" && !/^\s*=\s*$/.test(n.tree.source.slice(l.row.eb, r.row.sb));
        return { node: n, targets: targetsOf(l), value: unwrap(r), compound };
      }
      case "var_spec": case "const_spec": {
        const v = n.child("value");
        return v ? { node: n, targets: n.childrenByField("name").filter((t) => t.text !== "_"), value: unwrap(v), compound: false } : null;
      }
      case "range_clause": {
        const l = n.child("left"), r = n.child("right");
        return l && r ? { node: n, targets: targetsOf(l), value: r, compound: false } : null;
      }
    }
    return null;
  },
  func(n): FuncInfo | null {
    if (!["function_declaration", "method_declaration", "func_literal"].includes(n.type)) return null;
    const body = n.child("body");
    if (!body) return null;
    const list: { key: string; node: Node }[] = [];
    for (const pd of named(n.child("parameters"))) {
      const names = pd.childrenByField("name");
      if (!names.length) list.push({ key: `#${list.length}`, node: pd });
      else for (const nm of names) list.push({ key: nm.text, node: pd });
    }
    return { node: n, name: n.child("name")?.text ?? null, params: list, body, exprBody: false };
  },
  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),
  sources: [
    /^(r|req|request)\.(URL|FormValue|PostFormValue|Form|PostForm|Header|Cookie|Cookies|Body|Host|RequestURI|MultipartForm|PathValue|UserAgent|Referer)\b/,
    /^(c|ctx|e)\.(Query|Param|Params|PostForm|DefaultQuery|DefaultPostForm|GetHeader|FormValue|QueryParam|QueryParams|FormParams|Cookie|BodyParser|Bind\w*|ShouldBind\w*|GetQuery|GetPostForm|Request|Get|Body|Path|Hostname|IP|Params)\b/,
    /^(mux\.Vars|chi\.URLParam|httprouter\.ParamsFromContext)\(\)/,
    /^os\.Args\b/,
    /^(bufio\.NewReader\(\)\.ReadString|bufio\.NewScanner\(\)\.Text)\(\)/,
    /^flag\.(Arg|Args)\(\)/,
  ],
  numeric: /^(strconv\.(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)|uuid\.(Parse|MustParse)|len|int|int64|float64|bool)$/,
  stringValue(n) { return n.type === "interpreted_string_literal" || n.type === "raw_string_literal" ? n.text.slice(1, -1) : null; },
};
