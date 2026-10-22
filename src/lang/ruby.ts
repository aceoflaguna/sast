import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named, pairAssign } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "constant": case "instance_variable": case "global_variable": case "class_variable": case "self": return n.text;
    case "scope_resolution": { const s = pathOf(n.child("scope")); const m = n.child("name"); return m ? (s ? `${s}.${m.text}` : m.text) : null; }
    case "call": {
      const r = n.child("receiver"), m = n.child("method");
      if (!m) return null;
      if (!r) return `${m.text}()`;
      const rp = pathOf(r);
      return rp ? `${rp}.${m.text}()` : null;
    }
    case "element_reference": { const o = pathOf(n.child("object")); return o ? `${o}[]` : null; }
    case "parenthesized_statements": return pathOf(named(n)[0]);
  }
  return null;
}
const unwrap = (n: Node) => ((n.type === "right_assignment_list") && named(n).length === 1 ? named(n)[0] : n);
const targetsOf = (l: Node): Node[] => (l.type === "left_assignment_list" ? named(l) : [l]);

export const ruby: Profile = {
  name: "ruby",
  kinds: {
    Call: ["call", "subshell"],
    Assign: ["assignment", "operator_assignment"],
    Func: ["method", "singleton_method", "lambda"],
    Ident: ["identifier", "instance_variable", "global_variable", "constant"],
    Str: ["string", "bare_string", "heredoc_body"],
    Member: ["element_reference", "scope_resolution"],
    Return: ["return"],
    Class: ["class", "module"],
  },
  pathOf,
  memberObject: (n) => (n.type === "element_reference" ? n.child("object") : n.type === "scope_resolution" ? n.child("scope") : null),
  call(n): CallInfo | null {
    if (n.type === "subshell") return { node: n, callee: "`", receiver: null, args: [n] };
    if (n.type !== "call") return null;
    const m = n.child("method");
    if (!m) return null;
    const r = n.child("receiver");
    const callee = r ? `${pathOf(r) ?? "?"}.${m.text}` : m.text;
    // `where(name: x)` hash-style args are kept apart: the keyword form is the safe, parameterised one for many Rails APIs
    const all = named(n.child("arguments"));
    const kwargs = all.filter((a) => a.type === "pair").map((a) => ({ name: (a.child("key")?.text ?? "").replace(/^:|:$|["']/g, ""), value: a.child("value") ?? a }));
    // `render html: x` / `render inline: x` / `render file: x` is exposed as the pseudo-callee `render.html` (value = first arg),
    // so queries can tell the dangerous renderers from the safe ones (`render plain:` / `render json:`)
    if (!r && callee === "render") {
      const kw = kwargs.find((k) => /^(html|inline|body|file|template|plain|text|json|xml|js|partial|action|layout)$/.test(k.name));
      if (kw) return { node: n, callee: `render.${kw.name}`, receiver: null, args: [kw.value], kwargs: kwargs.filter((k) => k !== kw) };
    }
    return { node: n, callee, receiver: r, args: all.filter((a) => a.type !== "pair"), kwargs };
  },
  assign(n): AssignInfo | AssignInfo[] | null {
    if (n.type === "assignment" || n.type === "operator_assignment") {
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      if (l.type === "left_assignment_list") return pairAssign(n, named(l), r.type === "right_assignment_list" ? named(r) : [r], r, n.type === "operator_assignment");
      return { node: n, targets: targetsOf(l), value: unwrap(r), compound: n.type === "operator_assignment" };
    }
    // s << tainted   (string / array append)
    if (n.type === "binary" && n.child("operator")?.text === "<<") {
      const l = n.child("left"), r = n.child("right");
      if (l && r && ["identifier", "instance_variable"].includes(l.type)) return { node: n, targets: [l], value: r, compound: true };
    }
    return null;
  },
  func(n): FuncInfo | null {
    if (n.type !== "method" && n.type !== "singleton_method") return null;
    const body = n.child("body");
    if (!body) return { node: n, name: n.child("name")?.text ?? null, params: [], body: n, exprBody: false, implicitReturn: null };
    const list: { key: string; node: Node }[] = [];
    for (const p of named(n.child("parameters"))) {
      const id = p.type === "identifier" ? p : p.child("name") ?? named(p)[0];
      list.push({ key: id?.text ?? `#${list.length}`, node: p });
    }
    const last = named(body).filter((k) => k.type !== "comment").at(-1);
    return { node: n, name: n.child("name")?.text ?? null, params: list, body, exprBody: false, implicitReturn: last && last.type !== "return" ? last : null };
  },
  ret: (n) => (n.type === "return" ? named(n)[0] ?? null : null),
  exprChildren(n) { return n.type === "pair" ? ([n.child("value")].filter(Boolean) as Node[]) : named(n); },
  sources: [
    /^params\b/,
    /^request\.(params|parameters|query_parameters|request_parameters|headers|cookies|body|url|fullpath|referer|referrer|env|GET|POST|raw_post|query_string|path|original_url|user_agent)\b/,
    /^(cookies|cgi)\b/,
    /^gets\(\)$/,
    /^(ARGV|ENV)\b/,
    /^\$stdin\.(gets|read)\(\)$/,
  ],
  numeric: /(^|\.)(to_i|to_f|to_r|to_c|to_sym|size|length|count)$|^(Integer|Float|Rational|Complex)$|^Integer\.sqrt$/,
  stringValue(n) {
    if (n.type !== "string") return null;
    if (n.kids.some((k) => k.type === "interpolation")) return null;
    return n.kids.filter((k) => k.type === "string_content").map((k) => k.text).join("");
  },
};
