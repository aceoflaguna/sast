import type { Node } from "../node";

export interface CallInfo {
  node: Node;
  /** normalized dotted callee, e.g. "db.query", "cursor.execute", "$pdo.query", "new File", "echo" */
  callee: string;
  receiver: Node | null;
  /** positional arguments */
  args: Node[];
  /** keyword/hash arguments kept apart from positional ones: Ruby `where(name: x)` is the safe, parameterised form, so sinks
   *  only look at these when they opt in with `SinkSpec.kwargs` (calls still propagate taint through them). */
  kwargs?: { name: string; value: Node }[];
}
export interface AssignInfo { node: Node; targets: Node[]; value: Node; compound: boolean }
export interface FuncInfo {
  node: Node; name: string | null; params: { key: string; node: Node }[]; body: Node;
  /** body is a single expression whose value is returned (arrow functions, lambdas, endless defs) */
  exprBody: boolean;
  /** statement whose value is implicitly returned (Ruby: last expression of a method) */
  implicitReturn?: Node | null;
}

/** A language profile maps one grammar's node names onto a small common model so queries can stay language-agnostic. */
export interface Profile {
  name: string;
  /** abstract kinds usable in selectors:  Call, Assign, Func, Ident, Str, Member, Return, Class */
  kinds: Record<string, string[]>;
  call(n: Node): CallInfo | null;
  /** may return several records for multi-assignment (Go `a, b := x, y`, Ruby `a, b = x, y`) */
  assign(n: Node): AssignInfo | AssignInfo[] | null;
  func(n: Node): FuncInfo | null;
  ret(n: Node): Node | null;
  /** dotted access path for identifiers / member chains / calls ("req.query.id", "$_GET[]", "request.args.get()") */
  pathOf(n: Node): string | null;
  /** the object part of a member/subscript access */
  memberObject(n: Node): Node | null;
  /** nodes whose value is taken into account when evaluating an expression (default: named children) */
  exprChildren?(n: Node): Node[];
  /** true for expression nodes that neutralise taint regardless of the vulnerability class (e.g. PHP (int) cast) */
  safeCast?(n: Node): boolean;
  /** true if a parameter is user-controlled by declaration (e.g. Spring @RequestParam) */
  taintedParam?(n: Node): boolean;
  /** universal user-input sources, matched against pathOf() */
  sources: RegExp[];
  /** callees that convert to a number/bool — safe for injection style classes */
  numeric: RegExp;
  /** literal string value of a string node (without quotes), or null */
  stringValue(n: Node): string | null;
}
