import type { NodeRow } from "./parser";

/** One parsed file, rebuilt from rows (either fresh from the parser or loaded from Postgres). */
export class Tree {
  nodes: Node[] = [];
  constructor(public fileId: number, public path: string, public language: string, public source: string, rows: NodeRow[]) {
    for (const r of rows) this.nodes.push(new Node(this, r));
    for (const nd of this.nodes) {
      if (nd.row.parent >= 0) this.nodes[nd.row.parent].kids.push(nd);
    }
  }
  get root() { return this.nodes[0]; }
  line(row: number) { return this.source.split("\n")[row] ?? ""; }
}

export class Node {
  kids: Node[] = [];
  /** scratch space for analyses */
  data: Record<string, any> = {};
  constructor(public tree: Tree, public row: NodeRow) {}
  get type() { return this.row.type; }
  get field() { return this.row.field; }
  get named() { return this.row.named; }
  get id() { return this.row.n; }
  get parent(): Node | null { return this.row.parent >= 0 ? this.tree.nodes[this.row.parent] : null; }
  get text(): string { return this.tree.source.slice(this.row.sb, this.row.eb); }
  get children(): Node[] { return this.kids; }
  get namedChildren(): Node[] { return this.kids.filter((k) => k.named); }
  get line() { return this.row.sr + 1; }
  get col() { return this.row.sc + 1; }
  get endLine() { return this.row.er + 1; }
  get isLeaf() { return this.kids.length === 0; }
  /** child by field name, e.g. n.child("function") */
  child(field: string): Node | null { return this.kids.find((k) => k.field === field) ?? null; }
  childrenByField(field: string): Node[] { return this.kids.filter((k) => k.field === field); }
  get next(): Node | null { const p = this.parent; return p ? p.kids[this.row.idx + 1] ?? null : null; }
  get prev(): Node | null { const p = this.parent; return p ? p.kids[this.row.idx - 1] ?? null : null; }
  *descendants(): Generator<Node> { for (const k of this.kids) { yield k; yield* k.descendants(); } }
  *ancestors(): Generator<Node> { let p = this.parent; while (p) { yield p; p = p.parent; } }
  contains(o: Node) { return o.tree === this.tree && o.row.sb >= this.row.sb && o.row.eb <= this.row.eb; }
  loc() { return { file: this.tree.path, line: this.line, col: this.col, endLine: this.endLine }; }
  toString() { return `${this.type}@${this.tree.path}:${this.line}`; }
}
