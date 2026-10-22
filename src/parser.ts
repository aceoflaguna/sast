import { Parser, Language } from "web-tree-sitter";
import path from "node:path";

/** A flat, DB-friendly node row. `n` is the index of the node inside its file (pre-order). */
export interface NodeRow {
  n: number;
  parent: number; // -1 for root
  idx: number; // position among parent's (all) children
  type: string;
  field: string | null; // field name in parent (e.g. "function", "arguments", "left")
  named: boolean;
  sb: number; // start offset (UTF-16 index into source)
  eb: number;
  sr: number; // start row (0-based)
  sc: number;
  er: number;
  ec: number;
}

export const LANGS: Record<string, { wasm: string; exts: string[] }> = {
  javascript: { wasm: "tree-sitter-javascript.wasm", exts: [".js", ".mjs", ".cjs", ".jsx"] },
  typescript: { wasm: "tree-sitter-typescript.wasm", exts: [".ts", ".mts", ".cts"] },
  tsx: { wasm: "tree-sitter-tsx.wasm", exts: [".tsx"] },
  python: { wasm: "tree-sitter-python.wasm", exts: [".py"] },
  php: { wasm: "tree-sitter-php.wasm", exts: [".php", ".phtml"] },
  java: { wasm: "tree-sitter-java.wasm", exts: [".java"] },
  go: { wasm: "tree-sitter-go.wasm", exts: [".go"] },
  csharp: { wasm: "tree-sitter-c_sharp.wasm", exts: [".cs"] },
  ruby: { wasm: "tree-sitter-ruby.wasm", exts: [".rb", ".rake", ".ru"] },
};

export function detectLanguage(file: string): string | null {
  const ext = path.extname(file).toLowerCase();
  for (const [name, d] of Object.entries(LANGS)) if (d.exts.includes(ext)) return name;
  return null;
}

let inited: Promise<void> | null = null;
const cache = new Map<string, Language>();
const wasmDir = path.join(path.dirname(require.resolve("tree-sitter-wasms/package.json")), "out");

async function lang(name: string): Promise<Language> {
  inited ??= Parser.init();
  await inited;
  let l = cache.get(name);
  if (!l) {
    l = await Language.load(path.join(wasmDir, LANGS[name].wasm));
    cache.set(name, l);
  }
  return l;
}

export async function parseToRows(language: string, source: string): Promise<{ rows: NodeRow[]; hasError: boolean }> {
  if (!LANGS[language]) throw new Error(`Unsupported language: ${language}`);
  const language_ = await lang(language); // also awaits Parser.init()
  const parser = new Parser();
  parser.setLanguage(language_);
  const tree = parser.parse(source)!;
  const rows: NodeRow[] = [];
  const cur = tree.walk();
  // iterative pre-order walk
  const parentStack: number[] = [-1];
  const idxStack: number[] = [0];
  let first = true;
  const emit = () => {
    const nd = cur.currentNode;
    const n = rows.length;
    const depth = parentStack.length - 1;
    const parent = parentStack[depth];
    rows.push({
      n, parent, idx: idxStack[depth]++, type: nd.type, field: cur.currentFieldName ?? null, named: nd.isNamed,
      sb: nd.startIndex, eb: nd.endIndex, sr: nd.startPosition.row, sc: nd.startPosition.column,
      er: nd.endPosition.row, ec: nd.endPosition.column,
    });
    return n;
  };
  let current = emit();
  first = false;
  while (true) {
    if (cur.gotoFirstChild()) {
      parentStack.push(current);
      idxStack.push(0);
      current = emit();
      continue;
    }
    while (!cur.gotoNextSibling()) {
      if (!cur.gotoParent()) {
        const hasError = tree.rootNode.hasError;
        tree.delete();
        parser.delete();
        return { rows, hasError };
      }
      parentStack.pop();
      idxStack.pop();
    }
    current = emit();
  }
}
