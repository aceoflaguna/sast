import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { detectLanguage, parseToRows } from "./parser";
import type { Store } from "./store";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__", ".venv", "venv", ".next", "coverage"]);
const MAX_FILE = 2_000_000;

async function* walk(dir: string): AsyncGenerator<string> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name.startsWith(".") && e.isDirectory()) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(p); }
    else if (e.isFile()) yield p;
  }
}

export interface IndexResult { files: number; nodes: number; skipped: number; errors: string[] }

/** Parse every supported file under `root` and persist the AST nodes in the store. */
export async function indexDirectory(store: Store, projectId: number, root: string, onFile?: (f: string) => void): Promise<IndexResult> {
  const abs = path.resolve(root);
  const st = await stat(abs);
  const files = st.isDirectory() ? walk(abs) : (async function* () { yield abs; })();
  const base = st.isDirectory() ? abs : path.dirname(abs);
  const res: IndexResult = { files: 0, nodes: 0, skipped: 0, errors: [] };
  await store.clearFiles(projectId);
  for await (const f of files) {
    const lang = detectLanguage(f);
    if (!lang) { res.skipped++; continue; }
    try {
      if ((await stat(f)).size > MAX_FILE) { res.skipped++; continue; }
      const source = await readFile(f, "utf8");
      const { rows, hasError } = await parseToRows(lang, source);
      await store.addFile(projectId, path.relative(base, f), lang, source, rows, hasError);
      res.files++; res.nodes += rows.length; onFile?.(f);
    } catch (e: any) { res.errors.push(`${f}: ${e.message}`); }
  }
  return res;
}

export async function indexSnippet(store: Store, projectId: number, language: string, code: string, name = "snippet") {
  const { rows, hasError } = await parseToRows(language, code);
  await store.addFile(projectId, name, language, code, rows, hasError);
}
