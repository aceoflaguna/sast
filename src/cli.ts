import { openStore } from "./store";
import { indexDirectory } from "./indexer";
import { scanProject } from "./scan";

const [dir, ...only] = process.argv.slice(2);
if (!dir) { console.log("usage: bun run scan <dir> [query-id ...]"); process.exit(1); }
const store = await openStore();
const id = await store.createProject(dir, dir);
const r = await indexDirectory(store, id, dir);
console.log(`indexed ${r.files} files, ${r.nodes} AST nodes into ${store.kind}`, r.errors.length ? r.errors : "");
const res = await scanProject(store, id, only);
for (const f of res.findings) {
  console.log(`\n[${f.severity.toUpperCase()}] ${f.queryId}  ${f.file}:${f.line}  ${f.message}`);
  for (const s of f.path) console.log(`    ${s.kind.padEnd(9)} ${s.file}:${s.line}  ${s.code}`);
}
console.log("\n" + res.perQuery.map((q) => `${q.id}: ${q.count}`).join("  "));
const failed = res.perQuery.filter((q) => q.error);
for (const q of failed) console.error(`\n!! query "${q.id}" FAILED: ${q.error}`);
if (failed.length) { process.exitCode = 1; }
process.exit(0);
