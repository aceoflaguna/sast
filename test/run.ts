/** Regression test: bun run test   (uses the in-memory store unless DATABASE_URL is set) */
import path from "node:path";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { openStore } from "../src/store";
import { indexDirectory } from "../src/indexer";
import { scanProject } from "../src/scan";
import { runChain } from "../src/chain";
import { loadQueries } from "../src/query";

let failed = 0;
const ok = (cond: boolean, msg: string) => { console.log(`${cond ? "  ✓" : "  ✗"} ${msg}`); if (!cond) failed++; };
const sampleDir = path.join(import.meta.dir, "..", "sample");

const store = await openStore();
console.log(`store: ${store.kind}`);
const pid = await store.createProject("test", null);
const idx = await indexDirectory(store, pid, sampleDir);
const { findings, perQuery } = await scanProject(store, pid);
const ids = new Set((await loadQueries()).map((q) => q.id));

console.log(`\nindexed ${idx.files} files (${idx.errors.length} errors), ${findings.length} findings from ${ids.size} queries`);
ok(idx.errors.length === 0, "every sample file parsed");
ok(perQuery.every((q) => !q.error), "no query errored: " + (perQuery.filter((q) => q.error).map((q) => `${q.id}: ${q.error}`).join("; ") || "ok"));

console.log("\nfinding counts per query (pinned after manual review)");
const expected: Record<string, number> = {
  "sql-injection": 20, xss: 12, "command-injection": 9, "code-injection": 4, "path-traversal": 9, ssrf: 3, "open-redirect": 7, "hardcoded-secret": 9,
  "insecure-deserialization": 8, xxe: 6, "ldap-injection": 5, "xpath-injection": 6, "nosql-injection": 4, ssti: 4, "log-injection": 7,
  "header-injection": 7, "regex-injection": 7, "prototype-pollution": 1, "weak-hash": 7, "weak-cipher": 6, "insecure-random": 7,
  "tls-verification-disabled": 7, "insecure-jwt": 7, "cors-misconfiguration": 7,
};
for (const id of ids) ok(perQuery.find((q) => q.id === id)?.count === (expected[id] ?? -1), `${id}: ${expected[id]} (got ${perQuery.find((q) => q.id === id)?.count})`);

console.log("\nannotated sample lines  (comment names a query id => must be reported; comment says SAFE => must not be)");
const walk = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = path.join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
let marked = 0, safeLines = 0, bad: string[] = [];
for (const f of walk(sampleDir)) {
  const rel = path.relative(sampleDir, f);
  readFileSync(f, "utf8").split("\n").forEach((line, i) => {
    const m = /^(.*?\S.*?)\s*(?:\/\/|#)\s*(.+)$/.exec(line);          // code followed by a trailing comment
    if (!m || /^\s*(\/\/|#)/.test(line)) return;
    const comment = m[2];
    const n = i + 1;
    // reported at the sink, or (cross-function flows) the annotated line is a step on the reported path
    const hit = (q: string) => findings.some((x) => x.queryId === q && ((x.file === rel && x.line === n) || x.path.some((s) => s.file === rel && s.line === n)));
    if (/\bSAFE\b/.test(comment)) { safeLines++; if (findings.some((x) => x.file === rel && x.line === n)) bad.push(`${rel}:${n} flagged but marked SAFE`); return; }
    const id = comment.split(/[^a-z-]+/).find((t) => ids.has(t));
    if (id) { marked++; if (!hit(id)) bad.push(`${rel}:${n} expected ${id}`); }
  });
}
ok(bad.length === 0, `${marked} expected findings present, ${safeLines} SAFE lines clean` + (bad.length ? "\n      " + bad.join("\n      ") : ""));

console.log("\nlanguage coverage");
const langs = new Set(findings.map((f) => f.language));
for (const l of ["javascript", "python", "php", "java", "go", "csharp", "ruby"]) ok(langs.has(l), `findings in ${l}`);
for (const q of ["sql-injection", "xss", "command-injection", "path-traversal", "open-redirect"])
  ok(["javascript", "python", "php", "java", "go", "csharp", "ruby"].every((l) => findings.some((f) => f.queryId === q && f.language === l)), `${q} found in all 7 languages`);

console.log("\ninter-procedural paths carry call/return steps");
const hop = (file: string) => findings.find((f) => f.queryId === "sql-injection" && f.file === file && f.path.some((s) => s.kind === "call"));
for (const f of ["js/db.js", "python/app.py", "php/index.php", "java/UserController.java", "go/main.go", "csharp/UserController.cs", "ruby/users_controller.rb"])
  ok(!!hop(f) && hop(f)!.path[0].kind === "source" && hop(f)!.path.at(-1)!.kind === "sink", `${f}: source → call → sink`);

console.log("\njQuery-style queries");
const trees = await store.loadProjectTrees(pid);
const langsOf = (expr: string) => new Set(runChain(trees, expr).nodes.map((n) => n.tree.language));
ok(runChain(trees, `$("Call[callee=eval]")`).length === 3, `Call[callee=eval] matches JS + PHP + Ruby`);
ok(["javascript", "php"].every((l) => langsOf(`$("Call[callee$='.query']")`).has(l)), `Call[callee$='.query'] matches JS and PHP`);
ok(["go", "csharp"].every((l) => langsOf(`$("Call[callee$='.Query']")`).has(l)), `Call[callee$='.Query'] matches Go and C#`);
ok(langsOf(`$("Func[fname=runQuery]")`).has("java") && langsOf(`$("Func[fname=Run]")`).has("csharp") && langsOf(`$("Func[fname=helperQuery]")`).has("go"), `Func[fname=…] works in Java / C# / Go`);
ok(runChain(trees, `$("Func[fname=runQuery]").find("Return")`).length >= 2, `Func[fname=runQuery].find(Return)`);
ok(runChain(trees, `$("Call[callee=eval]").parent().closest("Func")`).length >= 1, `chained traversal`);
let blocked = false; try { runChain(trees, `$("Call").constructor("x")`); } catch { blocked = true; }
ok(blocked, "non-whitelisted method is rejected (no eval)");

await store.deleteProject(pid);
console.log(failed ? `\n${failed} FAILED` : "\nall passed");
process.exit(failed ? 1 : 0);
