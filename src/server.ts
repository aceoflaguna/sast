import path from "node:path";
import { openStore, type Finding } from "./store";
import { indexDirectory } from "./indexer";
import { scanProject } from "./scan";
import { loadQueries } from "./query";
import { detectLanguage, parseToRows, LANGS } from "./parser";
import { runChain } from "./chain";
import { profiles } from "./lang";
import type { Node } from "./node";

const store = await openStore();
const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number(process.env.PORT ?? 3000);
const uiDir = path.join(import.meta.dir, "..", "ui");

const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
const bad = (msg: string, status = 400) => json({ error: msg }, status);

function astJson(n: Node, all: boolean): any {
  const kids = (all ? n.kids : n.namedChildren).map((k) => astJson(k, all));
  return { t: n.type, f: n.field, sl: n.line, sc: n.col, el: n.endLine, ...(n.kids.length === 0 || n.text.length < 60 ? { x: n.text.slice(0, 60) } : {}), ...(kids.length ? { c: kids } : {}) };
}

function sarif(findings: Finding[]) {
  return {
    version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "sastql", rules: [...new Set(findings.map((f) => f.queryId))].map((id) => ({ id })) } },
      results: findings.map((f) => ({
        ruleId: f.queryId, level: f.severity === "critical" || f.severity === "high" ? "error" : "warning", message: { text: f.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, startColumn: f.col } } }],
        codeFlows: [{ threadFlows: [{ locations: f.path.map((s) => ({ location: { message: { text: `${s.kind}: ${s.code}` }, physicalLocation: { artifactLocation: { uri: s.file }, region: { startLine: s.line, startColumn: s.col } } } })) }] }],
      })),
    }],
  };
}

async function api(req: Request, url: URL): Promise<Response> {
  const p = url.pathname.replace(/^\/api/, "");
  const m = req.method;
  let r: RegExpMatchArray | null;

  if (p === "/info" && m === "GET") {
    const qs = await loadQueries();
    return json({ store: store.kind, languages: Object.keys(LANGS), exts: Object.fromEntries(Object.entries(LANGS).map(([k, v]) => [k, v.exts])), sampleDir: path.join(import.meta.dir, "..", "sample"), queries: qs.map((q) => ({ id: q.id, title: q.title, severity: q.severity, cwe: q.cwe, description: q.description, languages: q.languages ?? Object.keys(profiles), kind: q.taint ? "taint" : "traversal", file: q.file })) });
  }
  if (p === "/queries/reload" && m === "POST") return json({ queries: (await loadQueries(true)).length });
  if ((r = p.match(/^\/queries\/([\w-]+)\/source$/)) && m === "GET") {
    const q = (await loadQueries()).find((x) => x.id === r![1]);
    if (!q?.file) return bad("not found", 404);
    return json({ file: q.file, source: await Bun.file(path.join(import.meta.dir, "..", "queries", q.file)).text() });
  }

  if (p === "/projects" && m === "GET") return json(await store.listProjects());
  if (p === "/projects" && m === "POST") {
    const body = (await req.json()) as { name?: string; path?: string; files?: { path: string; content: string }[] };
    const name = body.name || body.path || "project";
    const id = await store.createProject(name, body.path ?? null);
    try {
      if (body.path) {
        const res = await indexDirectory(store, id, body.path);
        return json({ id, ...res });
      }
      let files = 0, nodes = 0, skipped = 0; const errors: string[] = [];
      for (const f of body.files ?? []) {
        const lang = detectLanguage(f.path);
        if (!lang) { skipped++; continue; }
        try { const { rows, hasError } = await parseToRows(lang, f.content); await store.addFile(id, f.path, lang, f.content, rows, hasError); files++; nodes += rows.length; }
        catch (e: any) { errors.push(`${f.path}: ${e.message}`); }
      }
      return json({ id, files, nodes, skipped, errors });
    } catch (e: any) { await store.deleteProject(id); return bad(e.message); }
  }
  if ((r = p.match(/^\/projects\/(\d+)$/))) {
    if (m === "DELETE") { await store.deleteProject(+r[1]); return json({ ok: true }); }
  }
  if ((r = p.match(/^\/projects\/(\d+)\/reindex$/)) && m === "POST") {
    const proj = (await store.listProjects()).find((x) => x.id === +r![1]);
    if (!proj?.root) return bad("project has no source path to re-index");
    return json(await indexDirectory(store, proj.id, proj.root));
  }
  if ((r = p.match(/^\/projects\/(\d+)\/scan$/)) && m === "POST") {
    const body = (await req.json().catch(() => ({}))) as { queries?: string[] };
    return json(await scanProject(store, +r[1], body.queries));
  }
  if ((r = p.match(/^\/projects\/(\d+)\/findings$/)) && m === "GET") return json(await store.listFindings(+r[1]));
  if ((r = p.match(/^\/projects\/(\d+)\/sarif$/)) && m === "GET") return json(sarif(await store.listFindings(+r[1])));
  if ((r = p.match(/^\/projects\/(\d+)\/files$/)) && m === "GET") return json(await store.listFiles(+r[1]));
  if ((r = p.match(/^\/projects\/(\d+)\/nodes$/)) && m === "GET") {
    const q = url.searchParams;
    return json(await store.searchNodes(+r[1], { type: q.get("type") || undefined, text: q.get("text") || undefined, language: q.get("language") || undefined, limit: Number(q.get("limit") ?? 100) }));
  }
  if ((r = p.match(/^\/projects\/(\d+)\/query$/)) && m === "POST") {
    const { expr, limit = 200 } = (await req.json()) as { expr: string; limit?: number };
    if (!expr?.trim()) return bad("empty query");
    const t0 = performance.now();
    const trees = await store.loadProjectTrees(+r[1]);
    const q = runChain(trees, expr);
    const rows = q.nodes.slice(0, limit).map((n) => ({
      file: n.tree.path, fileId: n.tree.fileId, language: n.tree.language, type: n.type, field: n.field, line: n.line, col: n.col, endLine: n.endLine,
      text: n.text.slice(0, 240), parents: [...n.ancestors()].slice(0, 4).map((a) => a.type),
    }));
    return json({ total: q.length, ms: Math.round(performance.now() - t0), rows });
  }
  if ((r = p.match(/^\/files\/(\d+)\/source$/)) && m === "GET") {
    const t = await store.loadTree(+r[1]);
    return t ? json({ path: t.path, language: t.language, source: t.source }) : bad("not found", 404);
  }
  if ((r = p.match(/^\/files\/(\d+)\/ast$/)) && m === "GET") {
    const t = await store.loadTree(+r[1]);
    return t ? json(astJson(t.root, url.searchParams.get("all") === "1")) : bad("not found", 404);
  }
  return bad("not found", 404);
}

Bun.serve({
  hostname: HOST,
  port: PORT,
  maxRequestBodySize: 256 * 1024 * 1024,
  async fetch(req) {
    const url = new URL(req.url);
    try {
      if (url.pathname.startsWith("/api/")) return await api(req, url);
      const file = Bun.file(path.join(uiDir, url.pathname === "/" ? "index.html" : path.normalize(url.pathname).replace(/^(\.\.[/\\])+/, "")));
      return (await file.exists()) ? new Response(file) : new Response("Not found", { status: 404 });
    } catch (e: any) {
      console.error(e);
      return bad(e.message ?? String(e), 500);
    }
  },
});
console.log(`sastql UI → http://${HOST}:${PORT}   (store: ${store.kind})`);
