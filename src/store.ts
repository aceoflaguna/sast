import postgres from "postgres";
import { Tree } from "./node";
import type { NodeRow } from "./parser";

export interface Step { kind: "source" | "propagate" | "call" | "return" | "sanitizer" | "sink"; file: string; line: number; col: number; code: string; note?: string }
export interface Finding {
  id?: number; queryId: string; title: string; severity: string; cwe?: string; message: string;
  file: string; line: number; col: number; language: string; path: Step[]; sinkCode?: string;
}
export interface ProjectRow { id: number; name: string; root: string | null; created_at: string; files: number; nodes: number; findings: number }
export interface FileRow { id: number; path: string; language: string; has_error: boolean; nodes: number }

export interface Store {
  kind: "postgres" | "memory";
  init(): Promise<void>;
  createProject(name: string, root: string | null): Promise<number>;
  listProjects(): Promise<ProjectRow[]>;
  deleteProject(id: number): Promise<void>;
  clearFiles(projectId: number): Promise<void>;
  addFile(projectId: number, path: string, language: string, source: string, rows: NodeRow[], hasError: boolean): Promise<number>;
  listFiles(projectId: number): Promise<FileRow[]>;
  loadTree(fileId: number): Promise<Tree | null>;
  loadProjectTrees(projectId: number): Promise<Tree[]>;
  replaceFindings(projectId: number, queryIds: string[], findings: Finding[]): Promise<void>;
  listFindings(projectId: number): Promise<Finding[]>;
  searchNodes(projectId: number, o: { type?: string; text?: string; language?: string; limit?: number }): Promise<any[]>;
}

/* ------------------------------------------------------------------ Postgres */
export class PgStore implements Store {
  kind = "postgres" as const;
  sql: postgres.Sql;
  constructor(url: string) { this.sql = postgres(url, { max: 5, onnotice: () => {}, connect_timeout: 5 }); }

  async init() {
    const s = this.sql;
    await s`select 1`;
    await s`create table if not exists projects (
      id serial primary key, name text not null, root text, created_at timestamptz default now())`;
    await s`create table if not exists files (
      id serial primary key, project_id int not null references projects(id) on delete cascade,
      path text not null, language text not null, source text not null, has_error boolean default false)`;
    await s`create table if not exists nodes (
      file_id int not null references files(id) on delete cascade,
      n int not null, parent int not null, idx int not null,
      type text not null, field text, named boolean not null,
      sb int not null, eb int not null, sr int not null, sc int not null, er int not null, ec int not null,
      text text, primary key (file_id, n))`;
    await s`create index if not exists nodes_type_idx on nodes(type)`;
    await s`create index if not exists nodes_parent_idx on nodes(file_id, parent)`;
    await s`create index if not exists nodes_text_idx on nodes(text) where text is not null`;
    await s`create index if not exists files_project_idx on files(project_id)`;
    await s`create table if not exists findings (
      id serial primary key, project_id int not null references projects(id) on delete cascade,
      query_id text not null, title text, severity text, cwe text, message text,
      file text, line int, col int, language text, path jsonb not null default '[]', sink_code text,
      created_at timestamptz default now())`;
    await s`create index if not exists findings_project_idx on findings(project_id, query_id)`;
  }

  async createProject(name: string, root: string | null) {
    const [r] = await this.sql`insert into projects(name, root) values (${name}, ${root}) returning id`;
    return r.id as number;
  }
  async listProjects() {
    return (await this.sql`
      select p.id, p.name, p.root, p.created_at,
        (select count(*)::int from files f where f.project_id = p.id) as files,
        (select count(*)::int from nodes n join files f on f.id = n.file_id where f.project_id = p.id) as nodes,
        (select count(*)::int from findings x where x.project_id = p.id) as findings
      from projects p order by p.id desc`) as any;
  }
  async deleteProject(id: number) { await this.sql`delete from projects where id = ${id}`; }
  async clearFiles(projectId: number) {
    await this.sql`delete from files where project_id = ${projectId}`;
    await this.sql`delete from findings where project_id = ${projectId}`;
  }
  async addFile(projectId: number, path: string, language: string, source: string, rows: NodeRow[], hasError: boolean) {
    const [f] = await this.sql`insert into files(project_id, path, language, source, has_error)
      values (${projectId}, ${path}, ${language}, ${source}, ${hasError}) returning id`;
    const fileId = f.id as number;
    const recs = rows.map((r, i, all) => ({
      file_id: fileId, n: r.n, parent: r.parent, idx: r.idx, type: r.type, field: r.field, named: r.named,
      sb: r.sb, eb: r.eb, sr: r.sr, sc: r.sc, er: r.er, ec: r.ec,
      text: r.named && (all[i + 1]?.parent !== r.n) && r.eb - r.sb <= 500 ? source.slice(r.sb, r.eb) : null,
    }));
    for (let i = 0; i < recs.length; i += 2000) {
      await this.sql`insert into nodes ${this.sql(recs.slice(i, i + 2000))}`;
    }
    return fileId;
  }
  async listFiles(projectId: number) {
    return (await this.sql`select f.id, f.path, f.language, f.has_error,
      (select count(*)::int from nodes n where n.file_id = f.id) as nodes
      from files f where f.project_id = ${projectId} order by f.path`) as any;
  }
  private async buildTree(f: any): Promise<Tree> {
    const rows = await this.sql`select n, parent, idx, type, field, named, sb, eb, sr, sc, er, ec
      from nodes where file_id = ${f.id} order by n`;
    return new Tree(f.id, f.path, f.language, f.source, rows as unknown as NodeRow[]);
  }
  async loadTree(fileId: number) {
    const [f] = await this.sql`select id, path, language, source from files where id = ${fileId}`;
    return f ? this.buildTree(f) : null;
  }
  async loadProjectTrees(projectId: number) {
    const files = await this.sql`select id, path, language, source from files where project_id = ${projectId} order by path`;
    const out: Tree[] = [];
    for (const f of files) out.push(await this.buildTree(f));
    return out;
  }
  async replaceFindings(projectId: number, queryIds: string[], findings: Finding[]) {
    await this.sql`delete from findings where project_id = ${projectId} and query_id in ${this.sql(queryIds)}`;
    const recs = findings.map((f) => ({
      project_id: projectId, query_id: f.queryId, title: f.title, severity: f.severity, cwe: f.cwe ?? null,
      message: f.message, file: f.file, line: f.line, col: f.col, language: f.language,
      path: this.sql.json(f.path as any), sink_code: f.sinkCode ?? null,
    }));
    for (let i = 0; i < recs.length; i += 500) await this.sql`insert into findings ${this.sql(recs.slice(i, i + 500))}`;
  }
  async listFindings(projectId: number) {
    const rows = await this.sql`select * from findings where project_id = ${projectId}
      order by case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end, file, line`;
    return rows.map((r: any) => ({
      id: r.id, queryId: r.query_id, title: r.title, severity: r.severity, cwe: r.cwe, message: r.message,
      file: r.file, line: r.line, col: r.col, language: r.language, path: r.path, sinkCode: r.sink_code,
    }));
  }
  async searchNodes(projectId: number, o: { type?: string; text?: string; language?: string; limit?: number }) {
    const limit = Math.min(o.limit ?? 100, 1000);
    return await this.sql`select f.path as file, f.language, n.type, n.field, n.sr + 1 as line, n.sc + 1 as col, n.text
      from nodes n join files f on f.id = n.file_id
      where f.project_id = ${projectId}
        ${o.type ? this.sql`and n.type = ${o.type}` : this.sql``}
        ${o.text ? this.sql`and n.text ilike ${"%" + o.text + "%"}` : this.sql``}
        ${o.language ? this.sql`and f.language = ${o.language}` : this.sql``}
      order by f.path, n.sr limit ${limit}`;
  }
}

/* ------------------------------------------------------------------ Memory fallback */
export class MemStore implements Store {
  kind = "memory" as const;
  private pid = 0; private fid = 0; private fnd = 0;
  projects = new Map<number, { id: number; name: string; root: string | null; created_at: string }>();
  files = new Map<number, { id: number; projectId: number; path: string; language: string; source: string; rows: NodeRow[]; hasError: boolean }>();
  findings = new Map<number, Finding[]>();
  async init() {}
  async createProject(name: string, root: string | null) {
    const id = ++this.pid; this.projects.set(id, { id, name, root, created_at: new Date().toISOString() }); return id;
  }
  async listProjects() {
    return [...this.projects.values()].reverse().map((p) => {
      const fs = [...this.files.values()].filter((f) => f.projectId === p.id);
      return { ...p, files: fs.length, nodes: fs.reduce((a, f) => a + f.rows.length, 0), findings: this.findings.get(p.id)?.length ?? 0 };
    });
  }
  async deleteProject(id: number) { await this.clearFiles(id); this.projects.delete(id); }
  async clearFiles(pid: number) {
    for (const [k, f] of this.files) if (f.projectId === pid) this.files.delete(k);
    this.findings.delete(pid);
  }
  async addFile(projectId: number, path: string, language: string, source: string, rows: NodeRow[], hasError: boolean) {
    const id = ++this.fid; this.files.set(id, { id, projectId, path, language, source, rows, hasError }); return id;
  }
  async listFiles(pid: number) {
    return [...this.files.values()].filter((f) => f.projectId === pid)
      .map((f) => ({ id: f.id, path: f.path, language: f.language, has_error: f.hasError, nodes: f.rows.length }))
      .sort((a, b) => a.path.localeCompare(b.path));
  }
  async loadTree(fileId: number) {
    const f = this.files.get(fileId); return f ? new Tree(f.id, f.path, f.language, f.source, f.rows) : null;
  }
  async loadProjectTrees(pid: number) {
    return [...this.files.values()].filter((f) => f.projectId === pid).sort((a, b) => a.path.localeCompare(b.path))
      .map((f) => new Tree(f.id, f.path, f.language, f.source, f.rows));
  }
  async replaceFindings(pid: number, queryIds: string[], found: Finding[]) {
    const keep = (this.findings.get(pid) ?? []).filter((f) => !queryIds.includes(f.queryId));
    this.findings.set(pid, [...keep, ...found.map((f) => ({ ...f, id: ++this.fnd }))]);
  }
  async listFindings(pid: number) {
    const order: any = { critical: 0, high: 1, medium: 2 };
    return [...(this.findings.get(pid) ?? [])].sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3) || a.file.localeCompare(b.file) || a.line - b.line);
  }
  async searchNodes(pid: number, o: { type?: string; text?: string; language?: string; limit?: number }) {
    const out: any[] = [];
    for (const f of this.files.values()) {
      if (f.projectId !== pid || (o.language && f.language !== o.language)) continue;
      for (const r of f.rows) {
        if (o.type && r.type !== o.type) continue;
        const text = f.source.slice(r.sb, r.eb);
        if (o.text && !text.toLowerCase().includes(o.text.toLowerCase())) continue;
        out.push({ file: f.path, language: f.language, type: r.type, field: r.field, line: r.sr + 1, col: r.sc + 1, text: text.slice(0, 200) });
        if (out.length >= (o.limit ?? 100)) return out;
      }
    }
    return out;
  }
}

export async function openStore(): Promise<Store> {
  const url = process.env.DATABASE_URL;
  if (url) {
    try { const s = new PgStore(url); await s.init(); return s; }
    catch (e: any) { console.warn(`[store] Postgres unavailable (${e.message}); falling back to in-memory store`); }
  } else console.warn("[store] DATABASE_URL not set; using in-memory store");
  return new MemStore();
}
