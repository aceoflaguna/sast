import type { Store, Finding } from "./store";
import { loadQueries, runQuery } from "./query";

export interface ScanResult { findings: Finding[]; perQuery: { id: string; count: number; ms: number; error?: string }[] }

export async function scanProject(store: Store, projectId: number, only?: string[]): Promise<ScanResult> {
  const defs = (await loadQueries()).filter((d) => !only?.length || only.includes(d.id));
  const trees = await store.loadProjectTrees(projectId);
  const all: Finding[] = [];
  const perQuery: ScanResult["perQuery"] = [];
  for (const d of defs) {
    const t0 = performance.now();
    try {
      const f = runQuery(d, trees);
      all.push(...f);
      perQuery.push({ id: d.id, count: f.length, ms: Math.round(performance.now() - t0) });
    } catch (e: any) {
      perQuery.push({ id: d.id, count: 0, ms: Math.round(performance.now() - t0), error: e.message });
    }
  }
  await store.replaceFindings(projectId, defs.map((d) => d.id), all);
  return { findings: all, perQuery };
}
