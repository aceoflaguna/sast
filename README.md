# sastql

A small SAST engine for Bun: parse code with tree-sitter, store the AST in PostgreSQL, query it with a **jQuery-style API**, and track **user input → sink** data flows. Results are shown in a built-in web UI.

```
source files ──tree-sitter──▶ AST nodes ──▶ PostgreSQL
                                  │
                       $("Call[callee$='.query']").parent().closest("Func")     (traversal API)
                                  │
                      taint engine (source → propagate → call/return → sink)
                                  │
                       queries/*.ts  ──▶  findings (JSONB paths)  ──▶  Web UI / SARIF
```

Supported languages: **JavaScript, TypeScript/TSX, Python, PHP, Java**. Queries are written once; each language has a small *profile* (`src/lang/*.ts`) that maps its grammar onto a common model.
## Express Run

Install [bun.js](https://bun.com/docs/installation) and clone/download the repo.

```bash
bun install
bun run start                             # UI on http://127.0.0.1:3000 upload a project folder
```

## Run

```bash
bun install
docker compose up -d                      # optional: Postgres 16 (any Postgres works)
export DATABASE_URL=postgres://sast:sast@localhost:5432/sast
bun run start                             # UI on http://127.0.0.1:3000 upload a project folder
bun run scan sample                       # or: CLI scan of a directory
bun run test                              # regression test (in-memory store unless DATABASE_URL is set)
```

Without `DATABASE_URL` (or if Postgres is unreachable) it falls back to an in-memory store, so you can try it immediately. Tables are created automatically (`projects`, `files`, `nodes`, `findings`). `HOST`/`PORT` env vars change the bind address (default `127.0.0.1:3000`).

> **Security:** the UI can index any path readable by the server process and has no authentication. Keep it on localhost (or behind your own auth).

## The query API (jQuery for ASTs)

```js
$("Call[callee$='.query']")          // every .query() call, in any language
  .parent()                          // traverse
  .closest("Func")                   // enclosing function
  .find("Return")                    // descendants
```

**Selectors** — CSS-like:

| | |
|---|---|
| `call_expression`, `method_invocation` | raw tree-sitter node type |
| `Call` `Assign` `Func` `Ident` `Str` `Member` `Return` `Class` | language-neutral *kinds* (resolved per language) |
| `a b` `a > b` `a + b` `a ~ b` `a, b` | descendant / child / next / following sibling / union |
| `[callee*="query"]` | normalized callee of a call (`db.query`, `$pdo.query`, `new File`, `echo`) |
| `[path^="req.query"]` | normalized access path of identifiers / member chains / calls |
| `[fname=handler]` | function name |
| `[text~=/re/i]` `[type=..]` `[line=12]` | builtin attributes (`=`, `!=`, `*=`, `^=`, `$=`, `~=`) |
| `[function="eval"]` | any other name = text of that **field** child (grammar specific) |
| `:has() :not() :is() :contains("x") :first-child :last-child :nth-child(n) :named :leaf` | pseudos |

**Methods** on the result set (`Q`): `find children named child parent parents closest next prev siblings filter not has is first last eq slice add each map get text texts attr loc`.

The UI console accepts these chains (whitelisted methods only — nothing is `eval`ed). Inside query files you get the full API with `ctx.$` and every `Node` (`.type .text .field .parent .children .line ...`).

## Writing a query

Drop a file in `queries/` (files starting with `_` are ignored) and press *Reload query files* in the UI.

**Declarative taint query** — sources/sinks/sanitizers per language (`"*"` applies to all):

```ts
import { defineQuery } from "../src/query";

export default defineQuery({
  id: "sql-injection", title: "SQL injection", severity: "critical", cwe: "CWE-89",
  taint: {
    sinks: {
      python: [{ callee: /(^|\.)(execute|executemany)$/, args: [0], label: "SQL execute" }],
      php:    [{ callee: /^(mysqli_query|pg_query)$/, label: "SQL query" }],
      javascript: [{ assign: /\.innerHTML$/, label: "innerHTML" }],      // assignment sinks too
    },
    sanitizers: { php: [/^mysqli_real_escape_string$/] },
    // sources: { python: [/^my_framework\.params/] }   // extra sources, on top of the built-in user input ones
  },
  message: (f) => `User input flows into ${f.label}`,
});
```

**Imperative query** — use `$`, `profile()`, `flows()` and `report()`; see `queries/hardcoded-secret.ts`:

```ts
run({ $, flows, report }) {
  for (const f of flows({ sinks: { "*": [{ callee: /^eval$/ }] } }))       // raw taint flows ...
    if ($(f.sink).closest("Func[fname=admin]").length === 0)                 // ... post-filtered with traversal
      report(f.sink, "eval of user input outside admin()", { path: f.path });
}
```

Bundled: `sql-injection`, `xss`, `command-injection`, `code-injection`, `path-traversal`, `ssrf`, `open-redirect`, `hardcoded-secret`.

## How the taint engine works (`src/taint.ts`)

* Each function / module is walked in source order with an environment `path → taint`; assignments, destructuring, `+=`, f-strings/templates, concatenation, and unknown calls (receiver + args) propagate taint. A plain re-assignment clears it.
* Every taint carries its **step list** (source → propagation → call → return → sink) which is what the UI shows and what SARIF `codeFlows` exports.
* Sources are built into each profile (`req.query`, `request.args`, `$_GET`, `getParameter`, Spring `@RequestParam`, …); sanitizers are per query, and numeric conversions (`parseInt`, `int()`, `intval`, `(int)`, `Integer.parseInt`) neutralise taint for all queries.
* **Function summaries** (params that reach a sink, params that flow to the return value, return of tainted data) are computed to a fixpoint across *all* files in the project, so `route → helper() → db.query()` is found even across files.

### Known limits (heuristic engine — expect false positives/negatives)
* Not path-sensitive: both branches of an `if` are walked in order; validation checks (`if (isSafe(x))`) are not understood.
* Calls are resolved **by name** (`obj.find()` ↔ any function/method named `find` in the same language), no types/class hierarchy, no imports/aliases, no dynamic dispatch.
* No taint through containers beyond the variable/property path (`arr.push(tainted)` then `arr[0]`), callbacks passed to other functions, `foreach` (PHP) or `with … as` (Python).
* Return-value sinks (Flask `return "<h1>"+name`) are not modelled; XSS sinks are calls/assignments.
* Sinks, sources and sanitizers are regex catalogs — extend them in `queries/*.ts` and `src/lang/*.ts`.

## Adding a language

1. Add the grammar to `LANGS` in `src/parser.ts` (any `tree-sitter-wasms` grammar works).
2. Create `src/lang/<lang>.ts` implementing `Profile` (`kinds`, `pathOf`, `call`, `assign`, `func`, `ret`, `sources`, `numeric`, …) — the four existing profiles are ~100 lines each. Use the UI's AST explorer to learn node/field names.
3. Register it in `src/lang/index.ts`, then add a `<lang>:` entry to the queries' `sinks`.

## HTTP API

`GET /api/info` · `GET|POST /api/projects` (`{path}` or `{files:[{path,content}]}`) · `POST /api/projects/:id/scan` · `GET …/findings` · `GET …/sarif` · `POST …/query {expr}` · `GET …/nodes?type=&text=` (SQL-backed node search) · `GET /api/files/:id/{source,ast}` · `GET /api/queries/:id/source` · `POST /api/queries/reload`

## Database

`nodes(file_id, n, parent, idx, type, field, named, sb, eb, sr, sc, er, ec, text)` holds the AST (pre-order, `n` = index in file, `parent` = parent's `n`). You can also query it directly:

```sql
-- every identifier named "query" used as the object of a call, by project
select f.path, n.sr+1 as line from nodes n join files f on f.id=n.file_id
where n.type='identifier' and n.text='query' and n.field='object';
```
