# Querying ASTs with sastql

This document explains how to write queries against parsed source code in this codebase. There are **three layers** you can use, from simplest to most powerful:

1. **jQuery-style chains** in the UI console (`runChain`) — for exploration.
2. **CSS-like selectors** (`$("...")`) — the matching engine underneath everything.
3. **Declarative queries** (`defineQuery`) — for real detection rules with taint tracking.

---

## 1. The building blocks

| Concept | What it is |
|---|---|
| `Tree` | One parsed file. Holds `nodes[]`, `source`, `path`, `language`. |
| `Node` | A single AST node. Has `.type`, `.text`, `.line`, `.col`, `.parent`, `.kids`, `.namedChildren`, `.child(field)`, `.descendants()`, `.ancestors()`. |
| `Q` | A jQuery-like collection of `Node`s with traversal/filtering methods. |
| `$` | `makeDollar(trees)` — builds a `Q` from a selector string, a `Node`, or an array. |
| `Profile` | Per-language adapter (`javascript`, `python`, `php`, `java`) that maps grammar-specific node names onto abstract **kinds**: `Call`, `Assign`, `Func`, `Ident`, `Str`, `Member`, `Return`, `Class`. |

The abstract kinds are what make queries **language-agnostic**: `Call` matches `call_expression` in JS, `call` in Python, `method_invocation` in Java, `function_call_expression` in PHP.

---

## 2. Selector syntax (the core skill)

Selectors are CSS-like but match AST nodes.

### Tags
```
Call                          abstract kind (any language)
call_expression               exact tree-sitter node type
*                             any node
```

### Combinators
```
Call Ident                    descendant
Call > Ident                  direct child
Call + Ident                  next sibling
Call ~ Ident                  any following sibling
Call, Assign                  union
```

### Attribute filters
```
[text="eval"]                 exact text
[text*="query"]               contains
[text^="req."]                starts with
[text$="()"]                  ends with
[text~="^exec"]               regex (string form)
[text=/^exec/i]               regex literal with flags
[text!="x"]                   not equal
[type=identifier]             node type
[field=function]              field name in parent
[line=12]                     line number
[named=true]                  named-node flag
```

### Language-neutral attributes (via the profile)
```
[callee*="query"]             normalized callee of a Call: "db.query", "$pdo.query", "new File", "echo"
[path^="req.query"]           normalized access path of an Ident/Member/Call: "req.query.id", "$_GET[]", "request.args.get()"
[fname=handler]               function name of a Func
```

### Generic field attribute
Any other attribute name means **"text of the child in that field"**:
```
call_expression[function="eval"]      the `function` child's text is "eval"
[arguments]                           a child in field `arguments` exists
```

### Pseudo-classes
```
:has(sel)          has a descendant matching sel  (or :has(> sel) for direct child)
:not(sel)          does not match
:is(a, b)          matches any of
:contains("txt")   text contains
:first-child  :last-child  :nth-child(n)
:named             is a named node
:leaf              has no children
```

### Examples
```js
// Every call whose callee ends in "query"
Call[callee$="query"]

// Every eval() call in any language
Call[callee=eval]

// Calls that are descendants of a function named "handler"
Func[fname=handler] Call

// Identifiers whose path starts with "req.body"
Ident[path^="req.body"]

// Strings passed directly to a query call
Call[callee*="query"] > Str

// Functions containing a call to exec
Func:has(Call[callee=exec])
```

---

## 3. The `Q` API (jQuery-style)

You get a `Q` from `$("...")` (searches all trees) or `$(node)` (wraps one/many).

### Traversal
```js
q.find("Ident")        // descendants matching selector
q.children(sel?)       // direct children (all, or matching)
q.named()              // named children only
q.child("field")       // children by field name
q.parent(sel?)         // parents
q.parents(sel?)        // all ancestors
q.closest(sel)         // nearest self-or-ancestor matching
q.next(sel?) / q.prev(sel?)
q.siblings(sel?)
```

### Filtering
```js
q.filter(sel | fn)     // keep matches
q.not(sel | fn)        // drop matches
q.has(sel)             // keep nodes with a descendant matching
q.is(sel | fn)         // boolean: any match?
q.first() / q.last() / q.eq(i) / q.slice(a, b)
q.add(otherQ | node | node[])
```

### Reading
```js
q.length
q.nodes                // the raw Node[]
q.each(fn)             // iterate
q.map(fn)              // map to values
q.get(i?)
q.text()               // first node's text
q.texts()              // all texts
q.type()               // first node's type
q.attr(field)          // first node's child-in-field text
q.loc()                // first node's {file, line, col, endLine}
q[Symbol.iterator]     // for..of works
```

### Example chain
```js
$("Call[callee=eval]")
  .parent()                 // the enclosing expression/statement
  .find("Ident")            // identifiers inside it
  .not("Ident[text=eval]")  // excluding the callee itself
  .texts()
```

---

## 4. Running chains in the UI console (`runChain`)

The UI console accepts a single input string parsed by `chain.ts`. Grammar:

```
$("<selector>") . method(args) . method(args) ...
```

- The initial `$("...")` argument **must be a quoted string**.
- Each method call uses **string or integer literals only** (no expressions, no `eval`).
- Only these methods are whitelisted:

| Method | Args | Maps to |
|---|---|---|
| `find` | `(sel)` | `q.find` |
| `children` | `(sel?)` | `q.children` |
| `named` | `()` | `q.named` |
| `child` | `(field)` | `q.child` |
| `parent` / `parents` / `closest` | `(sel?)` / `(sel?)` / `(sel)` | traversal |
| `next` / `prev` / `siblings` | `(sel?)` | traversal |
| `filter` / `not` / `has` | `(sel)` | filtering |
| `first` / `last` | `()` | slice |
| `eq` | `(int)` | index |
| `slice` | `(int?, int?)` | range |

**Bare selectors** (no `$(`) are also accepted — the whole input is treated as a selector.

### Console examples
```js
$("Call[callee*=query]").parent().find("Ident")
$("Call[callee=eval]").closest("Func").attr("name")
$("Ident[path^=req]").parents("Call").first()
$("Func[fname=login]").find("Str").texts()
$("Call[callee*=execute]").parent().prev("Assign")
```

The result `Q` is serialized by the server (`POST /api/projects/:id/query`) into rows with `file`, `type`, `line`, `text`, `parents`, etc.

---

## 5. Writing declarative queries (`defineQuery`)

Real detection rules live in `queries/*.ts` and export a default `defineQuery(...)`.

```ts
import { defineQuery } from "../src/query";

export default defineQuery({
  id: "js-eval",
  title: "Code injection via eval()",
  severity: "critical",
  cwe: "CWE-95",
  languages: ["javascript"],          // optional; default = all profiles
  taint: {                            // declarative taint spec (optional)
    sinks: {
      "*": [{ callee: /^eval$/, label: "eval()" }],
    },
    sanitizers: {
      "*": [/^(parseInt|Number)$/],
    },
  },
  message: (f) => `Untrusted input reaches ${f.label} at ${f.file}:${f.line}`,
});
```

### `QueryDef` fields

| Field | Purpose |
|---|---|
| `id`, `title`, `severity`, `cwe`, `description` | metadata |
| `languages` | restrict to profile names (`javascript`, `python`, `php`, `java`) |
| `taint` | a `FlowSpec` — source→sink analysis |
| `message(f)` | custom message for each `Flow` |
| `run(ctx)` | imperative query using `$`, `flows()`, `report()` |

### Imperative form
```ts
export default defineQuery({
  id: "js-hardcoded-secret",
  title: "Hardcoded secret",
  severity: "medium",
  run(ctx) {
    const q = ctx.$("Assign").filter((n) => {
      const a = ctx.profile(n).assign(n);
      if (!a) return false;
      const key = ctx.profile(n).pathOf(a.targets[0]) ?? "";
      return /secret|password|token/i.test(key) && a.value.type === "string";
    });
    q.each((n) => {
      const a = ctx.profile(n).assign(n)!;
      ctx.report(a.targets[0], `Hardcoded secret assigned to '${ctx.profile(n).pathOf(a.targets[0])}'`, {
        path: [step("sink", n)],
        severity: "medium",
      });
    });
  },
});
```

### `QueryCtx` surface

| Member | Description |
|---|---|
| `ctx.$` | `makeDollar(trees)` bound to the filtered trees |
| `ctx.trees` | `Tree[]` in scope |
| `ctx.profile(treeOrNode)` | language `Profile` |
| `ctx.flows(spec)` | run ad-hoc taint and return raw `Flow[]` |
| `ctx.report(node, message, {path?, severity?})` | emit a `Finding` |

### Taint spec (`FlowSpec`)

```ts
interface FlowSpec {
  sinks: PerLang<SinkSpec>;        // "*" or per-language
  sources?: PerLang<RegExp>;       // extra sources on top of built-ins
  sanitizers?: PerLang<RegExp>;    // neutralizers for this vuln class
  onlyCustomSources?: boolean;
}

interface SinkSpec {
  callee?: RegExp;                 // normalized callee
  assign?: RegExp;                 // assignment target path
  args?: number[];                 // which arg positions are dangerous
  when?: (c: CallInfo) => boolean;
  label?: string;
}
```

`PerLang<T>` is `{ "*": T[], javascript?: T[], python?: T[], php?: T[], java?: T[] }` — `"*"` always applies, the language key adds to it.

### Built-in sources (per language)
Each profile declares `sources: RegExp[]` matched against `pathOf()`:
- **JS**: `req.query.*`, `req.body.*`, `ctx.*`, `location.*`, `document.cookie`, `process.argv`, `event.data`
- **Python**: `request.args.*`, `request.json`, `input()`, `sys.argv`, `flask.request.*`
- **PHP**: `$_GET`, `$_POST`, `$request.input()`, `file_get_contents()`
- **Java**: `getParameter()`, `System.getenv()`, `scanner.nextLine()`, `@RequestParam`

### Built-in numeric sanitizers (per language)
Profiles also expose `numeric: RegExp` — callees that coerce to a number/bool and thus sanitize injection-style vulns: `parseInt`, `Number`, `int()`, `intval`, `Integer.parseInt`, etc. These are auto-applied as sanitizers in every `FlowSpec`.

### Taint engine guarantees
- Flow-insensitive across branches, but **source order aware** within a scope.
- **Function summaries** are computed to a fixpoint (3 passes) over the whole project, so cross-function and cross-file flows are found by name.
- Each `Flow.path` is a `Step[]`: `source → propagate → call → return → sanitizer → sink`, capped at 40 steps.
- `call.receiver` and unknown-callee args are treated as pass-through (string builders, `format`, `concat`, …).
- `Profile.safeCast` (e.g. PHP `(int)`) neutralizes taint everywhere.

---

## 6. Running queries

### CLI
```bash
bun run scan <dir> [query-id ...]
```
Indexes `<dir>`, runs all (or only the listed) queries, prints findings and a per-query summary.

### HTTP API
| Method + path | Purpose |
|---|---|
| `GET /api/info` | store kind, languages, extensions, loaded queries |
| `POST /api/queries/reload` | hot-reload `queries/*.ts` |
| `GET /api/queries/:id/source` | source of a query file |
| `GET/POST /api/projects` | list / create (with `path` or `files[]`) |
| `POST /api/projects/:id/scan` | run queries (`{queries?: string[]}`) |
| `GET /api/projects/:id/findings` | findings |
| `GET /api/projects/:id/sarif` | SARIF export |
| `POST /api/projects/:id/query` | run a **chain** (`{expr, limit}`) — returns matched nodes |
| `GET /api/projects/:id/nodes` | raw node search (`type`, `text`, `language`) |
| `GET /api/files/:id/ast` | AST JSON (`?all=1` includes unnamed nodes) |
| `GET /api/files/:id/source` | file source |

### Console → API
```
POST /api/projects/1/query
{ "expr": "$(\"Call[callee*=query]\").parent().find(\"Ident\")", "limit": 200 }
```
→ `{ total, ms, rows: [{file, fileId, language, type, field, line, col, endLine, text, parents}] }`

---

## 7. Recipe book

**Find SQL injection sinks in any language**
```js
$("Call[callee$=query]")
```

**Find eval / exec / system calls**
```js
$("Call[callee=eval], Call[callee=exec], Call[callee=system]")
```

**Find DOM XSS: assignment to innerHTML**
```js
$("Assign").has("Member[path$=innerHTML]")
```

**Find functions that call a dangerous API**
```js
$("Func:has(Call[callee=exec])").map((n) => n.child("name")?.text)
```

**Find string literals used as SQL**
```js
$("Str[text*=/select\\s+.+from/i]")
```

**Find parameters that reach a sink (via taint)**
```ts
ctx.flows({ sinks: { "*": [{ callee: /^exec$/ }] } })
```

**Find a project function called with tainted data**
The taint engine already resolves `lastSeg(callee)` to a project function's summary — a `flow` with a `call` step appears in `f.path`.

**Use `path` to find source reads**
```js
$("Ident[path^=req.query], Ident[path^=request.args]")
```

**Cross-language: any call whose callee ends in `execute`**
```js
$("Call[callee$=execute]")
```

**Filter to just one language in a chain**
Wrap with a selector on the tree — not directly expressible; instead write a `defineQuery` with `languages: ["python"]`, or in the console prepend a `Str`-free prefilter like `$("Func Call[callee=exec]")`.

---

## 8. Tips & gotchas

- **Strings in the console** must be quoted: `$('...')` or `$("...")`. Escaping inside the JSON is handled by the server.
- **No expressions** in chain args — `eq(2)` and `slice(0, 10)` work, but `eq(i+1)` does not.
- **`[callee=...]`** matches the *normalized* callee, not raw text. `db.query` is `db.query`, PHP member calls become `$obj.method`, `new File` keeps the `new ` prefix.
- **`[path=...]`** uses `Profile.pathOf` — identifiers, member chains, subscripts (`x[]`), and calls (`f()`).
- **Field attributes** (`[function="eval"]`) are language-specific — prefer `[callee=...]` for portability.
- **Abstract kinds** (`Call`, `Assign`, `Func`, …) only match nodes declared in the profile's `kinds` map. Use the concrete `type` when you need precision.
- **`:has(> sel)`** scopes to direct children; plain `:has(sel)` searches descendants.
- **Taint is name-based** for cross-function resolution — keep helper names unique, or add per-function `taintedParam` annotations in the profile.
- **`safeCast`** (PHP numeric casts) and **`numeric`** callees short-circuit taint; add to the profile rather than per-query when the language has many coercions.

---

## 9. Quick reference

```
$("Kind[attr=val] Descendant[callee*=x]").parent().find("Ident").texts()
```

- **Selector**: `Tag`, `[attr op value]`, `:pseudo(arg)`, combinators `space > + ~ ,`
- **Chain methods**: `find children named child parent parents closest next prev siblings filter not has first last eq slice`
- **Query def**: `defineQuery({ id, title, severity, cwe, languages?, taint?, message?, run? })`
- **Taint spec**: `sinks: PerLang<SinkSpec>`, `sources?`, `sanitizers?`, `onlyCustomSources?`
- **Context**: `ctx.$`, `ctx.trees`, `ctx.profile`, `ctx.flows(spec)`, `ctx.report(node, msg, opts)`
- **Run**: `bun run scan <dir>` or `POST /api/projects/:id/scan` / `/query`