# Adding a new language

Adding a language touches **five** places. The whole point of the `Profile` abstraction is that once those five are done, **every existing query works on the new language for free** (any `[callee=...]`, `[path^=...]`, `Call`, `Assign`, `Func`, `Str`, `Ident`, `Member`, `Return`, `Class`, taint, `:has`, etc.).

Here's the checklist, using **Go** (`tree-sitter-go`) as a worked example.

---

## 1. Register the grammar (WASM) in `parser.ts`

`parser.ts` already has `LANGS` mapping language name → `{ wasm, exts }`. Add an entry:

```ts
export const LANGS: Record<string, { wasm: string; exts: string[] }> = {
  javascript: { wasm: "tree-sitter-javascript.wasm", exts: [".js", ".mjs", ".cjs", ".jsx"] },
  typescript: { wasm: "tree-sitter-typescript.wasm", exts: [".ts", ".mts", ".cts"] },
  tsx:        { wasm: "tree-sitter-tsx.wasm",        exts: [".tsx"] },
  python:     { wasm: "tree-sitter-python.wasm",     exts: [".py"] },
  php:        { wasm: "tree-sitter-php.wasm",        exts: [".php", ".phtml"] },
  java:       { wasm: "tree-sitter-java.wasm",       exts: [".java"] },
  go:         { wasm: "tree-sitter-go.wasm",         exts: [".go"] },   // ← new
};
```

`detectLanguage()` and `parseToRows()` need no changes — they iterate `LANGS` and `Language.load(path.join(wasmDir, LANGS[name].wasm))`.

### Where does the WASM come from?

`parser.ts` resolves WASM from `tree-sitter-wasms/out`. That package ships prebuilt grammars. Check it has yours:

```bash
ls node_modules/tree-sitter-wasms/out | grep -i go
# tree-sitter-go.wasm
```

If it doesn't, install a package that provides it, or compile one yourself:

```bash
# Option A: prebuilt from the tree-sitter-wasms package family
bun add -d tree-sitter-wasms   # check `out/` for the file

# Option B: build from the grammar source
git clone https://github.com/tree-sitter/tree-sitter-go
cd tree-sitter-go
bunx tree-sitter-cli build --wasm
cp tree-sitter-go.wasm <project>/node_modules/tree-sitter-wasms/out/
```

If the file lives elsewhere, adjust `wasmDir` in `parser.ts` (or make it per-language):

```ts
const wasmDir = path.join(path.dirname(require.resolve("tree-sitter-wasms/package.json")), "out");
```

The version of the WASM **must match** the `web-tree-sitter` version's ABI. Mismatched ABI gives you a `Language.load` failure at startup — that's the usual first symptom.

---

## 2. Create the Profile file `src/lang/go.ts`

This is the whole game. The `Profile` interface (`src/lang/types.ts`) has 12 members. Only `kinds`, `call`, `assign`, `func`, `ret`, `pathOf`, `memberObject`, `sources`, `numeric`, `stringValue` are required; the rest (`exprChildren`, `safeCast`, `taintedParam`) are optional.

The trick: **inspect the actual tree-sitter grammar output** before writing it. Easiest way is your own UI:

```bash
# index a tiny Go project first
bun run scan ./sample-go  # or POST /api/projects {path: "./sample-go"}

# then dump the AST of one file (unnamed nodes included)
curl 'http://127.0.0.1:3000/api/files/<fileId>/ast?all=1' | jq
```

or the console:

```
$("call_expression").first().parents()      // what wraps a call in Go?
```

Here's a skeleton based on `tree-sitter-go`'s node names:

```ts
// src/lang/go.ts
import type { Node } from "../node";
import type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
import { named, collect } from "./common";

function pathOf(n: Node | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "package_identifier": return n.text;
    case "field_identifier": return n.text;
    case "selector_expression": {          // pkg.Fn, recv.Method
      const o = pathOf(n.child("operand"));
      const f = n.child("field");
      return o && f ? `${o}.${f.text}` : null;
    }
    case "index_expression": {             // arr[i]
      const o = pathOf(n.child("operand"));
      return o ? `${o}[]` : null;
    }
    case "call_expression": {              // fn(...)
      const f = pathOf(n.child("function"));
      return f ? `${f}()` : null;
    }
    case "parenthesized_expression": case "unary_expression":
      return pathOf(named(n)[0]);
  }
  return null;
}

function nameOfFunc(n: Node): string | null {
  const nm = n.child("name");
  if (nm) return nm.text;
  // method_declaration has receiver + name; func_literal has no name
  return null;
}

export const go: Profile = {
  name: "go",
  kinds: {
    Call:   ["call_expression"],
    Assign: ["short_var_declaration", "assignment_statement", "var_declaration", "const_declaration"],
    Func:   ["function_declaration", "method_declaration", "func_literal"],
    Ident:  ["identifier", "field_identifier", "package_identifier"],
    Str:    ["interpreted_string_literal", "raw_string_literal"],
    Member: ["selector_expression", "index_expression"],
    Return: ["return_statement"],
    Class:  ["type_declaration", "type_spec"],          // closest analogue
  },

  pathOf,
  memberObject: (n) =>
    n.type === "selector_expression" ? n.child("operand")
    : n.type === "index_expression"  ? n.child("operand")
    : null,

  call(n): CallInfo | null {
    if (n.type !== "call_expression") return null;
    const f = n.child("function");
    if (!f) return null;
    return {
      node: n,
      callee: pathOf(f) ?? f.text.slice(0, 60),
      receiver: f.type === "selector_expression" ? f.child("operand") : null,
      args: named(n.child("arguments")),
    };
  },

  assign(n): AssignInfo | null {
    if (n.type === "short_var_declaration") {           // a, b := v
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      return { node: n, targets: collect(l, ["identifier"]), value: r, compound: false };
    }
    if (n.type === "assignment_statement") {            // a, b = v   (also +=)
      const l = n.child("left"), r = n.child("right");
      if (!l || !r) return null;
      return {
        node: n, targets: collect(l, ["identifier"]),
        value: r,
        compound: !/^\s*=\s*$/.test(n.tree.source.slice(l.row.eb, r.row.sb)),
      };
    }
    if (n.type === "var_declaration" || n.type === "const_declaration") {
      // var_spec ( name value? ) — grab the first spec
      const spec = named(n).find((k) => k.type === "var_spec" || k.type === "const_spec");
      if (!spec) return null;
      const names = spec.childrenByField("name");
      const v = spec.child("value");
      if (!names.length || !v) return null;
      return { node: n, targets: names, value: v, compound: false };
    }
    if (n.type === "for_statement" || n.type === "range_clause") {
      const l = n.child("left"), r = n.child("right");
      if (l && r) return { node: n, targets: collect(l, ["identifier"]), value: r, compound: false };
    }
    return null;
  },

  func(n): FuncInfo | null {
    if (!["function_declaration", "method_declaration", "func_literal"].includes(n.type)) return null;
    const body = n.child("body");
    if (!body) return null;
    const ps = n.child("parameters");
    const list: { key: string; node: Node }[] = [];
    for (const p of named(ps)) {
      const id = p.type === "parameter_declaration" ? p.child("name") : null;
      list.push({ key: id?.text ?? `#${list.length}`, node: p });
    }
    return { node: n, name: nameOfFunc(n), params: list, body, exprBody: body.type !== "block" };
  },

  ret: (n) => (n.type === "return_statement" ? named(n)[0] ?? null : null),

  // Go doesn't have request-declaration annotations; skip.
  // taintedParam: (p) => false,

  sources: [
    /^(r|req|request)\.(URL|Body|Form|PostForm|MultipartForm|Header|Host|RemoteAddr|RequestURI)\b/,
    /^os\.(Args|Getenv)$/,
    /^flag\.Args$/,
    /^(bufio\.NewScanner|os\.Stdin)\b/,
  ],
  numeric: /^(strconv\.(Atoi|ParseInt|ParseFloat|ParseBool|ParseUint)|int|int64|int32|float64|float32|uint|uint64|uint32|len|cap)$/,

  stringValue(n) {
    if (n.type === "interpreted_string_literal") return n.text.slice(1, -1);
    if (n.type === "raw_string_literal") return n.text.slice(1, -1);
    return null;
  },
};
```

**How to verify each field against the real grammar**

| Field | Check |
|---|---|
| `kinds` | `$("Call").length > 0` on a Go file after indexing. Same for each other kind. |
| `pathOf` | `$("Ident[path~=req]").texts()` — should return `req.URL`, `req.Body`, … |
| `call` | `$("Call").map(n => ctx.profile(n).call(n)?.callee)` — should be `fmt.Println`, `db.Query`, … |
| `assign` | `$("Assign").map(n => ctx.profile(n).assign(n)?.targets.map(t=>t.text))` |
| `func` | `$("Func").map(n => ctx.profile(n).func(n)?.name)` — should list `main`, `handler`, … |
| `ret` | `$("Return").length` and `.texts()` |
| `stringValue` | `$("Str").map(n => ctx.profile(n).stringValue(n))` |

Once those look right, the profile is done. Everything below is essentially automatic.

---

## 3. Register the profile in `src/lang/index.ts`

```ts
import type { Profile } from "./types";
import { javascript } from "./javascript";
import { python } from "./python";
import { php } from "./php";
import { java } from "./java";
import { go } from "./go";              // ← new

const byParser: Record<string, Profile> = {
  javascript, typescript: javascript, tsx: javascript,
  python, php, java, go,                // ← new (key = grammar name from LANGS)
};

export function profileFor(parserLanguage: string): Profile {
  const p = byParser[parserLanguage];
  if (!p) throw new Error("No profile for language " + parserLanguage);
  return p;
}
export const profiles = { javascript, python, php, java, go };  // ← add
export type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
```

Note the key `go` in `byParser` must match the key in `LANGS` from step 1. If you add `.tsx` → `tsx` grammar but reuse the `javascript` profile, that's exactly what's happening here (`tsx: javascript`).

---

## 4. (Optional) bump `detectLanguage` extensions

Only if your language has extra extensions or needs to be detected under a different name. Go is `.go` only, so step 1 is enough. For e.g. C# you'd add `".cs"`, `".csx"` to the `LANGS` entry.

---

## 5. Verify

```bash
# 1. index a small sample
bun run scan ./sample-go
# → indexed N files, M AST nodes into ...

# 2. exercise the profile from the UI console (POST /api/projects/:id/query)
$("Call").first().attr("function")          // raw field name in this grammar
$("Call").map(n => n.text).slice(0,5)       // call sites
$("Func").map(n => n.child("name")?.text)   // function names

# 3. language-neutral attributes
$("Call[callee$=Query]")                    // db.Query, tx.Query, ...
$("Ident[path^=req.]")                      // request paths
$("Func[fname=handler]")                    // abstract Func kind + fname

# 4. every existing query now runs against Go too
bun run scan ./sample-go sql-injection command-injection ssrf
```

After that, every query in `queries/` applies to Go automatically:
- `Call[callee=eval]` — no-op for Go, but `Call[callee$=Query]` works
- `sql-injection.ts` / `ssrf.ts` / `command-injection.ts` — fire wherever the Go callees match the regexes
- `hardcoded-secret.ts` — `Assign` + `stringValue` + `pathOf` all work; `Str` matching works
- `path-traversal.ts` — add Go-specific sinks (`os.Open`, `os.ReadFile`, `ioutil.ReadFile`) to the `sinks` map
- `eval-outside-admin.ts` — `$("Func[fname=admin]")` resolves to Go's `function_declaration` with name `admin`, so the scope filter works

---

## Extending a query to a new language

Queries are language-agnostic by design, but sink lists are regexes. To add Go-specific sinks, edit the relevant query — e.g. `sql-injection.ts`:

```ts
taint: {
  sinks: {
    javascript: [...],
    python: [...],
    php: [...],
    java: [...],
    go: [
      { callee: /\.(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Scan)$/, args: [0], label: "database/sql" },
      { callee: /^gorm\.(Raw|Exec)$/, args: [0], label: "gorm" },
      { callee: /\.(Where|Raw|Exec)$/, args: [0], label: "gorm chain" },
    ],
  },
},
```

and `ssrf.ts`:

```ts
go: [
  { callee: /^http\.(Get|Post|Head|PostForm|NewRequest)$/, args: [0, 1], label: "net/http client" },
  { callee: /\.(Do|Get|Post)$/, args: [0], label: "http client method" },
],
```

Same pattern for `command-injection.ts`:

```ts
go: [
  { callee: /^exec\.(Command|CommandContext)$/, args: [0, 1], label: "os/exec" },
  { callee: /^syscall\.Exec$/, label: "syscall.Exec" },
],
```

That's it — no query file needs structural edits, only sink regexes, because `sinks: PerLang<SinkSpec>` already namespaces by language name (`"go"`).

---

## Caveats / things that bite

1. **Grammar ABI.** `web-tree-sitter` and the `.wasm` must be compatible. Bumping one requires bumping the other. `Language.load` failing with `Invalid language` = ABI mismatch.

2. **`named` / `field` names vary by grammar.** Your `profile.*` code must use the *actual* field names the grammar emits (`n.child("operand")` vs `n.child("object")`). Confirm with the `?all=1` AST dump, not by assumption.

3. **`pathOf` is the single most important method.** Almost every sink regex is matched against it. If it doesn't produce the shape you expect (dotted path, `[]` for subscripts, `()` for calls), the taint engine misses everything. Prefer testing it early.

4. **Abstract `Class` is optional.** Go has no classes — map it to `type_declaration` only if any query uses `Class`. Grep:

   ```bash
   grep -R "Class" queries/ src/taint.ts
   ```
   If nothing uses it, omit the key — queries that ask for `Class` will just match nothing in Go, which is correct.

5. **`taintedParam` is language-specific.** Spring uses `@RequestParam`, Python uses `request.args` reads, Go has neither. Omit it for Go; declarative sources cover the common cases.

6. **Sink arg indices.** `args: [0]` refers to the **position in `CallInfo.args`**, which is `named(arguments_child)`. For Go that's `call_expression > argument_list > ...` and matches caller intuition, but for grammars where `arguments` includes commas (PHP's `argument_list` is named-only in this parser, so fine) re-verify with `$("Call").map(n => profile(n).call(n)?.args.length)`.

7. **`declarative vs imperative`.** `QueryDef.languages` restricts by `profileFor(tree.language).name` — so a query with `languages: ["javascript"]` will not run on `typescript`/`tsx` (different tree language) even though both use the `javascript` profile. That's a pre-existing inconsistency; if you're adding TSX/TS coverage for an existing JS query, use `languages: ["javascript", "typescript", "tsx"]` or omit `languages` and rely on `"*"` sinks.

8. **`store.searchNodes`** and `GET /api/projects/:id/nodes?language=go` will now work because `files.language` is whatever `detectLanguage` returned, which is `go`.

---

## TL;DR checklist

```
[ ] 1. parser.ts     — add LANGS[name] = { wasm, exts }        (+ ensure the .wasm exists)
[ ] 2. lang/go.ts    — implement Profile (kinds, call, assign, func, ret,
                        pathOf, memberObject, sources, numeric, stringValue)
[ ] 3. lang/index.ts — add `go` to byParser and to `profiles`
[ ] 4. verify        — index a sample; $("Call"), $("Func[fname=…]"),
                        $("Ident[path^=…]") return sane results
[ ] 5. queries/*.ts  — add per-language sink regexes under `go:`
                        (SQL, SSRF, cmd, path traversal, deserialization …)
```

After step 3, the language is fully integrated: `bun run scan`, `POST /scan`, the SARIF export, the AST/source endpoints, the chain console, and every structural query (`hardcoded-secret`, `eval-outside-admin`, `debug-enabled`, `binding-all-interfaces`, …) work with no further changes. Only *taint* queries need the per-language sink regex additions in step 5.