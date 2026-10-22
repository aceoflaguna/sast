import { Parser, Language } from "web-tree-sitter";
await Parser.init();
const [,, file, code] = process.argv;
const lang = await Language.load(`node_modules/tree-sitter-wasms/out/tree-sitter-${file}.wasm`);
const p = new Parser(); p.setLanguage(lang);
const t = p.parse(code)!;
const c = t.walk();
let depth = 0;
function visit() {
  while (true) {
    if (c.nodeIsNamed) {
      const n = c.currentNode;
      const leaf = n.namedChildCount === 0 ? "  «" + n.text.slice(0,40).replace(/\n/g,"⏎") + "»" : "";
      console.log("  ".repeat(depth) + (c.currentFieldName ? c.currentFieldName + ": " : "") + n.type + leaf + `  [${n.startIndex}-${n.endIndex}]`);
    }
    if (c.gotoFirstChild()) { if (c.nodeIsNamed || true) depth++; visit(); c.gotoParent(); depth--; }
    if (!c.gotoNextSibling()) break;
  }
}
visit();
