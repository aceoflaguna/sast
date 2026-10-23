// queries/improper-input-validation.ts
import { defineQuery } from "../src/query";

const NUMERIC_SOURCE = /(parseInt|Number|int\(|Integer\.|to_i|strconv\.Atoi|atoi|intval)/;
const BOUNDS = /(>=\s*0|<\s*|length|size|count|bound|limit|max|min|clamp|Math\.(min|max))/i;

export default defineQuery({
  id: "improper-input-validation",
  title: "Unvalidated numeric input used as index/size",
  severity: "medium",
  cwe: "CWE-20",
  description: "A request-derived integer is used for array indexing, allocation, or loop bounds without range checking.",
  run({ $, profile, report }) {
    // Array index: arr[req.params.i] or arr[parseInt(req.query.n)]
    $("Member").each((n) => {
      const p = profile(n);
      const obj = p.memberObject(n);
      if (!obj) return;
      const idx = n.childrenByField("index").concat(n.childrenByField("subscript"))[0];
      if (!idx) return;
      if (!NUMERIC_SOURCE.test(idx.text) && !/(req|request|ctx|params|query)/i.test(idx.text)) return;
      const scope = [...n.ancestors()].find((a) => p.func(a))?.text ?? "";
      if (BOUNDS.test(scope)) return;
      report(n, `Array index from user input (${idx.text.slice(0, 40)}) lacks visible bounds checking.`);
    });

    // Allocation: new Array(n) / Buffer.alloc(n) / [n] with user-derived n
    $("Call").each((n) => {
      const p = profile(n);
      const c = p.call(n);
      if (!c) return;
      if (!/^(new Array|Buffer\.alloc|Buffer\.allocUnsafe|new Buffer|calloc|malloc)$/.test(c.callee)) return;
      const sizeArg = c.args[0];
      if (!sizeArg || !NUMERIC_SOURCE.test(sizeArg.text)) return;
      const scope = [...n.ancestors()].find((a) => p.func(a))?.text ?? "";
      if (BOUNDS.test(scope)) return;
      report(n, `Buffer/array sized by user input (${sizeArg.text.slice(0, 40)}) without a maximum cap.`);
    });
  },
});