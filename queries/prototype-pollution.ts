import { defineQuery } from "../src/query";

export default defineQuery({
  id: "prototype-pollution",
  title: "Prototype pollution",
  severity: "high",
  cwe: "CWE-1321",
  languages: ["javascript"],
  description: "Request data is deep-merged into an object or used as a property path, allowing __proto__ writes.",
  taint: {
    sinks: {
      javascript: [
        { callee: /^(_|lodash|\$)\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep|extend)$/, label: "deep merge / set" },
        { callee: /^(merge|deepmerge|deepMerge|deepExtend|extend|mixin|defaultsDeep|hoek\.merge|Hoek\.merge)$/, label: "recursive merge" },
      ],
    },
  },
  message: (f) => `Untrusted object flows into ${f.label}; reject __proto__/constructor keys or use Object.create(null).`,
});
