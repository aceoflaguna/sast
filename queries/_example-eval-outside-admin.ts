import { defineQuery } from "../src/query";
// Example (ignored by the loader because of the leading underscore): taint flows post-filtered with traversal.
export default defineQuery({
  id: "eval-outside-admin", title: "eval of user input outside admin()", severity: "high",
  run({ $, flows, report }) {
    for (const f of flows({ sinks: { "*": [{ callee: /^eval$/ }] } }))
      if ($(f.sink).closest("Func[fname=admin]").length === 0) report(f.sink, "eval of user input outside admin()", { path: f.path });
  },
});
