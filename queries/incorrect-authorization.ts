// queries/idor.ts
import { defineQuery } from "../src/query";

// Look for: Model.find(req.params.id) / .findById(req.params.id) / .get(pk=request.args['id'])
// WITHOUT a `.where(user_id: current_user.id)` or similar ownership clause in the same call chain.
const USER_INPUT_ID = /(req|request|ctx|params|query|body|args)\.(params|query|body|args|GET|POST)?\s*[\.\[]?\s*(id|userId|user_id|pk|key)\b/i;
const OWNERSHIP = /(user_id|userId|owner|current_user|currentUser|account_id|tenant|belongs_to|for_user|where\s*\(.*user)/i;

export default defineQuery({
  id: "idor",
  title: "Insecure direct object reference / IDOR",
  severity: "high",
  cwe: "CWE-639",
  description: "A user-controlled identifier fetches or mutates an object without an ownership/tenant check.",
  run({ $, profile, report }) {
    $("Call").each((n) => {
      const p = profile(n);
      const c = p.call(n);
      if (!c) return;
      // Only ORM-ish find/fetch/get calls
      if (!/\.(find|findByPk|findById|findOne|get|first|findUnique|findFirst|where)$/i.test(c.callee)) return;
      const argText = c.args.map((a) => a.text).join(" ");
      if (!USER_INPUT_ID.test(argText)) return;
      // Check the receiver chain and the whole call text for ownership constraints
      const full = c.node.text;
      if (OWNERSHIP.test(full)) return;
      // Avoid flagging if the enclosing function already constrains by the current user in a variable
      const enclosingFn = [...n.ancestors()].find((a) => p.func(a));
      const scopeText = enclosingFn?.text ?? "";
      if (OWNERSHIP.test(scopeText)) return;
      report(n, `Object fetched using user-supplied ID (${argText.trim().slice(0, 40)}) without an ownership filter.`);
    });
  },
});