import { defineQuery } from "../src/query";
import { textRules } from "./_lib";

export default defineQuery({
  id: "cors-misconfiguration",
  title: "Permissive CORS policy",
  severity: "medium",
  cwe: "CWE-942",
  description: "Any origin is allowed to read responses from this service.",
  // The classic variant: the request's Origin header is echoed back, so *every* origin is allowed (with credentials!).
  taint: {
    sinks: {
      javascript: [{ callee: /^(res|response|ctx)\.(setHeader|header|set|append|writeHead)$/, when: (c) => /Access-Control-Allow-Origin/i.test(c.node.text), label: "Access-Control-Allow-Origin header" }],
      python: [{ callee: /\.headers\.(add|set|setdefault)$|^(make_response|HttpResponse)$/, when: (c) => /Access-Control-Allow-Origin/i.test(c.node.text), label: "Access-Control-Allow-Origin header" }],
      php: [{ callee: /^header$/, when: (c) => /Access-Control-Allow-Origin/i.test(c.node.text), label: "Access-Control-Allow-Origin header" }],
      java: [{ callee: /\.(setHeader|addHeader)$/, when: (c) => /Access-Control-Allow-Origin/i.test(c.node.text), label: "Access-Control-Allow-Origin header" }],
      go: [{ callee: /\.Header\(\)\.(Set|Add)$|^(c|ctx)\.(Header|Writer\.Header\(\)\.Set)$/, when: (c) => /Access-Control-Allow-Origin/i.test(c.node.text), label: "Access-Control-Allow-Origin header" }],
      csharp: [{ callee: /(^|\.)Headers\.(Add|Append)$/, when: (c) => /Access-Control-Allow-Origin/i.test(c.node.text), label: "Access-Control-Allow-Origin header" }],
    },
  },
  message: (f) => `Request data is reflected into ${f.label}: every origin is trusted. Match the Origin against an allow-list instead.`,
  run(ctx) {
    textRules(ctx, {
      javascript: [
        { sel: "Call", re: /Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"]/ },
        { sel: "pair", re: /^["']?origin["']?\s*:\s*(['"]\*['"]|true\b)/ },
      ],
      python: [
        { sel: "Call", re: /origins?\s*=\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"]/ },
        { sel: "Assign", re: /Access-Control-Allow-Origin['"]\]\s*=\s*['"]\*['"]/ },
      ],
      php: [{ sel: "Call", re: /header\(\s*['"]Access-Control-Allow-Origin:\s*\*/i }],
      java: [{ sel: "Call", re: /(addAllowedOrigin|allowedOrigins?)\(\s*"\*"\s*\)|Access-Control-Allow-Origin"\s*,\s*"\*"/ }],
      go: [{ sel: "Call", re: /Access-Control-Allow-Origin["']\s*,\s*["']\*["']/ }, { sel: "composite_literal", re: /AllowAllOrigins\s*:\s*true/ }],
      csharp: [{ sel: "Call", re: /AllowAnyOrigin\(\)|WithOrigins\(\s*"\*"\s*\)/ }, { sel: "Assign", re: /Access-Control-Allow-Origin["']\]\s*=\s*["']\*["']/ }],
      ruby: [{ sel: "Call", re: /^origins\s+['"]\*['"]/ }, { sel: "Assign", re: /Access-Control-Allow-Origin["']\]\s*=\s*["']\*["']/ }],
    }, () => "CORS allows any origin ('*').");
  },
});
