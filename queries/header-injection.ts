import { defineQuery } from "../src/query";

export default defineQuery({
  id: "header-injection",
  title: "HTTP response header injection",
  severity: "medium",
  cwe: "CWE-113",
  taint: {
    sinks: {
      javascript: [{ callee: /^(res|response)\.(setHeader|set|header|append|writeHead|cookie)$/, args: [1], label: "response header" }],
      python: [{ assign: /^(response|resp|r)\.headers\[\]$/, label: "response.headers[...]" }, { callee: /^(response|resp)\.headers\.(add|set|setdefault)$/, args: [1], label: "response header" }],
      php: [{ callee: /^header$/, when: (c) => !/location/i.test(c.node.text), label: "header()" }],
      java: [{ callee: /\.(addHeader|setHeader|addCookie)$/, args: [1, 0], label: "response header" }],
      go: [{ callee: /\.Header\(\)\.(Set|Add)$/, args: [1], label: "w.Header().Set" }],
      csharp: [{ callee: /(^|\.)Response\.(AppendHeader|AddHeader|Headers\.Add|Headers\.Append)$/, args: [1], label: "response header" }],
      ruby: [{ assign: /^(response\.)?headers(\(\))?\[\]$/, label: "response.headers[...]" }],
    },
    sanitizers: { "*": [/(^|\.)(replace|replaceAll|gsub|encodeURIComponent|URLEncoder\.encode|urlencode|rawurlencode|Replace|UrlEncode)$/] },
  },
  message: (f) => `Untrusted input is placed in a header (${f.label}); strip CR/LF.`,
});
