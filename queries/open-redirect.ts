import { defineQuery } from "../src/query";

export default defineQuery({
  id: "open-redirect",
  title: "Open redirect",
  severity: "medium",
  cwe: "CWE-601",
  taint: {
    sinks: {
      javascript: [{ callee: /^(res|response)\.redirect$/, label: "res.redirect" }, { assign: /^(window\.)?location(\.href)?$/, label: "location assignment" }],
      python: [{ callee: /^(flask\.)?redirect$/, args: [0], label: "redirect()" }, { callee: /^HttpResponseRedirect$/, args: [0], label: "HttpResponseRedirect" }],
      php: [{ callee: /^header$/, label: "header(Location)", when: (c) => /location/i.test(c.node.text) }],
      java: [{ callee: /\.sendRedirect$/, label: "sendRedirect" }],
      go: [{ callee: /^http\.Redirect$/, label: "http.Redirect" }, { callee: /^(c|ctx)\.Redirect$/, label: "c.Redirect" }],
      csharp: [{ callee: /^((this|HttpContext)\.)?(Response\.)?(Redirect|RedirectPermanent)$/, label: "Redirect()" }, { callee: /^new RedirectResult$/, label: "RedirectResult" }],
      ruby: [{ callee: /^(redirect_to|redirect_back|redirect)$/, args: [0], label: "redirect_to" }],
    },
  },
  message: (f) => `User input controls a redirect target via ${f.label}.`,
});
