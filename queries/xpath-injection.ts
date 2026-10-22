import { defineQuery } from "../src/query";

export default defineQuery({
  id: "xpath-injection",
  title: "XPath injection",
  severity: "high",
  cwe: "CWE-643",
  taint: {
    sinks: {
      javascript: [{ callee: /^(xpath\.(select\d?|evaluate|parse)|\w+\.(selectNodes|evaluate))$/, args: [0], label: "XPath evaluate" }],
      python: [{ callee: /(^|\.)(xpath|XPath)$/, args: [0], label: "xpath()" }],
      php: [{ callee: /(^|\.)(xpath)$/, args: [0], label: "xpath()" }, { callee: /^\$?(xp|xpath|domxpath)\.(query|evaluate)$/i, args: [0], label: "DOMXPath" }],
      java: [{ callee: /^(xp|xpath|xPath|XPath\w*)\.(evaluate|compile)$/, args: [0], label: "XPath evaluate/compile" }],
      csharp: [{ callee: /(^|\.)(SelectNodes|SelectSingleNode|XPathSelectElements?|XPathEvaluate|Evaluate)$/, args: [0], label: "XPath select" }],
      go: [{ callee: /^(xpath|xmlquery|htmlquery|xmlpath)\.\w+$/, label: "XPath query" }],
      ruby: [{ callee: /(^|\.)(xpath|at_xpath)$/, args: [0], label: "Nokogiri xpath" }],
    },
  },
  message: (f) => `User input is concatenated into an XPath expression (${f.label}); use parameterized XPath / variable resolvers.`,
});
