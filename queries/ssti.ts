import { defineQuery } from "../src/query";

export default defineQuery({
  id: "ssti",
  title: "Server-side template / expression injection",
  severity: "critical",
  cwe: "CWE-1336",
  description: "User input is compiled as a template or expression language, usually leading to remote code execution.",
  taint: {
    sinks: {
      javascript: [{ callee: /^(ejs\.render|pug\.(render|compile)|handlebars\.compile|Handlebars\.compile|nunjucks\.renderString|_\.template|lodash\.template|doT\.template|mustache\.render|dust\.renderSource)$/, args: [0], label: "template compile" }],
      python: [
        { callee: /^((jinja2|mako\.template)\.)?Template$/, args: [0], label: "Jinja2/Mako Template()" },
        { callee: /(^|\.)from_string$/, args: [0], label: "Environment.from_string" },
      ],
      php: [{ callee: /(^|\.)(createTemplate|renderString|fetchString)$/, args: [0], label: "Twig/Smarty string template" }],
      java: [
        { callee: /^new Template$/, label: "FreeMarker Template" },
        { callee: /^Velocity\.evaluate$/, label: "Velocity.evaluate" },
        { callee: /(^|\.)(parseExpression|getValue)$/, when: (c) => /(parser|expression|spel|ognl|mvel)/i.test(c.callee), label: "SpEL / OGNL expression" },
        { callee: /^(Ognl|MVEL)\.(getValue|eval)$/, label: "OGNL / MVEL" },
      ],
      csharp: [{ callee: /^(Razor|Engine\.Razor|Template|Scriban\.Template|Handlebars)\.(Parse|Compile|RunCompile)$/, args: [0], label: "Razor / Scriban / Handlebars compile" }],
      go: [{ callee: /template\.New\(\)\.Parse$|^(t|tmpl|tpl)\.Parse$/, label: "template.Parse" }],
      ruby: [{ callee: /^(ERB\.new|Liquid\.Template\.parse|Slim\.Template\.new|Haml\.Engine\.new)$/, args: [0], label: "ERB / Liquid template" }, { callee: /^render\.(inline|template)$/, label: "render inline:" }],
    },
  },
  message: (f) => `User input is compiled as a template via ${f.label}.`,
});
