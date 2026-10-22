import { defineQuery } from "../src/query";

export default defineQuery({
  id: "regex-injection",
  title: "Regular-expression injection / ReDoS",
  severity: "medium",
  cwe: "CWE-1333",
  taint: {
    sinks: {
      javascript: [{ callee: /^new RegExp$/, args: [0], label: "new RegExp" }],
      python: [{ callee: /^re\.(compile|match|search|fullmatch|findall|finditer|sub|split)$/, args: [0], label: "re.* pattern" }],
      php: [{ callee: /^preg_(match|match_all|replace|replace_callback|split|grep)$/, args: [0], label: "preg_*" }],
      java: [{ callee: /^Pattern\.(compile|matches)$/, args: [0], label: "Pattern.compile" }],
      go: [{ callee: /^regexp\.(MustCompile|Compile|MatchString|Match)$/, args: [0], label: "regexp.Compile" }],
      csharp: [{ callee: /^(new Regex|Regex\.(IsMatch|Match|Matches|Replace|Split))$/, args: [0, 1], label: "Regex" }],
      ruby: [{ callee: /^(Regexp\.new|Regexp\.compile)$/, args: [0], label: "Regexp.new" }],
    },
    sanitizers: {
      javascript: [/(^|\.)(escapeRegExp|escapeRegex|escape)$/], python: [/^re\.escape$/], php: [/^preg_quote$/], java: [/^Pattern\.quote$/],
      go: [/^regexp\.QuoteMeta$/], csharp: [/^Regex\.Escape$/], ruby: [/^Regexp\.(escape|quote)$/],
    },
  },
  message: (f) => `User input compiled as a regular expression (${f.label}); escape it or bound its length.`,
});
