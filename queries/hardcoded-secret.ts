import { defineQuery } from "../src/query";

const NAME = /(pass(word|wd)?|pwd|secret|api[_-]?key|token|private[_-]?key|access[_-]?key|client[_-]?secret|auth)/i;
const PLACEHOLDER = /^(\s*|x+|\*+|changeme|change_me|<.*>|\$\{.*\}|\{\{.*\}\}|todo|none|null|example|your[_-].*)$/i;
const TOKENS: [string, RegExp][] = [
  ["AWS access key id", /AKIA[0-9A-Z]{16}/], ["GitHub token", /gh[pousr]_[A-Za-z0-9]{36,}/],
  ["Slack token", /xox[baprs]-[A-Za-z0-9-]{10,}/], ["Private key block", /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ["Stripe live key", /sk_live_[A-Za-z0-9]{16,}/],
];

/** Imperative example: pure jQuery-style traversal, no taint engine. */
export default defineQuery({
  id: "hardcoded-secret",
  title: "Hard-coded secret",
  severity: "medium",
  cwe: "CWE-798",
  run({ $, profile, report }) {
    // 1. name = "literal"   (variable declarations and assignments in every language)
    $("Assign").each((n) => {
      const p = profile(n);
      const r = p.assign(n);
      for (const a of r ? (Array.isArray(r) ? r : [r]) : []) {
        const lit = p.stringValue(a.value);
        if (lit == null || lit.length < 4 || PLACEHOLDER.test(lit)) continue;
        const name = a.targets.map((t) => p.pathOf(t) ?? "").find((x) => NAME.test(x));
        if (name) report(n, `Credential-like variable '${name}' is assigned a string literal.`);
      }
    });
    // 2. well-known token formats inside any string
    $("Str").each((n) => {
      for (const [label, re] of TOKENS) if (re.test(n.text)) report(n, `${label} found in source.`, { severity: "high" });
    });
  },
});
