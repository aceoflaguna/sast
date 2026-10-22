import { defineQuery } from "../src/query";
import { textRules } from "./_lib";

/** Flags cookies that are *explicitly* configured without Secure / HttpOnly (low noise: framework defaults are not guessed). */
export default defineQuery({
  id: "insecure-cookie",
  title: "Cookie without Secure / HttpOnly",
  severity: "medium",
  cwe: "CWE-614",
  description: "A cookie is explicitly configured with Secure or HttpOnly turned off, exposing it to network sniffing or script access.",
  run(ctx) {
    textRules(ctx, {
      javascript: [{ sel: "pair", re: /^["']?(secure|httpOnly)["']?\s*:\s*false\b/ }],
      python: [
        { sel: "Call", re: /set_cookie\([\s\S]*\b(secure|httponly)\s*=\s*False/i },
        { sel: "Assign", re: /(SESSION|CSRF|REMEMBER)_COOKIE_(SECURE|HTTPONLY)['"]?\]?\s*=\s*False/ },
      ],
      php: [
        { sel: "Call", re: /ini_set\(\s*['"]session\.cookie_(secure|httponly)['"]\s*,\s*(false|0|['"](0|off|false)['"])/i },
        { sel: "Call", re: /session_set_cookie_params\([^)]*\b(false|0)\s*,\s*(false|0)\s*\)/i },
      ],
      java: [{ sel: "Call", re: /\.set(Secure|HttpOnly)\(\s*false\s*\)/ }],
      go: [{ sel: "composite_literal", re: /\b(Secure|HttpOnly)\s*:\s*false\b/ }],
      csharp: [
        { sel: "Call", re: /CookieOptions[\s\S]*\b(Secure|HttpOnly)\s*=\s*false\b/ },
        { sel: "Assign", re: /\.(Secure|HttpOnly)\s*=\s*false\b|SecurePolicy\s*=\s*CookieSecurePolicy\.None/ },
      ],
      ruby: [{ sel: "pair", re: /^(secure|http_?only)\W{0,3}\s*(=>)?\s*false/i }],
    }, (_r, n) => `Cookie configured with ${/http_?only/i.test(n.text) ? "HttpOnly" : "Secure"} disabled.`);
  },
});
