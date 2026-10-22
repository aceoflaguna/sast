import { defineQuery } from "../src/query";
import { callRules, textRules, type CallRule } from "./_lib";

const ANY = /./;
const secretAt = (callee: RegExp, index: number): CallRule => ({ callee, arg: { index, re: ANY } });

export default defineQuery({
  id: "insecure-jwt",
  title: "Insecure JWT handling",
  severity: "high",
  cwe: "CWE-347",
  description: "Hard-coded signing key, 'none' algorithm accepted, or signature verification disabled.",
  run(ctx) {
    callRules(ctx, {
      javascript: [secretAt(/^(jwt|jsonwebtoken)\.(sign|verify)$/, 1)],
      python: [secretAt(/^jwt\.(encode|decode)$/, 1)],
      php: [secretAt(/^JWT\.(encode|decode)$/, 1)],
      ruby: [secretAt(/^JWT\.(encode|decode)$/, 1)],
      java: [secretAt(/(^|\.)signWith$/, 1), secretAt(/(^|\.)setSigningKey$/, 0), secretAt(/^Algorithm\.HMAC(256|384|512)$/, 0)],
    }, (_r, callee) => `Hard-coded JWT secret passed to ${callee}; load keys from a secret store.`);
    textRules(ctx, {
      javascript: [{ sel: "pair", re: /algorithms\s*:\s*\[[^\]]*['"]none['"]/i }],
      python: [{ sel: "Call", re: /jwt\.(decode|encode)[\s\S]*(verify_signature['"]\s*:\s*False|verify\s*=\s*False|algorithms?\s*=\s*(\[[^\]]*)?['"]none['"])/i }],
      php: [{ sel: "Call", re: /JWT::(decode|encode)\([^)]*\[\s*['"]none['"]/i }],
      ruby: [{ sel: "Call", re: /JWT\.decode\([^)]*,\s*(nil|false)\s*,\s*false/ }],
      csharp: [{ sel: "Call", re: /SymmetricSecurityKey\([^)]*GetBytes\(\s*"[^"]{3,}"/ }],
      go: [{ sel: "Call", re: /\.SignedString\(\s*\[\]byte\(\s*"/ }],
    }, () => "JWT signature verification disabled or hard-coded signing key.");
  },
});
