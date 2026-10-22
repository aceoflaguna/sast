import { defineQuery } from "../src/query";
import { callRules, textRules, type CallRule } from "./_lib";

const WEAK_NAME = /(^|[^a-z])(des|des3|3des|desede|rc2|rc4|arcfour|blowfish|bf)([^a-z]|$)|ecb/i;
const lit = (callee: RegExp, index = 0, re = WEAK_NAME): CallRule => ({ callee, arg: { index, re } });

export default defineQuery({
  id: "weak-cipher",
  title: "Weak cipher or ECB mode",
  severity: "medium",
  cwe: "CWE-327",
  description: "DES/3DES/RC2/RC4/Blowfish or ECB mode provide inadequate confidentiality.",
  run(ctx) {
    callRules(ctx, {
      javascript: [{ callee: /^crypto\.createCipher$/, note: "deprecated, no IV" }, lit(/^crypto\.createCipheriv$/)],
      python: [{ callee: /(^|\.)(DES|DES3|ARC4|ARC2|Blowfish|CAST)\.new$/ }, { callee: /(^|\.)AES\.new$/, when: (n) => /MODE_ECB/.test(n.text) }],
      php: [lit(/^openssl_(en|de)crypt$/, 1), { callee: /^mcrypt_\w+$/ }],
      java: [lit(/^Cipher\.getInstance$/, 0, /^(DES|DESede|RC2|RC4|ARCFOUR|Blowfish)\b|\/ECB\/|^AES$|^AES\/ECB/i)],
      go: [{ callee: /^(des\.(NewCipher|NewTripleDESCipher)|rc4\.NewCipher)$/ }],
      csharp: [{ callee: /^new (DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)$/ }, { callee: /^(DES|TripleDES|RC2)\.Create$/ }],
      ruby: [lit(/^OpenSSL\.Cipher\.new$/), { callee: /^OpenSSL\.Cipher\.(DES|RC4|BF)\w*\.new$/ }],
    }, (_r, callee) => `Weak cipher or mode used via ${callee}; use AES-GCM / ChaCha20-Poly1305.`);
    textRules(ctx, { csharp: [{ sel: "Member", re: /CipherMode\.ECB/ }] }, () => "ECB cipher mode.");
  },
});
