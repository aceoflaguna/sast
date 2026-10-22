import { defineQuery } from "../src/query";
import { callRules, type CallRule } from "./_lib";

const WEAK = /^(md2|md4|md5|sha-?1)$/i;
const r = (callee: RegExp, note?: string): CallRule => ({ callee, note });
const lit = (callee: RegExp, index = 0): CallRule => ({ callee, arg: { index, re: WEAK } });

/** Pattern query (no taint): any use of MD5 / SHA-1. Uses the traversal API through callRules(). */
export default defineQuery({
  id: "weak-hash",
  title: "Weak hash algorithm (MD5 / SHA-1)",
  severity: "medium",
  cwe: "CWE-328",
  description: "MD5 and SHA-1 are broken for integrity and unsuitable for password storage.",
  run(ctx) {
    callRules(ctx, {
      javascript: [lit(/^(crypto\.)?createHash$/), r(/^(CryptoJS\.)?(MD5|SHA1)$/), r(/^md5$/)],
      python: [r(/^hashlib\.(md5|sha1)$/), lit(/^hashlib\.new$/), r(/(^|\.)(MD5|SHA1)\.new$/)],
      php: [r(/^(md5|sha1|md5_file|sha1_file|crc32)$/)],
      java: [lit(/^MessageDigest\.getInstance$/), r(/(^|\.)DigestUtils\.(md5|sha1|sha|md5Hex|sha1Hex|shaHex)\w*$/)],
      go: [r(/^(md5|sha1)\.(New|Sum)$/)],
      csharp: [r(/^(MD5|SHA1)\.Create$/), r(/^new (MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed|MD5Cng|SHA1Cng)$/), lit(/^HashAlgorithm\.Create$/)],
      ruby: [r(/^(OpenSSL\.)?Digest\.(MD5|SHA1)\.\w+$/), lit(/^(OpenSSL\.)?Digest\.new$/)],
    }, (_r, callee) => `Weak hash algorithm via ${callee}; use SHA-256+ (and bcrypt/argon2/scrypt for passwords).`);
  },
});
