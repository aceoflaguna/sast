// queries/hardcoded-key.ts
import { defineQuery } from "../src/query";
import { callRules, type CallRule } from "./_lib";

const KEY_LIKE = /^["'][A-Za-z0-9+/=_-]{16,}["']$/;

const litKey = (callee: RegExp, index: number): CallRule => ({
  callee,
  when: (n) => {
    const c = (n as any).__callInfo;
    if (!c) return false;
    const a = c.args[index];
    return a != null && KEY_LIKE.test(a.text.trim());
  },
});

export default defineQuery({
  id: "hardcoded-key",
  title: "Hard-coded cryptographic key",
  severity: "high",
  cwe: "CWE-321",
  description: "A cryptographic primitive is initialized with a string literal key/IV.",
  run(ctx) {
    callRules(ctx, {
      javascript: [
        { callee: /^crypto\.create(Decipher|Cipher|Cipheriv|Decipheriv|Sign|Verify|Hmac)$/,
          when: (n) => /["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
        { callee: /^(jwt|jsonwebtoken)\.(sign|verify)$/,
          when: (n) => /,\s*["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
      python: [
        { callee: /^(AES|DES|DES3|ARC4|ChaCha20|Fernet)\.new$/,
          when: (n) => /["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
        { callee: /^jwt\.(encode|decode)$/,
          when: (n) => /,\s*["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
      php: [
        { callee: /^(openssl_encrypt|openssl_decrypt|mcrypt_encrypt|mcrypt_decrypt)$/,
          when: (n) => /["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
      java: [
        { callee: /^new SecretKeySpec$/,
          when: (n) => /["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
      go: [
        { callee: /^aes\.NewCipher$/,
          when: (n) => /\[\]byte\s*\(\s*["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
      csharp: [
        { callee: /^new (Rfc2898DeriveBytes|AesManaged|AesCryptoServiceProvider|TripleDESCryptoServiceProvider)$/,
          when: (n) => /["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
      ruby: [
        { callee: /^(OpenSSL::Cipher\.new|OpenSSL::HMAC\.(digest|hexdigest))$/,
          when: (n) => /["'][A-Za-z0-9+/=_-]{16,}["']/.test(n.text) },
      ],
    }, (_r, callee) => `Hard-coded key/IV passed to ${callee}; load from a secret store.`);
  },
});