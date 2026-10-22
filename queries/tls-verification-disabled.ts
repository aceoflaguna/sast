import { defineQuery } from "../src/query";
import { textRules } from "./_lib";

export default defineQuery({
  id: "tls-verification-disabled",
  title: "TLS certificate verification disabled",
  severity: "high",
  cwe: "CWE-295",
  description: "Certificate or hostname verification is turned off, enabling man-in-the-middle attacks.",
  run(ctx) {
    textRules(ctx, {
      javascript: [
        { sel: "pair", re: /^["']?rejectUnauthorized["']?\s*:\s*false\b/ },
        { sel: "Assign", re: /NODE_TLS_REJECT_UNAUTHORIZED[\s\S]*['"]0['"]/ },
      ],
      python: [
        { sel: "Call", re: /\bverify\s*=\s*False\b|_create_unverified_context/ },
        { sel: "Assign", re: /check_hostname\s*=\s*False|verify_mode\s*=\s*ssl\.CERT_NONE/ },
      ],
      php: [{ sel: "Call", re: /CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)\b/i }],
      java: [
        { sel: "Call", re: /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllStrategy|TrustSelfSignedStrategy|set(Default)?HostnameVerifier\(\s*(\([^)]*\)|\w+)\s*->\s*true\b/ },
        // trust manager whose checkServerTrusted / checkClientTrusted body is empty => accepts every certificate
        { sel: "method_declaration", re: /\bcheck(Server|Client)Trusted\s*\([^)]*\)[^{;]*\{\s*(\/\/[^\n]*\s*|\/\*[\s\S]*?\*\/\s*)*\}/ },
        { sel: "Member", re: /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier\.INSTANCE/ },
      ],
      go: [
        { sel: "composite_literal", re: /InsecureSkipVerify\s*:\s*true/ },
        { sel: "Assign", re: /InsecureSkipVerify\s*=\s*true/ },
      ],
      csharp: [
        { sel: "Assign", re: /ServerCertificate(Custom)?ValidationCallback\s*\+?=[\s\S]*\btrue\b/ },
        { sel: "Member", re: /DangerousAcceptAnyServerCertificateValidator/ },
      ],
      ruby: [
        { sel: "Assign", re: /verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE/ },
        { sel: "pair", re: /verify(_ssl|_mode)?\W{0,3}\s*(=>)?\s*(false|OpenSSL::SSL::VERIFY_NONE)/ },
      ],
    }, () => "TLS certificate/hostname verification is disabled.");
  },
});
