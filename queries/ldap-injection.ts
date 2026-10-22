import { defineQuery } from "../src/query";

export default defineQuery({
  id: "ldap-injection",
  title: "LDAP injection",
  severity: "high",
  cwe: "CWE-90",
  taint: {
    sinks: {
      javascript: [{ callee: /(^|\.)(client|ldap|ldapClient)\.search$/, args: [0, 1], label: "ldapjs search" }],
      python: [{ callee: /(^|\.)(search|search_s|search_st|search_ext|search_ext_s)$/, when: (c) => /(ldap|conn|server)/i.test(c.callee), label: "LDAP search" }],
      php: [{ callee: /^(ldap_search|ldap_list|ldap_read|ldap_bind)$/, label: "ldap_* call" }],
      java: [
        { callee: /(^|\.)(search|searchForObject|authenticate)$/, when: (c) => /(ctx|context|ldap|dirContext|template)/i.test(c.callee), label: "JNDI / Spring LDAP search" },
        { callee: /^new SearchControls$/, label: "SearchControls" },
      ],
      csharp: [{ callee: /^new (DirectorySearcher|SearchRequest)$/, label: "DirectorySearcher" }, { assign: /\.Filter$/, label: "DirectorySearcher.Filter" }],
      go: [{ callee: /^ldap\.NewSearchRequest$/, label: "ldap.NewSearchRequest" }],
      ruby: [{ callee: /(^|\.)(ldap|conn)\.(search|bind_as)$/, label: "Net::LDAP search" }],
    },
    sanitizers: {
      "*": [/(escape_filter_chars|escape_dn_chars|ldap_escape|encodeForLDAP|escapeLDAP\w*|EscapeFilter|escapeFilter|escapeDN|filter\.escape)$/i],
    },
  },
  message: (f) => `User input reaches ${f.label} unescaped; escape LDAP filter/DN special characters.`,
});
