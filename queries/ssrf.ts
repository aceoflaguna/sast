import { defineQuery } from "../src/query";

export default defineQuery({
  id: "ssrf",
  title: "Server-side request forgery (SSRF)",
  severity: "high",
  cwe: "CWE-918",
  taint: {
    sinks: {
      javascript: [{ callee: /^(axios(\.(get|post|put|delete|request|head))?|fetch|got(\.\w+)?|request|http\.get|https\.get|needle\.get|superagent\.get)$/, args: [0], label: "outbound HTTP request" }],
      python: [{ callee: /^(requests|httpx|session)\.(get|post|put|delete|request|head|patch)$/, args: [0], label: "outbound HTTP request" }, { callee: /^(urllib\.request\.)?urlopen$/, args: [0], label: "urlopen" }],
      php: [{ callee: /^(curl_init|fsockopen)$/, args: [0], label: "curl/socket" }, { callee: /^file_get_contents$/, args: [0], label: "file_get_contents URL" }],
      java: [{ callee: /^new URL$/, label: "new URL" }, { callee: /^URI\.create$/, label: "URI.create" }],
      go: [
        { callee: /^http\.(Get|Post|PostForm|Head|NewRequest|NewRequestWithContext)$/, label: "http request" },
        { callee: /^(client|c|httpClient|resty)\.(Get|Post|Head|Do)$/, label: "http client request" },
      ],
      csharp: [
        { callee: /(^|\.)(GetAsync|PostAsync|PutAsync|DeleteAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|DownloadString|DownloadStringAsync|DownloadFile|DownloadData|OpenRead)$/, args: [0], label: "HttpClient/WebClient request" },
        { callee: /^(new (Uri|HttpRequestMessage)|(System\.Net\.)?WebRequest\.Create(Http)?)$/, label: "outbound request URL" },
      ],
      ruby: [
        { callee: /^Net\.HTTP\.(get|get_response|post|post_form|start|new)$/, label: "Net::HTTP request" },
        { callee: /^(URI\.(open|parse)|open|HTTParty\.(get|post|put|delete|head)|Faraday\.(get|post|put|delete)|RestClient\.(get|post|put|delete|execute)|Typhoeus\.(get|post)|Excon\.(get|post))$/, args: [0], label: "outbound HTTP request" },
      ],
    },
  },
  message: (f) => `User input controls the destination of ${f.label}; allow-list hosts.`,
});
