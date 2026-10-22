import { defineQuery } from "../src/query";

export default defineQuery({
  id: "xss",
  title: "Cross-site scripting (XSS)",
  severity: "high",
  cwe: "CWE-79",
  description: "User-controlled data is written to an HTML response / DOM without encoding.",
  taint: {
    sinks: {
      javascript: [
        { assign: /\.(innerHTML|outerHTML)$/, label: "innerHTML assignment" },
        { callee: /^document\.(write|writeln)$/, label: "document.write" },
        { callee: /\.insertAdjacentHTML$/, args: [1], label: "insertAdjacentHTML" },
        { callee: /^\$\(\)\.(html|append|prepend|after|before)$/, label: "jQuery HTML sink" },
        { callee: /^(res|response)\.(send|write|end)$/, args: [0], label: "HTTP response body" },
      ],
      python: [
        { callee: /^(flask\.)?(render_template_string|Markup|make_response)$/, label: "HTML response" },
        { callee: /^(django\.http\.)?(HttpResponse)$/, args: [0], label: "HttpResponse" },
        { callee: /(^|\.)mark_safe$/, label: "mark_safe" },
      ],
      php: [
        { callee: /^(echo|print|printf|print_r|vprintf)$/, label: "echo/print output" },
      ],
      java: [
        { callee: /\.getWriter\(\)\.(print|println|write|printf|append)$/, label: "response writer" },
        { callee: /^(out|writer|pw)\.(print|println|write|printf)$/, label: "response writer" },
      ],
      go: [
        { callee: /^(w|rw|res|resp|writer)\.(Write|WriteString)$/, label: "ResponseWriter.Write" },
        { callee: /^(fmt\.(Fprintf|Fprint|Fprintln)|io\.WriteString)$/, when: (c) => /^(w|rw|res|resp|writer)$/.test(c.args[0]?.text ?? ""), label: "write to ResponseWriter" },
        { callee: /^template\.(HTML|JS|JSStr|URL|HTMLAttr|CSS)$/, label: "template trusted type" },
        { callee: /^(c|ctx)\.(HTML|Writer\.WriteString)$/, label: "HTML response" },
      ],
      csharp: [
        { callee: /^((this|HttpContext)\.)?Response\.(Write|WriteAsync)$/, label: "Response.Write" },
        { callee: /^(Html\.Raw|new HtmlString|new MvcHtmlString|MvcHtmlString\.Create|new MarkupString)$/, label: "raw HTML" },
      ],
      ruby: [
        { callee: /^render\.(html|inline|body)$/, label: "render html:" },
        { callee: /\.html_safe$/, receiver: true, label: "html_safe" },
        { callee: /^raw$/, label: "raw()" },
      ],
    },
    sanitizers: {
      javascript: [/(^|\.)(escape|escapeHtml|escapeHTML|sanitize|sanitizeHtml|encodeURIComponent|encodeURI|xss|encode)$/],
      python: [/(^|\.)(escape|html_escape|quote|clean|strip_tags|conditional_escape|format_html)$/],
      php: [/^(htmlspecialchars|htmlentities|strip_tags|esc_html|esc_attr|e|filter_var|json_encode)$/],
      java: [/(^|\.)(escapeHtml4?|encodeForHTML|encodeForJavaScript|htmlEscape|forHtml\w*|encode)$/],
      go: [/(^|\.)(EscapeString|HTMLEscapeString|JSEscapeString|HTMLEscaper|Sanitize|SanitizeBytes|QueryEscape|PathEscape)$/],
      csharp: [/(^|\.)(HtmlEncode|HtmlAttributeEncode|JavaScriptStringEncode|Encode|Sanitize\w*)$/],
      ruby: [/(^|\.)(h|html_escape|sanitize|escape_html|escapeHTML|escape|strip_tags|html_escape_once)$/],
    },
  },
  message: (f) => `Unencoded user input written via ${f.label}; encode for the HTML context.`,
});
