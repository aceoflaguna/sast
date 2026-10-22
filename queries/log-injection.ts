import { defineQuery } from "../src/query";

export default defineQuery({
  id: "log-injection",
  title: "Log injection (CRLF / forging)",
  severity: "low",
  cwe: "CWE-117",
  description: "Untrusted data is written to logs unmodified; attackers can forge entries via newlines.",
  taint: {
    sinks: {
      javascript: [{ callee: /^(console\.(log|info|warn|error|debug)|(logger|log|winston|bunyan|pino)\.(log|info|warn|error|debug|trace|fatal))$/, label: "log call" }],
      python: [{ callee: /^(logging|logger|log|app\.logger|current_app\.logger)\.(debug|info|warning|warn|error|critical|exception|log)$/, label: "logging call" }],
      php: [{ callee: /^(error_log|syslog)$/, label: "error_log" }],
      java: [{ callee: /^(log|logger|LOG|LOGGER|LOGGER)\.(trace|debug|info|warn|error|fatal)$/, label: "logger call" }],
      go: [{ callee: /^(log|logger|slog|zap|logrus)\.(Print\w*|Fatal\w*|Panic\w*|Info\w*|Warn\w*|Error\w*|Debug\w*)$/, label: "log call" }],
      csharp: [{ callee: /(^|\.)_?(logger|log)\.(Log\w*|Information|Warning|Error|Debug|Critical|Trace)$/i, label: "ILogger call" }],
      ruby: [{ callee: /^(Rails\.logger(\(\))?|logger)\.(info|warn|error|debug|fatal)$/, label: "logger call" }],
    },
    sanitizers: { "*": [/(^|\.)(replace|replaceAll|gsub|sub|strip|escape|sanitize|encode|encodeForHTML|Replace|Trim)$/] },
  },
  message: (f) => `Untrusted input is logged via ${f.label}; strip CR/LF before logging.`,
});
