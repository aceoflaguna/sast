import { defineQuery } from "../src/query";

export default defineQuery({
  id: "command-injection",
  title: "OS command injection",
  severity: "critical",
  cwe: "CWE-78",
  taint: {
    sinks: {
      javascript: [{ callee: /^((child_process|cp|shelljs|shell|childProcess)\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync)$/, args: [0, 1], label: "child_process call" }],
      python: [
        { callee: /^os\.(system|popen|popen2|popen3|spawn\w*|exec\w*)$/, label: "os command" },
        { callee: /^(subprocess\.)?(call|run|Popen|check_output|check_call|getoutput|getstatusoutput)$/, args: [0], label: "subprocess" },
        { callee: /^commands\.getoutput$/, label: "commands.getoutput" },
      ],
      php: [{ callee: /^(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)$/, label: "shell function" }],
      java: [
        { callee: /^Runtime\.getRuntime\(\)\.exec$/, label: "Runtime.exec" },
        { callee: /^new ProcessBuilder$/, label: "ProcessBuilder" },
      ],
      go: [{ callee: /^exec\.(Command|CommandContext)$/, label: "exec.Command" }],
      csharp: [
        { callee: /^((System\.Diagnostics\.)?Process\.Start|new ProcessStartInfo)$/, label: "Process.Start" },
        { assign: /\.(FileName|Arguments)$/, label: "ProcessStartInfo" },
      ],
      ruby: [{ callee: /^(system|exec|spawn|`|Kernel\.(system|exec|spawn|`)|IO\.popen|Open3\.\w+|PTY\.spawn|Process\.spawn|popen)$/, args: [0], label: "shell command" }],
    },
    sanitizers: {
      javascript: [/(^|\.)(escapeShellArg|shellescape|quote)$/],
      python: [/(^|\.)quote$/],
      php: [/^(escapeshellarg|escapeshellcmd)$/],
      ruby: [/(^|\.)(shellescape|escape)$/],
    },
  },
  message: (f) => `User input reaches ${f.label}; avoid shells or pass arguments as a fixed argv array.`,
});
