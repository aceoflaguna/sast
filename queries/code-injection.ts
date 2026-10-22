import { defineQuery } from "../src/query";

export default defineQuery({
  id: "code-injection",
  title: "Code injection / eval",
  severity: "critical",
  cwe: "CWE-94",
  description: "User-controlled data is evaluated as code or used to pick a class/method dynamically.",
  taint: {
    sinks: {
      javascript: [
        { callee: /^(eval|new Function|vm\.runIn\w+|vm\.compileFunction)$/, label: "dynamic code execution" },
        { callee: /^(setTimeout|setInterval)$/, args: [0], label: "string timer" },
      ],
      python: [{ callee: /^(eval|exec|compile|__import__)$/, label: "dynamic code execution" }, { callee: /(^|\.)import_module$/, label: "dynamic import" }],
      php: [{ callee: /^(eval|assert|create_function)$/, label: "dynamic code execution" }, { callee: /^preg_replace$/, args: [0], label: "preg_replace /e" }],
      java: [{ callee: /(^|\.)(eval)$/, label: "script engine eval" }, { callee: /^Class\.forName$/, label: "Class.forName" }],
      csharp: [{ callee: /^(CSharpScript\.(EvaluateAsync|RunAsync)|Assembly\.(Load|LoadFrom|LoadFile)|Activator\.CreateInstance|Type\.GetType)$/, label: "dynamic code / type load" }],
      ruby: [
        { callee: /(^|\.)(eval|instance_eval|class_eval|module_eval|send|public_send|__send__|const_get)$/, args: [0], label: "dynamic code / dispatch" },
        { callee: /\.(constantize|safe_constantize)$/, receiver: true, label: "constantize" },
      ],
    },
  },
  message: (f) => `User input reaches ${f.label}.`,
});
