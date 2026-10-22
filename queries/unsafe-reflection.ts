import { defineQuery } from "../src/query";

export default defineQuery({
  id: "unsafe-reflection",
  title: "Unsafe reflection / dynamic loading",
  severity: "high",
  cwe: "CWE-470",
  description: "User input selects which class, module, method or library gets loaded or invoked.",
  taint: {
    sinks: {
      javascript: [{ callee: /^(require|import)$/, args: [0], label: "dynamic require/import" }],
      python: [
        { callee: /^(__import__|importlib\.import_module|pydoc\.locate)$/, args: [0], label: "dynamic import" },
        { callee: /^getattr$/, args: [1], label: "getattr() with user-chosen name" },
      ],
      php: [
        { callee: /^(call_user_func|call_user_func_array|forward_static_call|forward_static_call_array|constant)$/, args: [0], label: "call_user_func" },
        { callee: /^new (ReflectionClass|ReflectionMethod|ReflectionFunction|ReflectionObject)$/, label: "Reflection API" },
      ],
      java: [
        { callee: /^(Class\.forName|System\.(load|loadLibrary)|Runtime\.getRuntime\(\)\.(load|loadLibrary))$/, args: [0], label: "Class.forName / native library load" },
        { callee: /\.(loadClass|getMethod|getDeclaredMethod|getField|getDeclaredField)$/, args: [0], label: "reflective member lookup" },
      ],
      go: [
        { callee: /^plugin\.Open$/, args: [0], label: "plugin.Open" },
        { callee: /\.(MethodByName|FieldByName)$/, args: [0], label: "reflect MethodByName / FieldByName" },
      ],
      csharp: [
        { callee: /^(Type\.GetType|Assembly\.(Load|LoadFrom|LoadFile|UnsafeLoadFrom|LoadWithPartialName)|Activator\.CreateInstance(From)?|AppDomain\.CurrentDomain\.(CreateInstance\w*|Load))$/, args: [0], label: "Type / Assembly loading" },
        { callee: /\.(GetMethod|GetProperty|GetField|InvokeMember)$/, args: [0], label: "reflective member lookup" },
      ],
      ruby: [
        { callee: /(^|\.)(send|public_send|__send__|const_get|instance_variable_get|instance_variable_set|method|try)$/, args: [0], label: "dynamic send / const_get" },
        { callee: /\.(constantize|safe_constantize)$/, receiver: true, label: "String#constantize" },
      ],
    },
  },
  message: (f) => `User input chooses what is loaded or invoked via ${f.label}; resolve against an allow-list of names.`,
});
