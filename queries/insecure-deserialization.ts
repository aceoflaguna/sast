import { defineQuery } from "../src/query";

export default defineQuery({
  id: "insecure-deserialization",
  title: "Insecure deserialization",
  severity: "critical",
  cwe: "CWE-502",
  description: "Untrusted data is deserialized with a format that can instantiate arbitrary objects.",
  taint: {
    sinks: {
      javascript: [{ callee: /^(\w+\.)?(unserialize|deserialize)$/, label: "node-serialize unserialize" }, { callee: /^(yaml|jsyaml)\.load$/, args: [0], label: "yaml.load" }],
      python: [
        { callee: /^(c?[pP]ickle|dill|shelve|marshal|jsonpickle)\.(loads?|decode|open)$/, label: "pickle-style loader" },
        { callee: /^yaml\.(load|load_all|unsafe_load)$/, args: [0], when: (c) => !/\b(C?SafeLoader|BaseLoader)\b/.test(c.node.text), label: "yaml.load" },
      ],
      php: [{ callee: /^unserialize$/, label: "unserialize()" }],
      java: [
        { callee: /\.(readObject|readUnshared)$/, receiver: true, label: "ObjectInputStream.readObject" },
        { callee: /^new XMLDecoder$/, label: "XMLDecoder" },
        { callee: /(^|\.)(fromXML|deserialize)$/, args: [0], label: "XStream / SerializationUtils" },
      ],
      csharp: [
        { callee: /(^|\.)(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\.Deserialize$|\.Deserialize$/, args: [0], label: "binary formatter Deserialize" },
        { callee: /^(JsonConvert\.DeserializeObject|JavaScriptSerializer\.Deserialize)$/, args: [0], label: "type-aware JSON deserialization" },
      ],
      ruby: [{ callee: /^(Marshal\.(load|restore)|YAML\.(load|unsafe_load|load_file)|Psych\.(load|unsafe_load)|Oj\.load)$/, args: [0], label: "Marshal/YAML load" }],
    },
  },
  message: (f) => `User input is deserialized via ${f.label}; use a data-only format (JSON) or an allow-list.`,
});
