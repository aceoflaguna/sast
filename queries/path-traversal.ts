import { defineQuery } from "../src/query";

export default defineQuery({
  id: "path-traversal",
  title: "Path traversal / arbitrary file access",
  severity: "high",
  cwe: "CWE-22",
  taint: {
    sinks: {
      javascript: [
        { callee: /^(fs|fsp|fs\.promises)\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|unlink|unlinkSync|readdir|readdirSync|appendFile|appendFileSync|stat|statSync|rm|rmSync|open|openSync)$/, args: [0], label: "filesystem access" },
        { callee: /^(res|response)\.(sendFile|download|sendfile)$/, args: [0], label: "file download" },
      ],
      python: [
        { callee: /^open$/, args: [0], label: "open()" },
        { callee: /^os\.(remove|unlink|rmdir|listdir|mkdir|makedirs|rename|stat)$/, args: [0], label: "os file operation" },
        { callee: /^shutil\.(copy|copyfile|move|rmtree)$/, label: "shutil operation" },
        { callee: /^(flask\.)?send_file$/, args: [0], label: "send_file" },
        { callee: /^(pathlib\.)?Path$/, label: "Path()" },
      ],
      php: [{ callee: /^(fopen|file_get_contents|file_put_contents|readfile|file|unlink|include|copy|rename|mkdir|rmdir|scandir|fpassthru|move_uploaded_file|opendir|highlight_file|show_source)$/, label: "file access / include" }],
      java: [
        { callee: /^new (File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)$/, label: "File access" },
        { callee: /^(Paths\.get|Path\.of|Files\.(readAllBytes|readAllLines|readString|newInputStream|newBufferedReader|write|delete|copy|move|lines|walk|list))$/, label: "NIO file access" },
      ],
      go: [{ callee: /^(os\.(Open|OpenFile|ReadFile|WriteFile|Remove|RemoveAll|Create|Mkdir|MkdirAll|Stat|ReadDir|Rename)|ioutil\.(ReadFile|WriteFile|ReadDir)|http\.ServeFile|filepath\.(Walk|WalkDir|Glob)|http\.Dir)$/, label: "filesystem access" }],
      csharp: [
        { callee: /^(System\.IO\.)?(File|Directory)\.\w+$/, label: "System.IO access" },
        { callee: /^new (FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo)$/, label: "file stream" },
        { callee: /^(this\.)?(PhysicalFile|File)$/, args: [0], label: "file download" },
      ],
      ruby: [
        { callee: /^(File|IO|FileUtils|Dir|Pathname|Kernel)\.(read|readlines|binread|open|new|write|binwrite|delete|unlink|rm|rm_rf|rm_r|mkdir|mkdir_p|cp|mv|foreach|glob|entries|stat|chmod|realpath)$/, label: "file access" },
        { callee: /^(send_file|send_data|open|require|load|require_relative|render\.file|render\.template)$/, args: [0], label: "file access / load" },
      ],
    },
    sanitizers: {
      javascript: [/^path\.basename$/, /(^|\.)(sanitizeFilename|sanitize-filename)$/],
      python: [/(^|\.)(secure_filename|basename)$/],
      php: [/^basename$/],
      java: [/(^|\.)(getName|FilenameUtils\.getName)$/],
      go: [/^(filepath|path)\.Base$/, /SecureJoin$/],
      csharp: [/(^|\.)(GetFileName|GetFileNameWithoutExtension)$/],
      ruby: [/\.basename$/],
    },
  },
  message: (f) => `User-controlled path reaches ${f.label}; resolve against a base directory and reject ".." / use basename.`,
});
