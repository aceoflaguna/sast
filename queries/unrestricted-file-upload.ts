// queries/unrestricted-upload.ts
import { defineQuery } from "../src/query";

const VALIDATION = /(allowed_extensions|whitelist|allowlist|mimetype|content_type|magic|filetype|secure_filename|basename|path\.extname|extension|accept)/i;

export default defineQuery({
  id: "unrestricted-upload",
  title: "Unrestricted file upload",
  severity: "high",
  cwe: "CWE-434",
  description: "Uploaded file is saved without an extension/MIME allow-list or with a user-controlled filename.",
  taint: {
    sinks: {
      javascript: [
        { callee: /^multer\(\)\.(single|array|fields|any)$/, label: "multer upload" },
        { callee: /^(req|request)\.file\.(mv|save)$/, label: "file.move/save" },
        { assign: /\.(originalname|originalName)$/, label: "user-controlled filename" },
      ],
      python: [
        { callee: /^\.save$/, when: (c) => /(file|upload|image|avatar)/i.test(c.callee), label: "FileField.save" },
        { callee: /^(open|shutil\.copy|shutil\.move)$/, args: [0], label: "file write with user path" },
      ],
      php: [
        { callee: /^move_uploaded_file$/, label: "move_uploaded_file" },
        { callee: /^copy$/, when: (c) => /\$_(FILES|POST|GET)/.test(c.node.text), label: "copy uploaded file" },
      ],
      java: [
        { callee: /\.(transferTo|write)$/, when: (c) => /(file|upload|part|multipart)/i.test(c.node.text), label: "MultipartFile transfer" },
      ],
      go: [
        { callee: /^(io\.Copy|os\.Create|os\.WriteFile)$/, when: (c) => /multipart|FormFile|\.FileName/.test(c.node.text), label: "uploaded file write" },
      ],
      csharp: [
        { callee: /\.(CopyTo|SaveAs|WriteAllBytes)$/, when: (c) => /(file|upload|iformfile)/i.test(c.node.text), label: "uploaded file save" },
      ],
      ruby: [
        { callee: /^(File\.(open|write|binwrite)|IO\.copy_stream|FileUtils\.(cp|mv))$/, label: "file write" },
      ],
    },
    sanitizers: {
      "*": [VALIDATION],
    },
  },
  message: (f) => `Uploaded file written via ${f.label} without a validated extension/MIME allow-list.`,
});