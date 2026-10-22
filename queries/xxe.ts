import { defineQuery } from "../src/query";

export default defineQuery({
  id: "xxe",
  title: "XML external entity (XXE) risk",
  severity: "high",
  cwe: "CWE-611",
  description: "Untrusted XML reaches a parser; verify external entities / DTDs are disabled.",
  taint: {
    sinks: {
      javascript: [{ callee: /^(libxmljs\.)?parseXml(String)?$/, args: [0], label: "libxmljs parseXml" }],
      python: [
        { callee: /^(lxml\.)?etree\.(fromstring|XML|parse|parse_xml)$/, args: [0], label: "lxml parser" },
        { callee: /^(xml\.)?(dom\.minidom|dom\.pulldom|sax)\.(parseString|parse)$/, args: [0], label: "xml.dom/sax parser" },
        { callee: /^(xml\.)?(dom\.)?minidom\.parseString$/, args: [0], label: "minidom.parseString" },
      ],
      php: [
        { callee: /^(simplexml_load_string|simplexml_load_file|xml_parse)$/, args: [0], label: "SimpleXML" },
        { callee: /(^|\.)(loadXML|loadHTML)$/, args: [0], label: "DOMDocument::loadXML" },
        { callee: /^new SimpleXMLElement$/, args: [0], label: "SimpleXMLElement" },
      ],
      java: [
        { callee: /(^|\.)(parse|unmarshal|build|createXMLStreamReader|createXMLEventReader|transform|newSAXParser)$/, when: (c) => /(builder|parser|reader|unmarshaller|factory|transformer|^db\b|^dbf\b|^dBuilder)/i.test(c.callee), label: "XML parser" },
        { callee: /^new (SAXBuilder|InputSource|StreamSource)$/, label: "XML input source" },
      ],
      csharp: [
        { callee: /(^|\.)(LoadXml|Load|Parse)$/, when: (c) => /(xml|doc|xdoc)/i.test(c.callee) && !/bson|json|yaml|toml|jobject|jtoken/i.test(c.callee), args: [0], label: "XmlDocument / XDocument" },
        { callee: /^(XmlReader\.Create|new XmlTextReader)$/, args: [0], label: "XmlReader" },
      ],
      ruby: [{ callee: /^(Nokogiri\.XML|Nokogiri\.XML\.Document\.parse|REXML\.Document\.new|Nokogiri\.XML\.Reader)$|^REXML\.Document\.new$/, args: [0], label: "Nokogiri / REXML" }],
    },
  },
  message: (f) => `Untrusted XML parsed by ${f.label}; disable DTDs and external entities.`,
});
