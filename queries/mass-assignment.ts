import { defineQuery } from "../src/query";

// Whole request objects handed to a model/record constructor or updater (CWE-915). Only fires when the *entire*
// request object is the argument — picking fields (req.body.name) or permit()-ing them is the safe form.
const whole = (re: RegExp) => (c: { args: { text: string }[] }) => c.args.some((a) => re.test(a.text.trim()));

const NOT_MODELS = /^(::)?(Regexp|ERB|URI|Date|Time|DateTime|String|Array|Hash|Pathname|File|Dir|IO|Logger|Set|Struct|Class|Module|Thread|Mutex|StringIO|Tempfile|OpenStruct|Integer|Float|BigDecimal|Rational|Complex|Object|Nokogiri[\w.]*|Net[\w.]*|Liquid[\w.]*|Slim[\w.]*|Haml[\w.]*|Rack[\w.]*|REXML[\w.]*|Open3|Tilt[\w.]*|CSV|JSON|YAML|Psych|Oj|Base64|Digest[\w.]*|OpenSSL[\w.]*)\.new$/;

export default defineQuery({
  id: "mass-assignment",
  title: "Mass assignment",
  severity: "medium",
  cwe: "CWE-915",
  description: "The whole request body / params hash is bound to a model, letting clients set fields such as role or is_admin.",
  taint: {
    sinks: {
      javascript: [
        { callee: /^Object\.assign$/, args: [1], when: whole(/^(req|request)\.(body|query)$/), label: "Object.assign(model, req.body)" },
        { callee: /^[A-Z]\w*\.(create|insertMany|findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|build)$/, when: whole(/^(req|request)\.(body|query)$/), label: "Model.create(req.body)" },
        { callee: /^new [A-Z]\w*$/, args: [0], when: whole(/^(req|request)\.(body|query)$/), label: "new Model(req.body)" },
      ],
      python: [{ callee: /(\.create|\.update|\.build|^[A-Z]\w*)$/, when: (c) => /\*\*\s*request\.(POST|data|GET|json|form|args)\b/.test(c.node.text), label: "Model(**request.data)" }],
      php: [{ callee: /(^|\.)(create|fill|update|forceFill|forceCreate|firstOrCreate|updateOrCreate)$/, when: whole(/^\$request->(all|input)\(\)$|^\$_(POST|REQUEST|GET)$/), label: "Model::create($request->all())" }],
      ruby: [{
        callee: /(^|\.)(new|create|create!|update|update!|update_attributes|update_attributes!|assign_attributes|insert_all|upsert)$/, args: [0],
        // `.new` is only a model constructor for ActiveRecord-ish classes; skip the usual stdlib/gem classes that take a string or hash
        when: (c) => whole(/^params(\[:?['"]?\w+['"]?\])?$/)(c) && !NOT_MODELS.test(c.callee), label: "Model.new(params[...])",
      }],
    },
    sanitizers: { ruby: [/(^|\.)permit!?$/, /\.slice$/, /\.except$/], javascript: [/(^|\.)(pick|omit)$/] },
  },
  message: (f) => `Whole request object bound to a model via ${f.label}; whitelist the allowed fields.`,
});
