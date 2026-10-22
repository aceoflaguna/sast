const crypto = require("crypto");
function probeJs(req, res) {
  crypto.createHash("md5").update(pw).digest("hex");                       // VULN weak-hash
  crypto.createHash("sha256").update(pw);                                  // SAFE
  crypto.createCipheriv("des-ede3-cbc", k, iv);                            // VULN weak-cipher
  const token = Math.random().toString(36);                                // VULN insecure-random
  const agent = new https.Agent({ rejectUnauthorized: false });            // VULN tls-verification-disabled
  new RegExp(req.query.p);                                                 // VULN regex-injection
  new RegExp(_.escapeRegExp(req.query.p));                                 // SAFE
  console.log("login " + req.body.user);                                   // VULN log-injection
  res.setHeader("X-A", req.query.a);                                       // VULN header-injection
  libxmljs.parseXml(req.body.x, { noent: true });                          // VULN xxe
  serialize.unserialize(req.body.d);                                       // VULN insecure-deserialization
  ejs.render(req.body.t);                                                  // VULN ssti
  xpath.select("//u[@n='" + req.query.n + "']", doc);                      // VULN xpath-injection
  client.search("dc=x", { filter: "(uid=" + req.query.u + ")" }, cb);      // VULN ldap-injection
  User.findOne({ name: req.body.name });                                   // VULN nosql-injection
  User.findOne({ name: String(req.body.name) });                           // SAFE
  _.merge({}, req.body);                                                   // VULN prototype-pollution
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);        // VULN cors-misconfiguration
  jwt.verify(t, k, { algorithms: ["none"] });                              // VULN insecure-jwt
  const secret = "abcd1234efgh5678";                                       // VULN hardcoded-secret
}

function probeJsMore(req, res) {
  require(req.query.plugin);                                               // VULN unsafe-reflection
  require("./static-module");                                              // SAFE
  res.cookie("sid", sid, { httpOnly: false, secure: true });               // VULN insecure-cookie
  res.cookie("sid", sid, { httpOnly: true, secure: true });                // SAFE
  res.status(500).send(err.stack);                                         // VULN debug-enabled
  Object.assign(user, req.body);                                           // VULN mass-assignment
  Object.assign(user, { name: req.body.name });                            // SAFE
  User.create(req.body);                                                   // VULN mass-assignment
  User.create({ name: req.body.name });                                    // SAFE
}
