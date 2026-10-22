const express = require("express");
const jwt = require("jsonwebtoken");
const ejs = require("ejs");
const _ = require("lodash");
const crypto = require("crypto");
const libxmljs = require("libxmljs");
const serialize = require("node-serialize");
const xpath = require("xpath");
const cors = require("cors");
const app = express();
app.use(cors({ origin: "*" }));                                    // cors-misconfiguration

app.post("/login", async (req, res) => {
  const found = await db.collection("users").find({ user: req.body.user });      // VULN nosql-injection
  const ok = await users.findOne({ name: String(req.body.name) });               // SAFE (coerced)
  console.log("login attempt " + req.body.user);                                  // VULN log-injection (low)
  res.setHeader("X-User", req.query.n);                                           // VULN header-injection
  const re = new RegExp(req.query.q);                                             // VULN regex-injection
  _.merge({}, req.body);                                                          // VULN prototype-pollution
  res.send(ejs.render(req.query.tpl));                                            // VULN ssti (+ xss)
  libxmljs.parseXml(req.body.xml);                                                // VULN xxe
  serialize.unserialize(req.body.data);                                           // VULN insecure-deserialization
  xpath.select("//u[@n='" + req.query.n + "']", doc);                             // VULN xpath-injection
  client.search("dc=x", { filter: "(uid=" + req.query.u + ")" });                 // VULN ldap-injection
});

const hash = crypto.createHash("md5").update("x").digest("hex");                 // weak-hash
const c1 = crypto.createCipher("aes192", "pw");                                  // weak-cipher
const resetToken = Math.random().toString(36).slice(2);                          // insecure-random
const agent = new https.Agent({ rejectUnauthorized: false });                    // tls-verification-disabled
const t = jwt.sign({ id: 1 }, "my-secret");                                      // insecure-jwt
const opts = { algorithms: ["none"] };                                           // insecure-jwt (none)
const okHash = crypto.createHash("sha256");                                      // SAFE
const diceRoll = Math.random();                                                  // SAFE (not a secret)
