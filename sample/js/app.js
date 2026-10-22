const express = require("express");
const fs = require("fs");
const { exec } = require("child_process");
const { runQuery } = require("./db");
const app = express();

const DB_PASSWORD = "sup3rS3cretPass!";

function buildFilter(name) {
  return "WHERE name = '" + name + "'";
}

// VULN: classic SQL injection (direct)
app.get("/user", async (req, res) => {
  const { id } = req.query;
  const q = `SELECT * FROM users WHERE id = ${id}`;
  const rows = await pool.query(q);
  res.json(rows);
});

// VULN: cross-function + cross-file SQL injection
app.get("/search", async (req, res) => {
  const filter = buildFilter(req.query.name);
  const rows = await runQuery("SELECT * FROM users " + filter);
  res.json(rows);
});

// SAFE: parameterized
app.get("/safe", async (req, res) => {
  const rows = await pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
  res.json(rows);
});

// SAFE: numeric conversion sanitizes
app.get("/safe2", async (req, res) => {
  const id = parseInt(req.query.id, 10);
  res.json(await pool.query("SELECT * FROM users WHERE id = " + id));
});

// VULN: reflected XSS
app.get("/hello", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
});

// SAFE: escaped
app.get("/hello2", (req, res) => {
  res.send("<h1>" + escapeHtml(req.query.name) + "</h1>");
});

// VULN: command injection
app.post("/ping", (req, res) => {
  exec("ping -c 1 " + req.body.host, (err, out) => res.send(out));
});

// VULN: path traversal
app.get("/file", (req, res) => {
  const p = "/var/data/" + req.query.name;
  fs.readFile(p, "utf8", (e, d) => res.send(d));
});

// VULN: code injection
app.post("/calc", (req, res) => res.json({ r: eval(req.body.expr) }));

// VULN: DOM XSS (client-side style)
function render() {
  const hash = window.location.hash;
  document.getElementById("out").innerHTML = hash;
}

// VULN: open redirect
app.get("/go", (req, res) => res.redirect(req.query.next));

app.listen(3000);
