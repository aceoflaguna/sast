import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, redirect
from markupsafe import escape

app = Flask(__name__)
API_KEY = "AKIAIOSFODNN7EXAMPLE"
db_password = "hunter2hunter2"


def run(conn, sql):
    cur = conn.cursor()
    cur.execute(sql)          # parameter reaches sink (summary)
    return cur.fetchall()


def make_where(name):
    return "WHERE name = '%s'" % name


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {uid}"     # VULN
    cur.execute(query)
    return str(cur.fetchall())


@app.route("/search")
def search():
    name = request.form["name"]
    where = make_where(name)
    return str(run(sqlite3.connect("app.db"), "SELECT * FROM users " + where))   # VULN via helper


@app.route("/safe")
def safe():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (request.args.get("id"),))   # SAFE
    return "ok"


@app.route("/safe2")
def safe2():
    uid = int(request.args.get("id"))
    sqlite3.connect("app.db").cursor().execute("SELECT * FROM users WHERE id = %d" % uid)   # SAFE
    return "ok"


@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")      # VULN XSS


@app.route("/hi2")
def hi2():
    name = escape(request.args.get("name", ""))
    return render_template_string("<h1>Hello " + name + "</h1>")      # SAFE


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)                                      # VULN
    subprocess.run("nslookup " + host, shell=True)                      # VULN
    return "done"


@app.route("/read")
def read():
    path = os.path.join("/srv/files", request.args["f"])
    with open(path) as fh:                                              # VULN path traversal
        return fh.read()


@app.route("/go")
def go():
    return redirect(request.args.get("next"))                           # VULN
