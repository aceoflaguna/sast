import hashlib, logging, pickle, random, re, yaml, ssl, jwt, requests
from flask import Flask, request, make_response
from jinja2 import Template
from lxml import etree
from Crypto.Cipher import DES, AES
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")                                              # cors-misconfiguration
log = logging.getLogger()


@app.route("/x")
def x():
    pickle.loads(request.data)                                      # VULN insecure-deserialization
    yaml.load(request.form["y"])                                    # VULN insecure-deserialization
    Template(request.args["t"])                                     # VULN ssti
    etree.fromstring(request.data)                                  # VULN xxe
    users.find({"u": request.json["u"]})                            # VULN nosql-injection
    log.info("login %s", request.args["u"])                         # VULN log-injection (low)
    re.compile(request.args["p"])                                   # VULN regex-injection
    tree.xpath("//u[@n='%s']" % request.args["n"])                  # VULN xpath-injection
    conn.search_s("dc=x", 2, "(uid=" + request.args["u"] + ")")     # VULN ldap-injection
    resp = make_response("ok")
    resp.headers["X-Name"] = request.args["n"]                      # VULN header-injection
    requests.get("https://x", verify=False)                         # tls-verification-disabled
    return resp


def misc():
    h = hashlib.md5(b"x").hexdigest()                               # weak-hash
    c = DES.new(b"8bytekey", DES.MODE_ECB)                          # weak-cipher
    session_token = random.randint(0, 10**9)                        # insecure-random
    jwt.encode({"id": 1}, "secret", algorithm="HS256")              # insecure-jwt
    jwt.decode("t", options={"verify_signature": False})            # insecure-jwt
    safe = hashlib.sha256(b"x").hexdigest()                         # SAFE
    n = random.random()                                             # SAFE (not a secret)
    return h, c, safe, n
