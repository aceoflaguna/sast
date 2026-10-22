def probe_py():
    hashlib.md5(pw.encode())                                               # VULN weak-hash
    hashlib.sha256(pw.encode())                                            # SAFE
    DES.new(key, DES.MODE_ECB)                                             # VULN weak-cipher
    token = random.randint(0, 999999)                                      # VULN insecure-random
    requests.get(url, verify=False)                                        # VULN tls-verification-disabled
    re.compile(request.args["p"])                                          # VULN regex-injection
    re.compile(re.escape(request.args["p"]))                               # SAFE
    logging.info("login %s" % request.form["u"])                           # VULN log-injection
    resp.headers["X-A"] = request.args["a"]                                # VULN header-injection
    etree.fromstring(request.data)                                         # VULN xxe
    pickle.loads(request.data)                                             # VULN insecure-deserialization
    yaml.load(request.data)                                                # VULN insecure-deserialization
    yaml.safe_load(request.data)                                           # SAFE
    yaml.load(request.data, Loader=yaml.SafeLoader)                        # SAFE
    Template(request.args["t"]).render()                                   # VULN ssti
    tree.xpath("//u[@n='" + request.args["n"] + "']")                      # VULN xpath-injection
    conn.search("dc=x", "(uid=" + request.args["u"] + ")")                 # VULN ldap-injection
    db.users.find({"n": request.json["n"]})                                # VULN nosql-injection
    resp.headers.add("Access-Control-Allow-Origin", request.headers.get("Origin"))   # VULN cors-misconfiguration
    jwt.decode(tok, options={"verify_signature": False})                   # VULN insecure-jwt
    api_key = "sk_live_abcdefghijklmnop1234"                               # VULN hardcoded-secret


def probe_py_more():
    importlib.import_module(request.args["m"])                             # VULN unsafe-reflection
    getattr(obj, request.args["attr"])                                     # VULN unsafe-reflection
    getattr(obj, "fixed")                                                  # SAFE
    resp.set_cookie("sid", sid, httponly=False)                            # VULN insecure-cookie
    resp.set_cookie("sid", sid, httponly=True, secure=True)                # SAFE
    app.run(debug=True)                                                    # VULN debug-enabled
    app.run(debug=False)                                                   # SAFE
    User.objects.create(**request.data)                                    # VULN mass-assignment
    User.objects.create(name=request.data["name"])                         # SAFE
