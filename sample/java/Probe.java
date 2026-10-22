class Probe { void a(HttpServletRequest req, HttpServletResponse resp) throws Exception {
  MessageDigest.getInstance("MD5");                                        // VULN weak-hash
  MessageDigest.getInstance("SHA-256");                                    // SAFE
  Cipher.getInstance("DES/ECB/PKCS5Padding");                              // VULN weak-cipher
  String token = String.valueOf(new Random().nextInt());                   // VULN insecure-random
  HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);           // VULN tls-verification-disabled
  Pattern.compile(req.getParameter("p"));                                  // VULN regex-injection
  Pattern.compile(Pattern.quote(req.getParameter("p")));                   // SAFE
  logger.info("login " + req.getParameter("u"));                           // VULN log-injection
  resp.setHeader("X-A", req.getParameter("a"));                            // VULN header-injection
  DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(req.getInputStream());   // VULN xxe
  new ObjectInputStream(req.getInputStream()).readObject();                // VULN insecure-deserialization
  Velocity.evaluate(ctx, w, "t", req.getParameter("t"));                   // VULN ssti
  xpath.evaluate("//u[@n='" + req.getParameter("n") + "']", doc);          // VULN xpath-injection
  ctx.search("dc=x", "(uid=" + req.getParameter("u") + ")", sc);           // VULN ldap-injection
  Document.parse(req.getParameter("f"));                                   // VULN nosql-injection
  resp.setHeader("Access-Control-Allow-Origin", req.getHeader("Origin"));  // VULN cors-misconfiguration
  String password = "Sup3rS3cretValue";                                    // VULN hardcoded-secret
}}

class ProbeMore { void a(HttpServletRequest req, HttpServletResponse resp) throws Exception {
  Class.forName(req.getParameter("c"));                                    // VULN unsafe-reflection
  Class.forName("com.example.Fixed");                                      // SAFE
  Cookie c = new Cookie("sid", sid); c.setHttpOnly(false);                 // VULN insecure-cookie
  c.setHttpOnly(true);                                                     // SAFE
  e.printStackTrace(resp.getWriter());                                     // VULN debug-enabled
}}
