package demo;

import java.io.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.servlet.http.*;
import javax.xml.parsers.*;

public class Extra extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        Object o = ois.readObject();                                                       // VULN insecure-deserialization

        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        db.parse(new ByteArrayInputStream(req.getParameter("xml").getBytes()));            // VULN xxe

        ctx.search("dc=x", "(uid=" + req.getParameter("u") + ")", controls);               // VULN ldap-injection
        xpath.evaluate("//u[@n='" + req.getParameter("n") + "']", doc);                    // VULN xpath-injection
        logger.info("login " + req.getParameter("user"));                                  // VULN log-injection (low)
        Pattern.compile(req.getParameter("p"));                                            // VULN regex-injection
        resp.setHeader("X-Name", req.getParameter("n"));                                   // VULN header-injection
        Document d = Document.parse(req.getParameter("q"));                                // VULN nosql-injection

        MessageDigest md = MessageDigest.getInstance("MD5");                               // weak-hash
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");                             // weak-cipher
        String sessionToken = Long.toString(new Random().nextLong());                      // insecure-random
        MessageDigest ok = MessageDigest.getInstance("SHA-256");                           // SAFE
        Cipher ok2 = Cipher.getInstance("AES/GCM/NoPadding");                              // SAFE
        builder.addAllowedOrigin("*");                                                     // cors-misconfiguration
        Jwts.builder().signWith(SignatureAlgorithm.HS256, "secret");                       // insecure-jwt
        builder.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);                        // tls-verification-disabled
    }
}
