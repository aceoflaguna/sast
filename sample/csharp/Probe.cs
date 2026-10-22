public class ProbeController : Controller {
  public void A(string t) {
    var h = MD5.Create();                                                                  // VULN weak-hash
    var h2 = SHA256.Create();                                                              // SAFE
    var d = DES.Create();                                                                  // VULN weak-cipher
    var token = new Random().Next().ToString();                                            // VULN insecure-random
    ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;       // VULN tls-verification-disabled
    var re = new Regex(t);                                                                 // VULN regex-injection
    var re2 = new Regex(Regex.Escape(t));                                                  // SAFE
    _logger.LogInformation("user " + t);                                                   // VULN log-injection
    Response.Headers.Add("X-A", t);                                                        // VULN header-injection
    var doc = new XmlDocument(); doc.LoadXml(t);                                           // VULN xxe
    var obj = new BinaryFormatter().Deserialize(Request.Body);                             // VULN insecure-deserialization
    nav.SelectNodes("//u[@n='" + t + "']");                                                // VULN xpath-injection
    searcher.Filter = "(uid=" + t + ")";                                                   // VULN ldap-injection
    BsonDocument.Parse(t);                                                                 // VULN nosql-injection
    Response.Headers["Access-Control-Allow-Origin"] = "*";                                 // VULN cors-misconfiguration
    var pwd = "Sup3rS3cretValue";                                                          // VULN hardcoded-secret
  }
}

public class ProbeMoreController : Controller {
  public void A(string t) {
    Assembly.Load(t);                                                      // VULN unsafe-reflection
    Assembly.Load("Fixed.Module");                                         // SAFE
    var o = new CookieOptions { HttpOnly = false };                        // VULN insecure-cookie
    var o2 = new CookieOptions { HttpOnly = true, Secure = true };         // SAFE
  }
  public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
    app.UseDeveloperExceptionPage();                                       // VULN debug-enabled
    if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }          // SAFE
  }
}
