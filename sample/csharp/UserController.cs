using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace Demo
{
    public class UserController : Controller
    {
        private const string Password = "Sup3rS3cretPass!";           // hardcoded secret
        private readonly SqlConnection conn = new SqlConnection();
        private readonly ILogger<UserController> _logger;

        private IEnumerable<User> Run(string sql) => conn.Query<User>(sql);   // parameter reaches Dapper sink

        [HttpGet("u")]
        public IActionResult Get([FromQuery] string name)
        {
            var id = Request.Query["id"];
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);   // VULN sql-injection
            cmd.ExecuteReader();

            Run("SELECT * FROM Users WHERE Name = '" + name + "'");                   // VULN sql-injection (cross-method, [FromQuery] source)

            var n = Convert.ToInt32(Request.Query["n"]);
            new SqlCommand("SELECT * FROM T WHERE N = " + n, conn);                  // SAFE (numeric conversion)
            var safe = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);   // SAFE (parameterized)
            safe.Parameters.AddWithValue("@id", id);

            Response.Write("<h1>" + name + "</h1>");                                  // VULN xss
            Response.Write("<h1>" + HttpUtility.HtmlEncode(name) + "</h1>");          // SAFE

            Process.Start("cmd.exe", "/c ping " + Request.Query["host"]);            // VULN command-injection
            System.IO.File.ReadAllText(Path.Combine("/data", Request.Query["f"]));   // VULN path-traversal
            new HttpClient().GetStringAsync(Request.Query["url"]);                   // VULN ssrf
            var obj = new BinaryFormatter().Deserialize(Request.Body);               // VULN insecure-deserialization

            var doc = new XmlDocument();
            doc.LoadXml(Request.Form["xml"]);                                        // VULN xxe
            new DirectorySearcher(entry, "(uid=" + Request.Query["user"] + ")");     // VULN ldap-injection
            doc.SelectNodes("//u[@n='" + name + "']");                               // VULN xpath-injection
            _logger.LogInformation("login " + Request.Form["user"]);                 // VULN log-injection
            var rx = new Regex(Request.Query["p"]);                                  // VULN regex-injection
            Response.Headers.Add("X-Name", name);                                    // VULN header-injection

            var md5 = MD5.Create();                                                  // weak-hash
            var des = new DESCryptoServiceProvider();                                // weak-cipher
            var resetToken = new Random().Next();                                    // insecure-random
            ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;   // tls-verification-disabled
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("supersecretkey123"));    // insecure-jwt

            return Redirect(Request.Query["next"]);                                  // VULN open-redirect
        }

        public void Configure(CorsPolicyBuilder builder) { builder.AllowAnyOrigin(); }        // cors-misconfiguration
    }
}
