package demo;

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

public class UserController extends HttpServlet {
    private static final String password = "Sup3rS3cret!";
    private Connection conn;

    private ResultSet runQuery(String sql) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery(sql);                         // parameter reaches sink
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        String q = "SELECT * FROM users WHERE id = " + id;
        Statement st = conn.createStatement();
        st.executeQuery(q);                                  // VULN SQLi

        runQuery("SELECT * FROM users WHERE name = '" + req.getParameter("name") + "'");   // VULN via helper

        int n = Integer.parseInt(req.getParameter("n"));
        st.executeQuery("SELECT * FROM t WHERE n = " + n);   // SAFE

        PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");
        ps.setString(1, id);                                 // SAFE
        ps.executeQuery();

        resp.getWriter().println("<h1>Hello " + req.getParameter("name") + "</h1>");   // VULN XSS

        Runtime.getRuntime().exec("ping " + req.getParameter("host"));                 // VULN cmd

        File f = new File("/data/" + req.getParameter("file"));                         // VULN path traversal
        new FileInputStream(f);

        resp.sendRedirect(req.getParameter("next"));                                    // VULN redirect
    }

    @GetMapping("/spring")
    public String spring(@RequestParam String name) throws Exception {
        return conn.createStatement().executeQuery("SELECT * FROM t WHERE n='" + name + "'").toString();   // VULN (annotation source)
    }
}
