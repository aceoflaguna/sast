package main

import (
	"crypto/tls"
	"crypto/md5"
	"database/sql"
	"fmt"
	"html"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"
)

var dbPassword = "Sup3rS3cretPass!" // hardcoded secret
var db *sql.DB

// parameter 0 reaches the SQL sink -> found through the function summary
func helperQuery(q string) (*sql.Rows, error) {
	return db.Query(q)
}

func buildWhere(name string) string {
	return "WHERE name = '" + name + "'"
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := "SELECT * FROM users WHERE id = " + id
	db.Query(q) // VULN sql-injection

	helperQuery("SELECT * FROM t " + buildWhere(r.FormValue("name"))) // VULN sql-injection (cross-function)

	n, _ := strconv.Atoi(r.FormValue("n"))
	db.Query("SELECT * FROM t WHERE n = " + strconv.Itoa(n)) // SAFE (numeric conversion)
	db.Query("SELECT * FROM t WHERE id = $1", id)            // SAFE (bind parameter)

	fmt.Fprintf(w, "<h1>Hello %s</h1>", r.URL.Query().Get("name"))                  // VULN xss
	fmt.Fprintf(w, "<h1>%s</h1>", html.EscapeString(r.URL.Query().Get("name")))     // SAFE

	exec.Command("sh", "-c", "ping -c1 "+r.FormValue("host")).Run() // VULN command-injection
	os.ReadFile("/srv/files/" + r.URL.Query().Get("f"))             // VULN path-traversal
	http.Redirect(w, r, r.URL.Query().Get("next"), 302)             // VULN open-redirect
	http.Get(r.FormValue("url"))                                    // VULN ssrf
	log.Printf("login failed for %s", r.FormValue("user"))          // VULN log-injection
	w.Header().Set("X-Name", r.FormValue("n"))                      // VULN header-injection
	regexp.MustCompile(r.FormValue("p"))                            // VULN regex-injection

	w.Header().Set("Access-Control-Allow-Origin", "*") // cors-misconfiguration
	sum := md5.New()                                    // weak-hash
	_ = sum
	_ = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // tls-verification-disabled
	sessionToken := fmt.Sprint(rand.Int63())                                    // insecure-random
	_ = sessionToken
}

func ginHandler(c *gin.Context) {
	db.Raw("SELECT * FROM t WHERE id = " + c.Param("id")) // VULN sql-injection (gin source)
	c.HTML(200, c.Query("x"))                              // VULN xss
}
