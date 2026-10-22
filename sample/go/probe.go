package main

import _ "net/http/pprof" // VULN debug-enabled
import (
	"crypto/md5"
	"crypto/sha256"
	"math/rand"
)

func probeGo(w http.ResponseWriter, r *http.Request) {
	h := md5.New()                                                                            // VULN weak-hash
	s := sha256.New()                                                                         // SAFE
	c, _ := des.NewCipher(key)                                                                // VULN weak-cipher
	token := fmt.Sprint(rand.Intn(1000000))                                                   // VULN insecure-random
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}             // VULN tls-verification-disabled
	re := regexp.MustCompile(r.FormValue("p"))                                                // VULN regex-injection
	re2 := regexp.MustCompile(regexp.QuoteMeta(r.FormValue("p")))                             // SAFE
	log.Printf("login failed for %s", r.FormValue("user"))                                    // VULN log-injection
	w.Header().Set("X-Name", r.FormValue("n"))                                                // VULN header-injection
	template.New("x").Parse(r.FormValue("tpl"))                                               // VULN ssti
	xpath.MustCompile("//u[@n='" + r.FormValue("xp") + "']")                                  // VULN xpath-injection
	ldap.NewSearchRequest(base, 2, 0, 0, 0, false, "(uid="+r.FormValue("u")+")", nil, nil)    // VULN ldap-injection
	bson.UnmarshalExtJSON([]byte(r.FormValue("f")), true, &filter)                             // VULN nosql-injection
	coll.Find(ctx, bson.M{"user": r.FormValue("u")})                                          // SAFE
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))                     // VULN cors-misconfiguration
	w.Header().Set("Access-Control-Allow-Origin", "https://example.com")                      // SAFE
	secret := "hunter2-hunter2"                                                               // VULN hardcoded-secret
}

func probeGoMore(w http.ResponseWriter, r *http.Request) {
	plugin.Open(r.FormValue("p"))                                          // VULN unsafe-reflection
	plugin.Open("./fixed.so")                                              // SAFE
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: v, HttpOnly: false})   // VULN insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: v, HttpOnly: true, Secure: true})   // SAFE
}
