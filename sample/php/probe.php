<?php
md5($pw);                                                                  // VULN weak-hash
hash('sha256', $pw);                                                       // SAFE
openssl_encrypt($d, 'des-ecb', $k);                                        // VULN weak-cipher
$token = rand();                                                           // VULN insecure-random
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);                           // VULN tls-verification-disabled
preg_match($_GET['p'], $s);                                                // VULN regex-injection
preg_match('/' . preg_quote($_GET['p']) . '/', $s);                        // SAFE
error_log("login " . $_POST['u']);                                         // VULN log-injection
header("X-A: " . $_GET['a']);                                              // VULN header-injection
simplexml_load_string($_POST['x']);                                        // VULN xxe
unserialize($_POST['d']);                                                  // VULN insecure-deserialization
$twig->createTemplate($_POST['t']);                                        // VULN ssti
$xp->query("//u[@n='" . $_GET['n'] . "']");                                // VULN xpath-injection
ldap_search($ds, $base, "(uid=" . $_GET['u'] . ")");                       // VULN ldap-injection
$collection->find(["u" => $_POST['u']]);                                   // VULN nosql-injection
header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);         // VULN cors-misconfiguration
JWT::decode($t, $k, ['none']);                                             // VULN insecure-jwt
$password = "Sup3rS3cretValue";                                            // VULN hardcoded-secret
call_user_func($_GET['fn']);                                               // VULN unsafe-reflection
call_user_func('strtoupper', 'x');                                         // SAFE
ini_set('session.cookie_httponly', 0);                                     // VULN insecure-cookie
ini_set('session.cookie_httponly', 1);                                     // SAFE
ini_set('display_errors', 1);                                              // VULN debug-enabled
phpinfo();                                                                 // VULN debug-enabled
User::create($request->all());                                             // VULN mass-assignment
User::create($request->only(['name']));                                    // SAFE
