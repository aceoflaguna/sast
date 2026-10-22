<?php
header("Access-Control-Allow-Origin: *");                          // cors-misconfiguration

$o = unserialize($_COOKIE['data']);                                // VULN insecure-deserialization
$x = simplexml_load_string($_POST['xml']);                         // VULN xxe
$r = $collection->find(['user' => $_GET['u']]);                    // VULN nosql-injection
error_log("login " . $_POST['user']);                              // VULN log-injection (low)
preg_match($_GET['p'], $subject);                                  // VULN regex-injection
$xp->query("//u[@n='" . $_GET['n'] . "']");                        // VULN xpath-injection
ldap_search($ds, "dc=x", "(uid=" . $_GET['u'] . ")");              // VULN ldap-injection
header("X-Name: " . $_GET['n']);                                   // VULN header-injection
$tpl = $twig->createTemplate($_GET['tpl']);                        // VULN ssti

$h = md5("password");                                              // weak-hash
$enc = openssl_encrypt($d, "des-ecb", $k);                         // weak-cipher
$reset_token = mt_rand();                                          // insecure-random
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);                   // tls-verification-disabled
$safeh = hash('sha256', 'x');                                      // SAFE
$n = rand(1, 6);                                                   // SAFE (not a secret)
