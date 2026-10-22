<?php
$dbPassword = "Sup3rS3cret!";

function findUser($conn, $where) {
    return mysqli_query($conn, "SELECT * FROM users " . $where);   // param reaches sink
}

function whereName($n) { return "WHERE name = '" . $n . "'"; }

$id = $_GET['id'];
$q = "SELECT * FROM users WHERE id = $id";
$r = mysqli_query($conn, $q);                              // VULN SQLi

$res = findUser($conn, whereName($_POST['name']));         // VULN SQLi (cross-function)

$safe = (int)$_GET['uid'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $safe);   // SAFE (cast)

$esc = mysqli_real_escape_string($conn, $_GET['n']);
mysqli_query($conn, "SELECT * FROM t WHERE n = '" . $esc . "'");   // SAFE (escaped)

$stmt = $pdo->query("SELECT * FROM t WHERE x = '" . $_REQUEST['x'] . "'");   // VULN

echo "<p>Hello " . $_GET['name'] . "</p>";                 // VULN XSS
echo "<p>Hello " . htmlspecialchars($_GET['name']) . "</p>";   // SAFE

system("ping -c 1 " . $_GET['host']);                      // VULN cmd
include $_GET['page'] . ".php";                            // VULN LFI
eval($_POST['code']);                                      // VULN
header("Location: " . $_GET['to']);                        // VULN redirect

class Repo {
    public function find($name) {
        return $this->db->query("SELECT * FROM t WHERE name='" . $name . "'");   // param reaches sink
    }
}
$repo->find($_GET['q']);                                   // VULN via method summary
