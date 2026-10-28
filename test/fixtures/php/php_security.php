<?php
// PHP Security Test Fixtures

function test_a01_path_traversal($user_path) {
    // ruleid: php-path-traversal
    file_get_contents($user_path);

    // ok: php-path-traversal
    file_get_contents("safe_file.txt");
}

function test_a02_crypto($pw) {
    // ruleid: php-weak-cryptographic-hash
    md5($pw);

    // ok: php-weak-cryptographic-hash
    password_hash($pw, PASSWORD_DEFAULT);
}

function test_a03_injection($cmd, $conn, $user_id) {
    // ruleid: php-command-injection
    system($cmd);

    // ok: php-command-injection
    system("ls -la");

    // ruleid: php-sql-injection
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $user_id);

    // ok: php-sql-injection
    mysqli_query($conn, "SELECT * FROM users WHERE id = 1");
}

function test_a04_hardcoded_secret($payload) {
    // ruleid: php-hardcoded-secret
    JWT::encode($payload, "super_secret_jwt_key_string");

    // ok: php-hardcoded-secret
    JWT::encode($payload, getenv("JWT_SECRET"));
}

function test_a05_misconfiguration() {
    // ruleid: php-display-errors-enabled
    ini_set('display_errors', '1');

    // ok: php-display-errors-enabled
    ini_set('display_errors', '0');
}

function test_a06_xxe($xml) {
    // ruleid: php-xxe-simplexml
    simplexml_load_string($xml);
}

function test_a07_insecure_cookie() {
    // ruleid: php-insecure-cookie
    $options = ['httponly' => false];
}

function test_a08_deserialization($data) {
    // ruleid: php-unsafe-unserialize
    unserialize($data);

    // ok: php-unsafe-unserialize
    json_decode($data);
}

function test_a09_empty_catch() {
    try {
        doSomething();
    // ruleid: php-empty-catch-block
    } catch (Exception $e) {}
}

function test_a10_ssrf($user_url) {
    // ruleid: php-ssrf-curl
    curl_init($user_url);

    // ok: php-ssrf-curl
    curl_init("https://api.example.com/status");
}
?>
