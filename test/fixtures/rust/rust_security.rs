// Rust Security Test Fixtures

use std::fs::File;
use std::process::Command;

fn test_a01_path_traversal(user_path: &str) {
    // ruleid: rust-path-traversal
    let _ = File::open(user_path);

    // ok: rust-path-traversal
    let _ = File::open("safe_static.txt");
}

fn test_a02_crypto() {
    // ruleid: rust-weak-cryptography
    let digest = md5::compute(b"password");
}

fn test_a03_command_injection() {
    // ruleid: rust-command-injection-shell
    let _ = Command::new("sh");

    // ok: rust-command-injection-shell
    let _ = Command::new("git");
}

fn test_a04_secret() {
    // ruleid: rust-hardcoded-secret
    let _ = jsonwebtoken::EncodingKey::from_secret(b"hardcoded_super_secret");
}

fn test_a05_misconfig(builder: reqwest::ClientBuilder) {
    // ruleid: rust-tls-invalid-certs-allowed
    let _ = builder.danger_accept_invalid_certs(true);
}

fn test_a06_unsafe_block() {
    let mut num = 42;
    // ruleid: rust-unsafe-block
    unsafe {
        let r = &mut num as *mut i32;
        *r = 100;
    }

    // ok: rust-unsafe-block
    println!("Safe code: {}", num);
}

fn test_a07_insecure_cookie(cookie: &mut Cookie) {
    // ruleid: rust-insecure-cookie
    cookie.set_http_only(false);
}

fn test_a08_transmute(v: u32) {
    // ruleid: rust-mem-transmute-usage
    let _ = std::mem::transmute(v);
}

fn test_a09_logging(path: &str) {
    // ruleid: rust-unhandled-critical-error
    let _ = std::fs::remove_file(path);
}

fn test_a10_ssrf(user_url: &str) {
    // ruleid: rust-ssrf-http-client
    let _ = reqwest::get(user_url);

    // ok: rust-ssrf-http-client
    let _ = reqwest::get("https://api.github.com/zen");
}
