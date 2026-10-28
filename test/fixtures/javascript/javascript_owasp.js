// JavaScript OWASP Top 10 Test Fixtures

const fs = require('fs');
const crypto = require('crypto');
const child_process = require('child_process');
const jwt = require('jsonwebtoken');
const axios = require('axios');

function test_a01_path_traversal(userPath, res) {
    // ruleid: js-path-traversal
    fs.readFile(userPath, 'utf8', (err, data) => {});

    // ok: js-path-traversal
    fs.readFile('safe_file.txt', 'utf8', (err, data) => {});
}

function test_a02_crypto_failures() {
    // ruleid: js-weak-cryptography
    crypto.createHash('md5');

    // ok: js-weak-cryptography
    crypto.createHash('sha256');
}

function test_a03_injection(cmd, userInput) {
    // ruleid: js-dangerous-eval
    eval(userInput);

    // ruleid: js-command-injection
    child_process.exec(cmd);

    // ok: js-dangerous-eval
    console.log("safe");
}

function test_a04_hardcoded_secrets(payload) {
    // ruleid: js-hardcoded-secret
    jwt.sign(payload, "super_hardcoded_jwt_secret_token");

    // ok: js-hardcoded-secret
    jwt.sign(payload, process.env.JWT_SECRET);
}

function test_a05_cors_misconfig() {
    // ruleid: js-cors-wildcard-credentials
    const corsOptions = {
        origin: "*",
        credentials: true
    };

    // ok: js-cors-wildcard-credentials
    const safeCors = {
        origin: "https://example.com"
    };
}

function test_a06_prototype_pollution(target, malicious) {
    // ruleid: js-prototype-pollution
    target.__proto__ = malicious;

    // ok: js-prototype-pollution
    target.normalProperty = malicious;
}

function test_a07_insecure_cookie(res, token) {
    // ruleid: js-insecure-cookie
    res.cookie("auth_session", token, { httpOnly: false });

    // ok: js-insecure-cookie
    res.cookie("auth_session", token, { httpOnly: true, secure: true });
}

function test_a08_deserialization(payload) {
    // ruleid: js-unsafe-deserialization
    serialize.unserialize(payload);

    // ok: js-unsafe-deserialization
    JSON.parse(payload);
}

function test_a09_empty_catch() {
    try {
        criticalOperation();
    // ruleid: js-empty-catch-block
    } catch (err) {}
}

function test_a10_ssrf(userUrl) {
    // ruleid: js-ssrf-http-request
    axios.get(userUrl);

    // ok: js-ssrf-http-request
    axios.get("https://api.example.com/status");
}
