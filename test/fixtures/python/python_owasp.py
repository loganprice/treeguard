# Python OWASP Top 10 Test Fixtures

import os
import hashlib
import random
import jwt
import xml.etree.ElementTree as ET
import pickle
import requests

def test_a01_path_traversal(user_path):
    # ruleid: py-path-traversal
    open(user_path, "r")

    # ok: py-path-traversal
    open("safe_static_path.txt", "r")


def test_a02_crypto_failures(data):
    # ruleid: py-weak-cryptography
    hashlib.md5(data)

    # ruleid: py-weak-cryptography
    api_key = random.random()

    # ok: py-weak-cryptography
    hashlib.sha256(data)


def test_a03_injection(cmd, code):
    # ruleid: py-command-injection
    os.system(cmd)

    # ruleid: py-dangerous-eval
    eval(code)

    # ok: py-dangerous-eval
    print("code execution is safe")


def test_a04_hardcoded_secrets(payload):
    # ruleid: py-hardcoded-secret
    jwt.encode(payload, "super_secret_hardcoded_key")

    # ok: py-hardcoded-secret
    jwt.encode(payload, os.getenv("JWT_SECRET"))


def test_a05_debug_misconfig(app):
    # ruleid: py-debug-mode-enabled
    app.run(host="0.0.0.0", debug=True)

    # ok: py-debug-mode-enabled
    app.run(host="0.0.0.0", debug=False)


def test_a06_xxe(xml_file):
    # ruleid: py-xxe-elementtree
    ET.parse(xml_file)

    # ok: py-xxe-elementtree
    print("safe xml parsing")


def test_a07_insecure_cookie(response, token):
    # ruleid: py-insecure-cookie
    response.set_cookie("session", token, httponly=False)

    # ok: py-insecure-cookie
    response.set_cookie("session", token, httponly=True, secure=True)


def test_a08_deserialization(payload):
    # ruleid: py-unsafe-deserialization
    pickle.loads(payload)

    # ok: py-unsafe-deserialization
    print("deserialization avoided")


def test_a09_empty_exception():
    try:
        critical_security_operation()
    # ruleid: py-empty-except-pass
    except Exception:
        pass


def test_a10_ssrf(user_url):
    # ruleid: py-ssrf-requests
    requests.get(user_url)

    # ok: py-ssrf-requests
    requests.get("https://api.github.com/zen")
