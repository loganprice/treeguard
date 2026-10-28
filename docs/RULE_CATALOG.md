# TreeGuard Pre-Packaged OWASP Top 10 Rule Catalog

TreeGuard includes OWASP Top 10 (2021) rule coverage across 13 languages (including Dockerfile/Containerfile) with CWE identifiers and automated remediation (`autofix`) capabilities.

---

## 1. Python, JavaScript / TypeScript, and Go Catalog

| OWASP Category | Language | Rule ID | CWE | Autofix Available? | Recommended Fix |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **A01: Broken Access Control** | Python | `py-path-traversal` | CWE-22 | ❌ | Sanitize paths using `os.path.abspath` |
| **A01: Broken Access Control** | JS/TS | `js-path-traversal` | CWE-22 | ❌ | Sanitize paths using `path.resolve` |
| **A01: Broken Access Control** | Go | `go-path-traversal` | CWE-22 | ❌ | Clean paths using `filepath.Clean` |
| **A02: Cryptographic Failures** | Python | `py-weak-cryptography` | CWE-327 | ✅ | `hashlib.sha256` |
| **A02: Cryptographic Failures** | JS/TS | `js-weak-cryptography` | CWE-327 | ✅ | `'sha256'` |
| **A02: Cryptographic Failures** | Go | `go-weak-cryptography` | CWE-327 | ✅ | `sha256.New` / `sha256.Sum` |
| **A03: Injection** | Python | `py-sql-injection` | CWE-89 | ❌ | Parameterized SQL query tuple |
| **A03: Injection** | Python | `py-command-injection` | CWE-78 | ❌ | `subprocess.run` with list args |
| **A03: Injection** | JS/TS | `js-dangerous-eval` | CWE-95 | ❌ | Avoid `eval()` or `Function()` |
| **A03: Injection** | Go | `go-sql-injection` | CWE-89 | ❌ | Parameterized SQL `db.QueryContext` |
| **A04: Insecure Design** | Python | `py-hardcoded-secret` | CWE-798 | ❌ | Read from `os.environ` |
| **A04: Insecure Design** | JS/TS | `js-hardcoded-secret` | CWE-798 | ❌ | Read from `process.env` |
| **A04: Insecure Design** | Python | `py-cognitive-complexity` | CWE-1075 | ❌ | Refactor complex function into modular helpers |
| **A04: Insecure Design** | JS/TS | `js-cognitive-complexity` | CWE-1075 | ❌ | Refactor complex function into modular helpers |
| **A04: Insecure Design** | Go | `go-cognitive-complexity` | CWE-1075 | ❌ | Refactor complex function into modular helpers |
| **A05: Misconfiguration** | Python | `py-debug-mode-enabled` | CWE-489 | ✅ | `False` |
| **A05: Misconfiguration** | JS/TS | `js-cors-wildcard-credentials` | CWE-942 | ❌ | Restrict CORS origin |
| **A06: Vulnerable Components** | Python | `py-xxe-elementtree` | CWE-611 | ❌ | `defusedxml` |
| **A06: Vulnerable Components** | JS/TS | `js-prototype-pollution` | CWE-1321 | ❌ | Object schema validation |
| **A07: Identification Failures**| Python | `py-insecure-cookie` | CWE-1004 | ❌ | `httponly=True, secure=True` |
| **A07: Identification Failures**| JS/TS | `js-insecure-cookie` | CWE-1004 | ❌ | `httpOnly: true, secure: true` |
| **A08: Data Integrity** | Python | `py-unsafe-deserialization` | CWE-502 | ❌ | `json.loads` or `yaml.safe_load` |
| **A09: Logging Failures** | Python | `py-empty-except-pass` | CWE-391 | ❌ | Log exception trace |
| **A09: Logging Failures** | JS/TS | `js-empty-catch-block` | CWE-391 | ❌ | Handle error in catch block |
| **A10: SSRF** | Python | `py-ssrf-requests` | CWE-918 | ❌ | Validate target URL against allowlist |
| **A10: SSRF** | JS/TS | `js-ssrf-http-request` | CWE-918 | ❌ | Validate target URL against allowlist |

---

## 2. C / C++, Java, Ruby, PHP, and Rust Catalog

| OWASP Category | Language | Rule ID | CWE | Autofix Available? | Recommended Fix |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **A02: Cryptographic Failures** | C/C++ | `c-weak-prng-rand` | CWE-338 | ✅ | `arc4random()` |
| **A02: Cryptographic Failures** | Java | `java-weak-cryptographic-hash` | CWE-327 | ✅ | `"SHA-256"` |
| **A02: Cryptographic Failures** | Ruby | `ruby-weak-cryptography` | CWE-327 | ✅ | `Digest::SHA256` |
| **A04: Insecure Design** | C/C++ | `c-cognitive-complexity` | CWE-1075 | ❌ | Refactor complex function into modular helpers |
| **A05: Misconfiguration** | C/C++ | `c-insecure-file-permissions` | CWE-732 | ✅ | `0027` (umask) / `0755` (chmod) |
| **A06: Vulnerable Components** | C/C++ | `c-banned-memory-functions` | CWE-120 | ✅ | `strncpy` / `snprintf` / `fgets` |
| **A09: Logging Failures** | C/C++ | `c-format-string-vulnerability` | CWE-134 | ❌ | `printf("%s", user_buf)` |
| **A10: SSRF** | C/C++ | `c-ssrf-libcurl` | CWE-918 | ❌ | Validate URL before `curl_easy_setopt` |

---

## 3. Dockerfile Catalog

| OWASP Category | Language | Rule ID | CWE | Autofix Available? | Recommended Fix |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **A05: Misconfiguration** | Dockerfile | `docker-root-user` | CWE-250 | ❌ | Use non-root `USER` instruction |
| **A05: Misconfiguration** | Dockerfile | `docker-sudo-usage` | CWE-250 | ❌ | Remove `sudo` execution from `RUN` instructions |
| **A08: Data Integrity** | Dockerfile | `docker-latest-tag` | CWE-1188 | ❌ | Pin explicit base image version tag |
| **A08: Data Integrity** | Dockerfile | `docker-add-usage` | CWE-829 | ❌ | Replace `ADD` instruction with `COPY` |

