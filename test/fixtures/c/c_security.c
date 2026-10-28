// C Security Test Fixtures

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void test_a01_path_traversal(char *user_path) {
    // ruleid: c-path-traversal
    FILE *f = fopen(user_path, "r");

    // ok: c-path-traversal
    FILE *safe = fopen("safe.txt", "r");
}

void test_a02_crypto() {
    // ruleid: c-weak-prng-rand
    int token = rand();
}

void test_a03_injection(char *cmd) {
    // ruleid: c-command-injection
    system(cmd);

    // ok: c-command-injection
    system("ls -la");
}

void test_a04_secret() {
    // ruleid: c-hardcoded-secret
    char *SECRET_PASSWORD = "super_hardcoded_admin_password";
}

void test_a05_misconfig() {
    // ruleid: c-insecure-file-permissions
    umask(0);
}

void test_a06_banned(char *src) {
    char dest[100];
    // ruleid: c-banned-memory-functions
    strcpy(dest, src);

    // ok: c-banned-memory-functions
    strncpy(dest, src, sizeof(dest) - 1);
}

void test_a08_overflow(int count, int size) {
    // ruleid: c-integer-overflow-malloc
    char *buf = (char *)malloc(count * size);
}

void test_a09_format_string(char *user_buf) {
    // ruleid: c-format-string-vulnerability
    printf(user_buf);

    // ok: c-format-string-vulnerability
    printf("%s", user_buf);
}

void test_a10_ssrf(void *curl, char *user_url) {
    // ruleid: c-ssrf-libcurl
    curl_easy_setopt(curl, CURLOPT_URL, user_url);

    // ok: c-ssrf-libcurl
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com");
}
