// Java Security Test Fixtures

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import java.net.URL;

public class JavaSecurityTest {
    public void testA01PathTraversal(String userPath) throws Exception {
        // ruleid: java-path-traversal
        new FileInputStream(userPath);

        // ok: java-path-traversal
        new FileInputStream("safe_path.txt");
    }

    public void testA02Crypto() throws Exception {
        // ruleid: java-weak-cryptographic-hash
        java.security.MessageDigest.getInstance("MD5");

        // ok: java-weak-cryptographic-hash
        java.security.MessageDigest.getInstance("SHA-256");
    }

    public void testA03Injection(java.sql.Statement stmt, String userId, String cmd) throws Exception {
        // ruleid: java-sql-injection
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

        // ok: java-sql-injection
        stmt.executeQuery("SELECT * FROM users WHERE id = 'static_id'");

        // ruleid: java-command-injection
        Runtime.getRuntime().exec(cmd);

        // ok: java-command-injection
        Runtime.getRuntime().exec("ls -l");
    }

    public void testA04HardcodedSecret() {
        // ruleid: java-hardcoded-secret
        new SecretKeySpec("hardcoded_secret_key_123".getBytes(), "AES");
    }

    public void testA06XXE() throws Exception {
        // ruleid: java-xxe-xml-factory
        DocumentBuilderFactory.newInstance();
    }

    public void testA07InsecureCookie(javax.servlet.http.Cookie cookie) {
        // ruleid: java-insecure-cookie-flags
        cookie.setHttpOnly(false);

        // ok: java-insecure-cookie-flags
        cookie.setHttpOnly(true);
    }

    public void testA08Deserialization(ObjectInputStream in) throws Exception {
        // ruleid: java-unsafe-deserialization
        in.readObject();
    }

    public void testA09EmptyCatch() {
        try {
            doSomething();
        // ruleid: java-empty-catch-block
        } catch (Exception e) {}
    }

    public void testA10SSRF(String userUrl) throws Exception {
        // ruleid: java-ssrf-http-connection
        new URL(userUrl);

        // ok: java-ssrf-http-connection
        new URL("https://api.github.com/status");
    }

    private void doSomething() {}
}
