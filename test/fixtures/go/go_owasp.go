package fixtures

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
)

type dummySSH struct{}

func (d dummySSH) InsecureIgnoreHostKey() interface{} {
	return nil
}

var ssh dummySSH

type DummyToken struct{}

func (d *DummyToken) SignedString(key interface{}) (string, error) {
	return "", nil
}

func TestA01PathTraversal(userPath string) {
	// ruleid: go-path-traversal
	_, _ = os.Open(userPath)

	// ok: go-path-traversal
	_, _ = os.Open("safe_static_file.txt")
}

func TestA02CryptoFailures() {
	// ruleid: go-weak-cryptography
	_ = md5.New()

	// ok: go-weak-cryptography
	_ = sha256.New()
}

func TestA03CommandInjection(userInput string) {
	// ruleid: go-command-injection
	_ = exec.Command("sh", "-c", userInput)

	// ok: go-command-injection
	_ = exec.Command("ls", "-la")
}

func TestA04HardcodedSecret(token *DummyToken) {
	// ruleid: go-hardcoded-secret
	_, _ = token.SignedString([]byte("super_secret_hardcoded_jwt_key"))

	// ok: go-hardcoded-secret
	_, _ = token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
}

func TestA05Misconfiguration() {
	// ruleid: go-insecure-tls
	_ = &tls.Config{InsecureSkipVerify: true}

	// ok: go-insecure-tls
	_ = &tls.Config{InsecureSkipVerify: false}
}

func TestA06VulnerableComponents() {
	// ruleid: go-ssh-insecure-ignore-host-key
	_ = ssh.InsecureIgnoreHostKey()

	// ok: go-ssh-insecure-ignore-host-key
	println("safe host key verification")
}

func TestA07InsecureCookie() {
	// ruleid: go-insecure-cookie
	_ = http.Cookie{HttpOnly: false}

	// ok: go-insecure-cookie
	_ = http.Cookie{HttpOnly: true, Secure: true}
}

func TestA08DataIntegrity(r io.Reader) {
	// ruleid: go-unsafe-gob-decoder
	_ = gob.NewDecoder(r)

	// ok: go-unsafe-gob-decoder
	_ = json.NewDecoder(r)
}

func TestA09IgnoredError(path string) {
	// ruleid: go-unhandled-security-error
	_ = os.RemoveAll(path)

	// ok: go-unhandled-security-error
	if err := os.RemoveAll(path); err != nil {
		println("handled error")
	}
}

func TestA10SSRF(targetURL string) {
	// ruleid: go-ssrf-http-client
	_, _ = http.Get(targetURL)

	// ok: go-ssrf-http-client
	_, _ = http.Get("https://api.github.com/status")
}
