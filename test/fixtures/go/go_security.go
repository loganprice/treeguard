package fixtures

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)

func TestTLS() {
	// ruleid: go-insecure-tls
	_ = &tls.Config{InsecureSkipVerify: true}

	// ok: go-insecure-tls
	_ = &tls.Config{InsecureSkipVerify: false}
}

func TestCommand(userInput string) {
	// ruleid: go-command-injection
	_ = exec.Command("sh", "-c", userInput)

	// ruleid: go-command-injection
	_ = exec.Command("bash", "-c", userInput)

	// ok: go-command-injection
	_ = exec.Command("ls", "-la")
}

func TestSQL(db *sql.DB, id string) {
	// ruleid: go-sql-injection
	_, _ = db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))

	// ok: go-sql-injection
	_, _ = db.Query("SELECT * FROM users WHERE id = $1", id)
}
