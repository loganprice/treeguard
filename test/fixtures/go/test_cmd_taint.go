package fixtures

import (
	"net/http"
	"os/exec"
	"strconv"
)

func handleVulnerable(r *http.Request) {
	cmdArg := r.FormValue("cmd")
	// ruleid: go-command-injection-taint
	// ruleid: go-command-injection
	cmd := exec.Command("sh", "-c", cmdArg)
	cmd.Run()
}

func handleSanitized(r *http.Request) {
	idStr := r.FormValue("id")
	cleanID, _ := strconv.Atoi(idStr)
	_ = cleanID
	// ok: go-command-injection-taint
	cmd := exec.Command("echo", "safe")
	cmd.Run()
}
