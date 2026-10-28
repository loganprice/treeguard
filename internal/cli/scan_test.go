package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIScanCmdTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Prepare rule file
	ruleFile := filepath.Join(tmpDir, "eval.rego")
	ruleContent := `
package rules.python.eval
metadata := { "id": "py-eval", "severity": "ERROR" }
deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	finding := call
}
`
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Prepare source file
	pyFile := filepath.Join(tmpDir, "app.py")
	if err := os.WriteFile(pyFile, []byte("eval('1+1')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(tmpDir, "out.json")

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "Scan with text output format (returns findings error)",
			args:       []string{"-r", ruleFile, "-f", "text", pyFile},
			wantSubstr: "py-eval",
			wantErr:    true, // Unfixed finding returns exit error
		},
		{
			name:       "Scan with JSON output format to file",
			args:       []string{"-r", ruleFile, "-f", "json", "-o", outFile, pyFile},
			wantSubstr: "",
			wantErr:    true, // Unfixed finding returns exit error
		},
		{
			name:       "Scan with SARIF output format",
			args:       []string{"-r", ruleFile, "-f", "sarif", pyFile},
			wantSubstr: "\"version\": \"2.1.0\"",
			wantErr:    true, // Unfixed finding returns exit error
		},
		{
			name:       "Scan with HTML output format",
			args:       []string{"-r", ruleFile, "-f", "html", pyFile},
			wantSubstr: "<!DOCTYPE html>",
			wantErr:    true, // Unfixed finding returns exit error
		},
		{
			name:       "Scan with dry-run autofix",
			args:       []string{"-r", ruleFile, "--dry-run", pyFile},
			wantSubstr: "Autofix Preview",
			wantErr:    true, // Dry-run previews fixes but doesn't modify file, returns exit error for findings
		},
		{
			name:    "Scan without rules specified error",
			args:    []string{pyFile},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd(ctx)
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" {
				if !strings.Contains(buf.String(), tt.wantSubstr) {
					t.Errorf("output missing %q\nGot:\n%s", tt.wantSubstr, buf.String())
				}
			}
		})
	}

	// Verify outFile content from JSON test
	if data, err := os.ReadFile(outFile); err == nil {
		if !strings.Contains(string(data), "py-eval") {
			t.Errorf("Output file missing py-eval: %s", string(data))
		}
	}
}

func TestCLIScanWithConfigFileTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	ruleFile := filepath.Join(tmpDir, "eval.rego")
	ruleContent := `
package rules.python.eval
metadata := { "id": "py-eval", "severity": "ERROR" }
deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	finding := call
}
`
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	pyFile := filepath.Join(tmpDir, "app.py")
	if err := os.WriteFile(pyFile, []byte("eval('1+1')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgFile := filepath.Join(tmpDir, ".treeguard.yaml")
	cfgContent := "rules:\n  - " + ruleFile + "\nformat: json\n"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "Scan with explicit --config flag using json format from config",
			args:       []string{"-c", cfgFile, pyFile},
			wantSubstr: "\"rule_id\": \"py-eval\"",
			wantErr:    true, // Finding detected
		},
		{
			name:       "Scan overriding config format with CLI --format text",
			args:       []string{"-c", cfgFile, "-f", "text", pyFile},
			wantSubstr: "py-eval",
			wantErr:    true,
		},
		{
			name:       "Scan with missing config file error",
			args:       []string{"-c", filepath.Join(tmpDir, "nonexistent.yaml"), pyFile},
			wantSubstr: "load config file",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd(ctx)
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" {
				if !strings.Contains(buf.String(), tt.wantSubstr) {
					t.Errorf("output missing %q\nGot:\n%s", tt.wantSubstr, buf.String())
				}
			}
		})
	}
}

func TestCLIScanGitDiffFlagsTableDriven(t *testing.T) {
	ctx := context.Background()
	repoDir := t.TempDir()

	// Initialize git repo
	cmdInit := exec.Command("git", "init")
	cmdInit.Dir = repoDir
	cmdInit.Run()

	cmdName := exec.Command("git", "config", "user.name", "Test User")
	cmdName.Dir = repoDir
	cmdName.Run()

	cmdEmail := exec.Command("git", "config", "user.email", "test@example.com")
	cmdEmail.Dir = repoDir
	cmdEmail.Run()

	ruleFile := filepath.Join(repoDir, "eval.rego")
	ruleContent := `
package rules.python.eval
metadata := { "id": "py-eval", "severity": "ERROR" }
deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	finding := call
}
`
	os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	exec.Command("git", "-C", repoDir, "add", ".").Run()
	exec.Command("git", "-C", repoDir, "commit", "-m", "init").Run()

	untrackedPy := filepath.Join(repoDir, "untracked.py")
	os.WriteFile(untrackedPy, []byte("eval('1+1')\n"), 0644)

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "Scan with --changed-only flag finding untracked file",
			args:       []string{"-r", ruleFile, "--changed-only", repoDir},
			wantSubstr: "py-eval",
			wantErr:    true, // Unfixed finding error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd(ctx)
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" {
				if !strings.Contains(buf.String(), tt.wantSubstr) {
					t.Errorf("output missing %q\nGot:\n%s", tt.wantSubstr, buf.String())
				}
			}
		})
	}
}

func TestCLIScanFailOnTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Prepare warning-level rule file
	ruleFile := filepath.Join(tmpDir, "warn.rego")
	ruleContent := `
package rules.python.warn
metadata := { "id": "py-warn", "severity": "WARNING" }
deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "print"
	finding := call
}
`
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Prepare source file
	pyFile := filepath.Join(tmpDir, "app.py")
	if err := os.WriteFile(pyFile, []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "Fail on medium triggers failure on WARNING finding",
			args:       []string{"-r", ruleFile, "--fail-on", "medium", pyFile},
			wantSubstr: "py-warn",
			wantErr:    true,
		},
		{
			name:       "Fail on high does NOT trigger failure on WARNING finding",
			args:       []string{"-r", ruleFile, "--fail-on", "high", pyFile},
			wantSubstr: "py-warn",
			wantErr:    false,
		},
		{
			name:       "Fail on critical does NOT trigger failure on WARNING finding",
			args:       []string{"-r", ruleFile, "--fail-on", "critical", pyFile},
			wantSubstr: "py-warn",
			wantErr:    false,
		},
		{
			name:       "Fail on none does NOT trigger failure on any finding",
			args:       []string{"-r", ruleFile, "--fail-on", "none", pyFile},
			wantSubstr: "py-warn",
			wantErr:    false,
		},
		{
			name:       "Fail on any triggers failure on any finding",
			args:       []string{"-r", ruleFile, "--fail-on", "any", pyFile},
			wantSubstr: "py-warn",
			wantErr:    true,
		},
		{
			name:       "Invalid fail-on value returns validation error",
			args:       []string{"-r", ruleFile, "--fail-on", "invalid_value", pyFile},
			wantSubstr: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd(ctx)
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" {
				if !strings.Contains(buf.String(), tt.wantSubstr) {
					t.Errorf("output missing %q\nGot:\n%s", tt.wantSubstr, buf.String())
				}
			}
		})
	}
}
