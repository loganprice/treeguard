package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/runner"
)

func TestScannerRunTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Prepare rule directory and files
	ruleDir := filepath.Join(tmpDir, "rules")
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		t.Fatal(err)
	}

	validRuleFile := filepath.Join(ruleDir, "eval.rego")
	validRuleContent := `
package rules.python.eval
metadata := { "id": "py-eval-detected", "severity": "ERROR" }
deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	finding := call
}
`
	if err := os.WriteFile(validRuleFile, []byte(validRuleContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Prepare target source files
	targetDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(filepath.Join(targetDir, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	ignoredSubdir := filepath.Join(targetDir, "node_modules")
	if err := os.MkdirAll(ignoredSubdir, 0755); err != nil {
		t.Fatal(err)
	}

	pyTarget := filepath.Join(targetDir, "app.py")
	if err := os.WriteFile(pyTarget, []byte("eval('1+1')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nestedPy := filepath.Join(targetDir, "nested", "helper.py")
	if err := os.WriteFile(nestedPy, []byte("print('safe')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ignoredPy := filepath.Join(ignoredSubdir, "ignored.py")
	if err := os.WriteFile(ignoredPy, []byte("eval('ignored')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		opts         runner.ScanOptions
		wantFindings int
		wantFiles    int
		wantErr      bool
	}{
		{
			name: "Successful scan on directory with default threads",
			opts: runner.ScanOptions{
				TargetPaths: []string{targetDir},
				RulePaths:   []string{ruleDir},
			},
			wantFindings: 1,
			wantFiles:    2, // app.py + helper.py (node_modules is ignored)
			wantErr:      false,
		},
		{
			name: "Scan single file with thread count 1",
			opts: runner.ScanOptions{
				TargetPaths: []string{pyTarget},
				RulePaths:   []string{validRuleFile},
				Threads:     1,
			},
			wantFindings: 1,
			wantFiles:    1,
			wantErr:      false,
		},
		{
			name: "Scan with language filter matching python",
			opts: runner.ScanOptions{
				TargetPaths: []string{targetDir},
				RulePaths:   []string{ruleDir},
				Language:    "python",
			},
			wantFindings: 1,
			wantFiles:    2,
			wantErr:      false,
		},
		{
			name: "Scan with language filter mismatching javascript",
			opts: runner.ScanOptions{
				TargetPaths: []string{targetDir},
				RulePaths:   []string{ruleDir},
				Language:    "javascript",
			},
			wantFindings: 0,
			wantFiles:    0,
			wantErr:      false,
		},
		{
			name: "Scan with min severity filter ERROR",
			opts: runner.ScanOptions{
				TargetPaths: []string{targetDir},
				RulePaths:   []string{ruleDir},
				MinSeverity: engine.SeverityError,
			},
			wantFindings: 1,
			wantFiles:    2,
			wantErr:      false,
		},
		{
			name: "Missing rule paths error",
			opts: runner.ScanOptions{
				TargetPaths: []string{targetDir},
				RulePaths:   nil,
			},
			wantErr: true,
		},
		{
			name: "Non-existent rule path error",
			opts: runner.ScanOptions{
				TargetPaths: []string{targetDir},
				RulePaths:   []string{filepath.Join(tmpDir, "missing.rego")},
			},
			wantErr: true,
		},
		{
			name: "Non-existent target path error",
			opts: runner.ScanOptions{
				TargetPaths: []string{filepath.Join(tmpDir, "missing_target")},
				RulePaths:   []string{ruleDir},
			},
			wantErr: true,
		},
		{
			name: "Skip oversized file with small MaxFileSize",
			opts: runner.ScanOptions{
				TargetPaths: []string{pyTarget},
				RulePaths:   []string{ruleDir},
				MaxFileSize: 5, // smaller than pyTarget ("eval('1+1')\n" is 12 bytes)
			},
			wantErr:      false,
			wantFindings: 0,
			wantFiles:    1,
		},
		{
			name: "Scan completes with custom Timeout",
			opts: runner.ScanOptions{
				TargetPaths: []string{pyTarget},
				RulePaths:   []string{ruleDir},
				Timeout:     5 * time.Second,
			},
			wantErr:      false,
			wantFindings: 1,
			wantFiles:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := runner.NewScanner()
			res, err := s.Run(ctx, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(res.Findings) != tt.wantFindings {
				t.Errorf("Findings count = %d, want %d", len(res.Findings), tt.wantFindings)
			}
			if res.Stats.FilesScanned != tt.wantFiles {
				t.Errorf("FilesScanned = %d, want %d", res.Stats.FilesScanned, tt.wantFiles)
			}
		})
	}
}
