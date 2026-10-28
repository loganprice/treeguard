package validator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/validator"
)

func TestRuleValidatorTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// 1. Valid rule file
	validRuleFile := filepath.Join(tmpDir, "valid.rego")
	validRuleContent := `
package rules.python.eval
metadata := {
	"id": "py-eval",
	"title": "Use of eval",
	"severity": "ERROR",
	"cwe": "CWE-95"
}
deny[finding] {
	input.file.language == "python"
	finding := {"message": "unsafe eval"}
}
`
	if err := os.WriteFile(validRuleFile, []byte(validRuleContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Syntax error rule file
	syntaxErrFile := filepath.Join(tmpDir, "syntax_err.rego")
	syntaxErrContent := `
package rules.broken
metadata := {
	id: "broken"
}
deny[finding] {
`
	if err := os.WriteFile(syntaxErrFile, []byte(syntaxErrContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Missing metadata id rule file
	missingIDFile := filepath.Join(tmpDir, "missing_id.rego")
	missingIDContent := `
package rules.python.missing_id
metadata := {
	"severity": "ERROR"
}
deny[finding] {
	finding := "error"
}
`
	if err := os.WriteFile(missingIDFile, []byte(missingIDContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Missing entrypoint rule file
	missingEntrypointFile := filepath.Join(tmpDir, "no_entrypoint.rego")
	missingEntrypointContent := `
package rules.python.no_entrypoint
metadata := {
	"id": "no-entrypoint",
	"severity": "WARNING"
}
some_other_rule {
	1 == 1
}
`
	if err := os.WriteFile(missingEntrypointFile, []byte(missingEntrypointContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 5. Findings alternative entrypoint
	findingsEntrypointFile := filepath.Join(tmpDir, "findings_rule.rego")
	findingsEntrypointContent := `
package rules.go.findings
metadata := {
	"id": "go-findings-test",
	"title": "Findings test",
	"severity": "INFO"
}
findings[finding] {
	finding := {"message": "info"}
}
`
	if err := os.WriteFile(findingsEntrypointFile, []byte(findingsEntrypointContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 6. Invalid package name (does not start with rules.)
	invalidPkgFile := filepath.Join(tmpDir, "invalid_pkg.rego")
	invalidPkgContent := `
package custom.tools
metadata := {
	"id": "custom-id",
	"title": "Custom Tool",
	"severity": "INFO"
}
deny[finding] {
	finding := "test"
}
`
	if err := os.WriteFile(invalidPkgFile, []byte(invalidPkgContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 7. Invalid severity and missing title in strict mode
	strictWarningFile := filepath.Join(tmpDir, "strict_warning.rego")
	strictWarningContent := `
package rules.ruby.warn
metadata := {
	"id": "ruby-warn",
	"severity": "INVALID_SEVERITY"
}
deny[finding] {
	finding := "warn"
}
`
	if err := os.WriteFile(strictWarningFile, []byte(strictWarningContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 8. Non-object metadata
	nonObjectMetaFile := filepath.Join(tmpDir, "non_object_meta.rego")
	nonObjectMetaContent := `
package rules.c.invalid_meta
metadata := "invalid-string-metadata"
deny[finding] {
	finding := "err"
}
`
	if err := os.WriteFile(nonObjectMetaFile, []byte(nonObjectMetaContent), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		filePath   string
		strict     bool
		wantValid  bool
		wantRuleID string
		wantErrors int
	}{
		{
			name:       "Valid rule file in normal mode",
			filePath:   validRuleFile,
			strict:     false,
			wantValid:  true,
			wantRuleID: "py-eval",
			wantErrors: 0,
		},
		{
			name:       "Valid rule file in strict mode",
			filePath:   validRuleFile,
			strict:     true,
			wantValid:  true,
			wantRuleID: "py-eval",
			wantErrors: 0,
		},
		{
			name:       "Syntax error rule file",
			filePath:   syntaxErrFile,
			strict:     false,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name:       "Missing metadata id rule file",
			filePath:   missingIDFile,
			strict:     false,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name:       "Missing entrypoint rule file",
			filePath:   missingEntrypointFile,
			strict:     false,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name:       "Valid findings entrypoint",
			filePath:   findingsEntrypointFile,
			strict:     false,
			wantValid:  true,
			wantRuleID: "go-findings-test",
			wantErrors: 0,
		},
		{
			name:       "Invalid package prefix warns in normal mode",
			filePath:   invalidPkgFile,
			strict:     false,
			wantValid:  true,
			wantRuleID: "custom-id",
			wantErrors: 0,
		},
		{
			name:       "Invalid package prefix fails in strict mode",
			filePath:   invalidPkgFile,
			strict:     true,
			wantValid:  false,
			wantRuleID: "custom-id",
			wantErrors: 0,
		},
		{
			name:       "Strict mode fails on metadata warning",
			filePath:   strictWarningFile,
			strict:     true,
			wantValid:  false,
			wantRuleID: "ruby-warn",
			wantErrors: 0,
		},
		{
			name:       "Non-object metadata fails validation",
			filePath:   nonObjectMetaFile,
			strict:     false,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name:       "Non-existent rule file returns error issue",
			filePath:   filepath.Join(tmpDir, "does_not_exist.rego"),
			strict:     false,
			wantValid:  false,
			wantErrors: 1,
		},
	}

	val := validator.New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := val.ValidateFile(ctx, tt.filePath, validator.ValidationOptions{Strict: tt.strict})
			if res.Valid != tt.wantValid {
				t.Errorf("ValidateFile() valid = %v, want %v. Issues: %+v", res.Valid, tt.wantValid, res.Issues)
			}
			if tt.wantRuleID != "" && res.RuleID != tt.wantRuleID {
				t.Errorf("ValidateFile() RuleID = %q, want %q", res.RuleID, tt.wantRuleID)
			}

			errCount := 0
			for _, issue := range res.Issues {
				if issue.Severity == "ERROR" {
					errCount++
				}
			}
			if errCount < tt.wantErrors {
				t.Errorf("ValidateFile() error issues count = %d, want at least %d", errCount, tt.wantErrors)
			}
		})
	}
}

func TestValidatePaths(t *testing.T) {
	ctx := context.Background()
	val := validator.New()

	// 1. Valid library rules directory
	rulesDir := "../../rules"
	if _, err := os.Stat(rulesDir); err != nil {
		rulesDir = "rules"
	}

	report, err := val.ValidatePaths(ctx, []string{rulesDir}, validator.ValidationOptions{Strict: false})
	if err != nil {
		t.Fatalf("ValidatePaths() error = %v", err)
	}

	if !report.Passed {
		t.Errorf("ValidatePaths() report.Passed = false, expected standard rule library to pass validation")
	}

	if report.FilesScanned == 0 {
		t.Errorf("ValidatePaths() files scanned = 0, want > 0")
	}

	// 2. Single direct file path
	tmpDir := t.TempDir()
	singleFile := filepath.Join(tmpDir, "single.rego")
	_ = os.WriteFile(singleFile, []byte("package rules.test\nmetadata := {\"id\": \"test\"}\ndeny[f] { f := 1 }"), 0644)

	singleReport, err := val.ValidatePaths(ctx, []string{singleFile}, validator.ValidationOptions{Strict: false})
	if err != nil {
		t.Fatalf("ValidatePaths(singleFile) error = %v", err)
	}
	if singleReport.FilesScanned != 1 {
		t.Errorf("ValidatePaths() FilesScanned = %d, want 1", singleReport.FilesScanned)
	}

	// 3. Non-existent path returns error
	_, err = val.ValidatePaths(ctx, []string{filepath.Join(tmpDir, "missing_dir")}, validator.ValidationOptions{})
	if err == nil {
		t.Errorf("ValidatePaths(missing_dir) expected error, got nil")
	}
}

func TestRenderConsole(t *testing.T) {
	val := validator.New()

	// 1. Passing report
	passingReport := &validator.ValidationReport{
		FilesScanned: 2,
		RulesCount:   2,
		Passed:       true,
		Results: []validator.RuleValidationResult{
			{File: "rule1.rego", RuleID: "r1", Valid: true},
			{File: "rule2.rego", RuleID: "r2", Valid: true},
		},
	}
	var bufPass bytes.Buffer
	err := val.RenderConsole(&bufPass, passingReport)
	if err != nil {
		t.Errorf("RenderConsole() unexpected error on pass report: %v", err)
	}
	if !strings.Contains(bufPass.String(), "Rule validation passed!") {
		t.Errorf("RenderConsole() missing success message: %s", bufPass.String())
	}

	// 2. Report with issues (warning and error)
	failingReport := &validator.ValidationReport{
		FilesScanned: 2,
		Passed:       false,
		ErrorsCount:  1,
		WarnsCount:   1,
		Results: []validator.RuleValidationResult{
			{
				File:   "bad.rego",
				RuleID: "bad",
				Valid:  false,
				Issues: []validator.ValidationIssue{
					{Line: 10, Severity: "ERROR", Message: "Syntax error"},
				},
			},
			{
				File:   "warn.rego",
				RuleID: "warn",
				Valid:  true,
				Issues: []validator.ValidationIssue{
					{Line: 5, Severity: "WARNING", Message: "Missing title"},
				},
			},
		},
	}
	var bufFail bytes.Buffer
	err = val.RenderConsole(&bufFail, failingReport)
	if err == nil {
		t.Errorf("RenderConsole() expected error on failing report, got nil")
	}
	if !strings.Contains(bufFail.String(), "Validation failed!") {
		t.Errorf("RenderConsole() missing failure message: %s", bufFail.String())
	}
}

func TestRenderJSON(t *testing.T) {
	val := validator.New()
	report := &validator.ValidationReport{
		FilesScanned: 1,
		RulesCount:   1,
		Passed:       true,
		Results: []validator.RuleValidationResult{
			{File: "rule.rego", RuleID: "test-id", Valid: true},
		},
	}

	var buf bytes.Buffer
	if err := val.RenderJSON(&buf, report); err != nil {
		t.Fatalf("RenderJSON() error = %v", err)
	}

	var unmarshaled validator.ValidationReport
	if err := json.Unmarshal(buf.Bytes(), &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal RenderJSON output: %v", err)
	}

	if unmarshaled.FilesScanned != 1 || !unmarshaled.Passed {
		t.Errorf("Unmarshaled report mismatch: %+v", unmarshaled)
	}
}
