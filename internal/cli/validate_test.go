package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIValidateCmdTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

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
	os.WriteFile(validRuleFile, []byte(validRuleContent), 0644)

	invalidRuleFile := filepath.Join(tmpDir, "invalid.rego")
	invalidRuleContent := `
package rules.broken
metadata := { severity: "ERROR" }
deny[finding] {
`
	os.WriteFile(invalidRuleFile, []byte(invalidRuleContent), 0644)

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "Validate valid rule file with text output",
			args:       []string{validRuleFile},
			wantSubstr: "Rule validation passed!",
			wantErr:    false,
		},
		{
			name:       "Validate valid rule file with JSON format",
			args:       []string{"-f", "json", validRuleFile},
			wantSubstr: "\"passed\": true",
			wantErr:    false,
		},
		{
			name:       "Validate invalid rule file error",
			args:       []string{invalidRuleFile},
			wantSubstr: "Validation failed",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newValidateCmd(ctx)
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
