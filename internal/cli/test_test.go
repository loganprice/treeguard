package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCLITestCmdTableDriven(t *testing.T) {
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
	os.WriteFile(ruleFile, []byte(ruleContent), 0644)

	fixtureFile := filepath.Join(tmpDir, "test_eval.py")
	fixtureContent := "# ruleid: py-eval\neval('1')\n"
	os.WriteFile(fixtureFile, []byte(fixtureContent), 0644)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "Run rule tests on fixture",
			args:    []string{"-r", ruleFile, fixtureFile},
			wantErr: false,
		},
		{
			name:    "Test without rules flag error",
			args:    []string{fixtureFile},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newTestCmd(ctx)
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
