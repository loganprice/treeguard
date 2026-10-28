package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIDumpASTCmdTableDriven(t *testing.T) {
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "sample.py")
	os.WriteFile(pyFile, []byte("x = 10\n"), 0644)

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "Dump full AST JSON",
			args:       []string{pyFile},
			wantSubstr: "\"file\"",
			wantErr:    false,
		},
		{
			name:       "Dump nodes only",
			args:       []string{"--nodes-only", pyFile},
			wantSubstr: "\"type\": \"module\"",
			wantErr:    false,
		},
		{
			name:    "Dump AST with invalid file error",
			args:    []string{filepath.Join(tmpDir, "missing.py")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDumpASTCmd()
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
