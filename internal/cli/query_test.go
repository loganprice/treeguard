package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIQueryCmdTableDriven(t *testing.T) {
	ctx := context.Background()
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
			name:       "Query input file language",
			args:       []string{"-e", "input.file.language", pyFile},
			wantSubstr: "\"python\"",
			wantErr:    false,
		},
		{
			name:    "Query missing -e argument error",
			args:    []string{pyFile},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newQueryCmd(ctx)
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
