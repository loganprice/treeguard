package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/version"
)

func TestVersionCmd(t *testing.T) {
	t.Run("default text output", func(t *testing.T) {
		cmd := newVersionCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)

		if err := cmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "TreeGuard version") {
			t.Errorf("expected 'TreeGuard version' in output, got: %s", output)
		}
	})

	t.Run("json output", func(t *testing.T) {
		cmd := newVersionCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetArgs([]string{"--json"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var info version.Info
		if err := json.Unmarshal(buf.Bytes(), &info); err != nil {
			t.Fatalf("failed to unmarshal JSON output: %v, output was: %s", err, buf.String())
		}

		if info.Version == "" {
			t.Errorf("expected non-empty Version in JSON output")
		}
		if info.GoVersion == "" {
			t.Errorf("expected non-empty GoVersion in JSON output")
		}
		if info.Platform == "" {
			t.Errorf("expected non-empty Platform in JSON output")
		}
	})
}
