package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRootCmd(t *testing.T) {
	ctx := context.Background()
	cmd := NewRootCmd(ctx)
	if cmd == nil {
		t.Fatal("NewRootCmd() returned nil")
	}
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute --help error = %v", err)
	}
	if !strings.Contains(buf.String(), "TreeGuard is a high-performance") {
		t.Errorf("help output missing title: %s", buf.String())
	}

	// Test --version
	buf.Reset()
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute --version error = %v", err)
	}
	if !strings.Contains(buf.String(), "TreeGuard version") {
		t.Errorf("expected 'TreeGuard version' in output: %s", buf.String())
	}
}
