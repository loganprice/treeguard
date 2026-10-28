package query_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/loganprice/treeguard/internal/parser"
	"github.com/loganprice/treeguard/internal/query"
)

func TestService_DumpAST(t *testing.T) {
	svc := query.NewService()
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "test.py")
	if err := os.WriteFile(pyFile, []byte("x = 10\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("Full AST Dump", func(t *testing.T) {
		res, err := svc.DumpAST(pyFile, "", false)
		if err != nil {
			t.Fatalf("DumpAST() unexpected error = %v", err)
		}
		scanInput, ok := res.(parser.ScanInput)
		if !ok {
			t.Fatalf("expected parser.ScanInput, got %T", res)
		}
		if scanInput.File.Language != "python" {
			t.Errorf("got language %s, want python", scanInput.File.Language)
		}
		if len(scanInput.Nodes) == 0 {
			t.Errorf("expected nodes in AST, got 0")
		}
	})

	t.Run("Nodes Only Dump", func(t *testing.T) {
		res, err := svc.DumpAST(pyFile, "", true)
		if err != nil {
			t.Fatalf("DumpAST() unexpected error = %v", err)
		}
		nodes, ok := res.([]parser.ASTNode)
		if !ok {
			t.Fatalf("expected []parser.ASTNode, got %T", res)
		}
		if len(nodes) == 0 {
			t.Errorf("expected nodes, got 0")
		}
	})

	t.Run("Missing File Error", func(t *testing.T) {
		_, err := svc.DumpAST(filepath.Join(tmpDir, "nonexistent.py"), "", false)
		if err == nil {
			t.Fatal("expected error for nonexistent file, got nil")
		}
	})
}

func TestService_Eval(t *testing.T) {
	ctx := context.Background()
	svc := query.NewService()
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "test.py")
	if err := os.WriteFile(pyFile, []byte("x = 10\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("Valid Expression", func(t *testing.T) {
		bindings, err := svc.Eval(ctx, pyFile, "", "input.file.language")
		if err != nil {
			t.Fatalf("Eval() error = %v", err)
		}
		if len(bindings) == 0 {
			t.Fatal("expected at least 1 binding result")
		}
		val, ok := bindings[0]["result"]
		if !ok {
			t.Fatalf("expected result binding, got %v", bindings[0])
		}
		if val != "python" {
			t.Errorf("got result %v, want python", val)
		}
	})

	t.Run("Empty Expression Error", func(t *testing.T) {
		_, err := svc.Eval(ctx, pyFile, "", "")
		if err == nil {
			t.Fatal("expected error for empty expression, got nil")
		}
	})

	t.Run("Invalid Rego Query Error", func(t *testing.T) {
		_, err := svc.Eval(ctx, pyFile, "", "??? invalid syntax")
		if err == nil {
			t.Fatal("expected error for invalid syntax, got nil")
		}
	})
}
